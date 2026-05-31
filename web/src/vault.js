// The vault: store the signer's secret key encrypted at rest, unlocked only by
// a passkey via the WebAuthn PRF extension. No password, ever.
//
// How it works:
//   enroll  -> create a passkey (PRF enabled), derive a 32-byte secret from the
//              authenticator (PRF), HKDF -> AES-256-GCM key, encrypt the nostr
//              secret key, store {credentialId, salt, iv, ciphertext} in IndexedDB.
//   unlock  -> WebAuthn assertion with the same PRF salt -> same AES key ->
//              decrypt -> raw secret-key bytes (held only in memory, briefly).
//
// The authenticator's PRF output never leaves the device, and the AES key is
// non-extractable. Touch/biometric is the only thing that unlocks the key.

import { idbGet, idbSet, idbDel } from "./idb.js";

const RECORD_KEY = "identity";
// Fixed per-app PRF salt. Changing it would orphan existing vaults.
const PRF_SALT = new TextEncoder().encode("sin-signer-prf-v1");
const HKDF_INFO = new TextEncoder().encode("sin-vault-aes-gcm");

/** True if the platform looks capable of passkeys at all. */
export function webauthnSupported() {
  return typeof PublicKeyCredential !== "undefined" && !!navigator.credentials;
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

async function aesKeyFromPrf(prfOutput) {
  const base = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: HKDF_INFO },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function prfResult(credential) {
  const ext = credential.getClientExtensionResults?.();
  const first = ext?.prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}

/** Is an identity already enrolled on this device? */
export async function hasIdentity() {
  return (await idbGet(RECORD_KEY)) != null;
}

/** Remove the stored identity (does not delete the passkey itself). */
export async function forgetIdentity() {
  await idbDel(RECORD_KEY);
}

/**
 * Create a passkey and store `secretKey` encrypted under it.
 *
 * @param {Uint8Array} secretKey  the nostr secret key to protect
 * @param {string} userName       label shown by the authenticator (e.g. an npub)
 */
export async function enroll(secretKey, userName) {
  if (!webauthnSupported()) throw new Error("passkeys are not supported on this device");

  const userId = randomBytes(16);
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { name: "SIn Signer", id: location.hostname },
      user: { id: userId, name: userName, displayName: userName },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });

  const credentialId = new Uint8Array(credential.rawId);

  // Some platforms return PRF at creation; others only on assertion. Prefer the
  // creation result, otherwise immediately do an assertion to obtain it.
  let prf = prfResult(credential);
  if (!prf) prf = await evaluatePrf(credentialId);
  if (!prf) {
    throw new Error("this authenticator does not support the WebAuthn PRF extension");
  }

  const aesKey = await aesKeyFromPrf(prf);
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, secretKey),
  );

  await idbSet(RECORD_KEY, {
    credentialId: Array.from(credentialId),
    iv: Array.from(iv),
    ciphertext: Array.from(ciphertext),
    userName,
  });
}

async function evaluatePrf(credentialId) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  return prfResult(assertion);
}

/**
 * Unlock the stored identity. Prompts for the passkey, then returns the raw
 * secret-key bytes. Caller should use them and let them fall out of scope.
 *
 * @returns {Promise<Uint8Array>}
 */
export async function unlock() {
  const record = await idbGet(RECORD_KEY);
  if (!record) throw new Error("no identity enrolled on this device");

  const credentialId = new Uint8Array(record.credentialId);
  const prf = await evaluatePrf(credentialId);
  if (!prf) throw new Error("could not derive key from passkey (PRF unavailable)");

  const aesKey = await aesKeyFromPrf(prf);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(record.iv) },
    aesKey,
    new Uint8Array(record.ciphertext),
  );
  return new Uint8Array(plaintext);
}
