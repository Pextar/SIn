// Identity primitives: a secp256k1 (BIP-340 / nostr) keypair with npub/nsec
// encoding. Pure crypto, no DOM — so this module also runs under Node for tests.

import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import * as nip19 from "nostr-tools/nip19";

/** Generate a fresh secret key (32 raw bytes). */
export function newSecretKey() {
  return generateSecretKey();
}

/** Lowercase 64-char hex public key for a secret key. */
export function publicKeyHex(secretKey) {
  return getPublicKey(secretKey);
}

/** `npub1...` encoding of a secret key's public half. */
export function npub(secretKey) {
  return nip19.npubEncode(getPublicKey(secretKey));
}

/** `nsec1...` encoding of a secret key. Treat as password-equivalent. */
export function nsec(secretKey) {
  return nip19.nsecEncode(secretKey);
}

/** Parse an `nsec1...` string back into raw secret-key bytes. */
export function secretKeyFromNsec(nsecStr) {
  const { type, data } = nip19.decode(nsecStr.trim());
  if (type !== "nsec") throw new Error(`expected an nsec, got ${type}`);
  return data;
}
