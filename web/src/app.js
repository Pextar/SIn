// UI controller for the SIn signer PWA. Wires the DOM to identity creation,
// the passkey vault, and an authenticated demo request.

import { newSecretKey, publicKeyHex, npub } from "./identity.js";
import { enroll, unlock, hasIdentity, forgetIdentity, webauthnSupported } from "./vault.js";
import { nip98Token } from "./signer.js";
import { SinClient } from "./client.js";

const $ = (id) => document.getElementById(id);
const SERVER_KEY = "sin.serverUrl";

function setStatus(msg, kind = "info") {
  const el = $("status");
  el.textContent = msg;
  el.className = `status ${kind}`;
}

async function refresh() {
  const enrolled = await hasIdentity();
  $("enroll-view").hidden = enrolled;
  $("signer-view").hidden = !enrolled;
  if (enrolled) {
    const stored = await import("./idb.js").then((m) => m.idbGet("identity"));
    $("identity-label").textContent = stored?.userName ?? "(enrolled)";
  }
}

async function doEnroll() {
  if (!webauthnSupported()) {
    setStatus("This device/browser does not support passkeys.", "error");
    return;
  }
  try {
    setStatus("Creating your identity and passkey…");
    const sk = newSecretKey();
    const id = npub(sk);
    await enroll(sk, id);
    setStatus(`Identity created. Register this npub on the server:\n${id}`, "ok");
    await refresh();
  } catch (e) {
    setStatus(`Enrollment failed: ${e.message}`, "error");
  }
}

/** Run `fn` with a freshly-unlocked secret key, then drop it. */
async function withKey(fn) {
  setStatus("Unlock with your passkey…");
  const sk = await unlock();
  try {
    return await fn(sk);
  } finally {
    sk.fill(0);
  }
}

async function showNpub() {
  try {
    await withKey((sk) => setStatus(`Your identity:\n${npub(sk)}\n${publicKeyHex(sk)}`, "ok"));
  } catch (e) {
    setStatus(`Could not unlock: ${e.message}`, "error");
  }
}

async function copyToken() {
  const url = $("req-url").value.trim();
  const method = $("req-method").value;
  const challenge = $("req-challenge").value.trim();
  if (!url || !challenge) {
    setStatus("Enter both a request URL and a challenge to sign.", "error");
    return;
  }
  try {
    await withKey(async (sk) => {
      const token = nip98Token(sk, { url, method, challenge });
      await navigator.clipboard?.writeText(token).catch(() => {});
      $("token-out").value = token;
      setStatus("Signed. Token copied to clipboard.", "ok");
    });
  } catch (e) {
    setStatus(`Signing failed: ${e.message}`, "error");
  }
}

async function testSignIn() {
  const server = $("server-url").value.trim();
  if (!server) {
    setStatus("Set a server URL first.", "error");
    return;
  }
  localStorage.setItem(SERVER_KEY, server);
  try {
    await withKey(async (sk) => {
      const client = new SinClient(server);
      const res = await client.authedFetch(sk, $("test-path").value.trim() || "/auth/whoami");
      const text = await res.text();
      setStatus(`HTTP ${res.status}\n${text}`, res.ok ? "ok" : "error");
    });
  } catch (e) {
    setStatus(`Sign-in failed: ${e.message}`, "error");
  }
}

async function forget() {
  if (!confirm("Forget this identity on this device? You'll need to re-enroll.")) return;
  await forgetIdentity();
  setStatus("Identity removed from this device.", "info");
  await refresh();
}

function wire() {
  $("server-url").value = localStorage.getItem(SERVER_KEY) ?? "";
  $("btn-enroll").addEventListener("click", doEnroll);
  $("btn-show-npub").addEventListener("click", showNpub);
  $("btn-sign").addEventListener("click", copyToken);
  $("btn-test").addEventListener("click", testSignIn);
  $("btn-forget").addEventListener("click", forget);
  refresh();
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("./sw.js").catch(() => {});
}

document.addEventListener("DOMContentLoaded", wire);
