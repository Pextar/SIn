// Cross-language interop check: sign a NIP-98 token with the PWA's own signer
// code, then verify it with the Rust `sin-core` verifier via the `sin` CLI.
//
// This guarantees the browser signer and the server speak exactly the same
// protocol (event serialization, Schnorr sigs, base64, challenge binding).
//
//   node test/interop.mjs

import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { newSecretKey, publicKeyHex, npub } from "../src/identity.js";
import { nip98Token } from "../src/signer.js";

const SIN = join(import.meta.dirname, "..", "..", "target", "debug", "sin");
const SECRET = "57c369eb4d725db438821d8a4da2c6af8317b8a1f8d20e70f643f6ba57bcbed5";
const URL = "https://sockets.local/api/socket/3/on";
const METHOD = "POST";

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

function sinChallenge() {
  return execFileSync(SIN, ["challenge", "--secret", SECRET], {
    encoding: "utf8",
  }).trim();
}

function sinVerify(token, { url = URL, method = METHOD, file }) {
  return execFileSync(
    SIN,
    ["verify", "--secret", SECRET, "--url", url, "--method", method, "--file", file],
    { encoding: "utf8", input: token },
  ).trim();
}

// Workspace: an allowlist containing our generated identity.
const dir = mkdtempSync(join(tmpdir(), "sin-interop-"));
const allowlist = join(dir, "allowlist.json");
const sk = newSecretKey();
const pkHex = publicKeyHex(sk);
writeFileSync(
  allowlist,
  JSON.stringify({ keys: { [pkHex]: { label: "interop", role: "user" } } }),
);

// 1. Happy path: PWA-signed token is accepted by the Rust verifier.
{
  const challenge = sinChallenge();
  const token = nip98Token(sk, { url: URL, method: METHOD, challenge });
  const out = sinVerify(token, { file: allowlist });
  check("PWA token verifies in sin-core", out.startsWith("OK"));
  check("verifier reports our npub", out.includes(npub(sk)));
}

// 2. URL mismatch is rejected (request binding works).
{
  const challenge = sinChallenge();
  const token = nip98Token(sk, { url: URL, method: METHOD, challenge });
  let rejected = false;
  try {
    sinVerify(token, { url: "https://evil.local/api", file: allowlist });
  } catch {
    rejected = true;
  }
  check("token bound to a different URL is rejected", rejected);
}

// 3. Replaying a challenge across two requests... is fine across CLI processes
//    (the replay cache is per-process), so instead assert a forged challenge
//    fails — the cryptographic check that does survive a fresh process.
{
  const token = nip98Token(sk, {
    url: URL,
    method: METHOD,
    challenge: "this-is-not-a-real-challenge",
  });
  let rejected = false;
  try {
    sinVerify(token, { file: allowlist });
  } catch {
    rejected = true;
  }
  check("forged challenge is rejected", rejected);
}

// 4. A key that is not on the allowlist is rejected.
{
  const stranger = newSecretKey();
  const challenge = sinChallenge();
  const token = nip98Token(stranger, { url: URL, method: METHOD, challenge });
  let rejected = false;
  try {
    sinVerify(token, { file: allowlist });
  } catch {
    rejected = true;
  }
  check("unknown key is rejected", rejected);
}

console.log(failures === 0 ? "\nall interop checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
