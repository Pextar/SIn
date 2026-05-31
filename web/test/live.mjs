// Live end-to-end test against a running sin-demo server.
//
//   node test/live.mjs setup <allowlistPath>   # generate a key, write allowlist, print nsec
//   SIN_TEST_NSEC=<nsec> node test/live.mjs run <baseUrl>
//
// "run" performs the real browser flow over HTTP: GET /auth/challenge, sign a
// NIP-98 token bound to the target request, then call protected endpoints.

import { writeFileSync } from "node:fs";

import { newSecretKey, publicKeyHex, npub, nsec, secretKeyFromNsec } from "../src/identity.js";
import { nip98Token } from "../src/signer.js";

const [mode, arg] = process.argv.slice(2);

if (mode === "setup") {
  const sk = newSecretKey();
  writeFileSync(arg, JSON.stringify({ keys: { [publicKeyHex(sk)]: { label: "live", role: "admin" } } }));
  process.stdout.write(nsec(sk));
  process.exit(0);
}

if (mode === "run") {
  const base = arg.replace(/\/$/, "");
  const sk = secretKeyFromNsec(process.env.SIN_TEST_NSEC);
  let failures = 0;
  const check = (name, ok, extra = "") => {
    console.log(`${ok ? "ok  " : "FAIL"} ${name}${extra ? ` — ${extra}` : ""}`);
    if (!ok) failures++;
  };

  async function authed(path, method = "GET") {
    const { challenge } = await (await fetch(`${base}/auth/challenge`)).json();
    const url = base + path;
    const token = nip98Token(sk, { url, method, challenge });
    return fetch(url, { method, headers: { Authorization: token } });
  }

  // 1. Authenticated whoami returns our identity.
  {
    const res = await authed("/auth/whoami");
    const body = await res.json();
    check("GET /auth/whoami authenticates", res.status === 200 && body.npub === npub(sk), `status ${res.status}`);
    check("role comes back from the allowlist", body.role === "admin");
  }

  // 2. Protected socket endpoint works.
  {
    const res = await authed("/api/socket/3/on", "POST");
    const body = await res.json();
    check("POST /api/socket/3/on succeeds", res.status === 200 && body.ok === true && body.action === "on");
  }

  // 3. No Authorization header => 401.
  {
    const res = await fetch(`${base}/auth/whoami`);
    check("missing token is rejected", res.status === 401, `status ${res.status}`);
  }

  // 4. A token bound to a different path is rejected (request binding).
  {
    const { challenge } = await (await fetch(`${base}/auth/challenge`)).json();
    const token = nip98Token(sk, { url: `${base}/auth/whoami`, method: "GET", challenge });
    const res = await fetch(`${base}/api/socket/3/on`, { method: "POST", headers: { Authorization: token } });
    check("token bound to another path is rejected", res.status === 401, `status ${res.status}`);
  }

  // 5. The PWA itself is served at the root.
  {
    const res = await fetch(`${base}/`);
    const html = await res.text();
    check("PWA index is served", res.status === 200 && html.includes("SIn Signer"));
  }

  console.log(failures === 0 ? "\nall live checks passed" : `\n${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
}

console.error("usage: live.mjs setup <allowlistPath> | run <baseUrl>");
process.exit(2);
