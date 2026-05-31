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

  // Sign a NIP-98 token bound to `path`+`method` against a fresh challenge.
  async function sign(path, method = "GET") {
    const { challenge } = await (await fetch(`${base}/auth/challenge`)).json();
    return nip98Token(sk, { url: base + path, method, challenge });
  }
  // One-shot NIP-98 call (the CLI style).
  async function authed(path, method = "GET") {
    const token = await sign(path, method);
    return fetch(base + path, { method, headers: { Authorization: token } });
  }

  // 1. Per-request NIP-98 whoami returns our identity.
  {
    const res = await authed("/auth/whoami");
    const body = await res.json();
    check("GET /auth/whoami authenticates (NIP-98)", res.status === 200 && body.npub === npub(sk), `status ${res.status}`);
    check("role comes back from the allowlist", body.role === "admin");
  }

  // 2. Sign in once at /auth/login, get a session token + cookie.
  let sessionToken, sessionCookie;
  {
    const token = await sign("/auth/login", "POST");
    const res = await fetch(`${base}/auth/login`, { method: "POST", headers: { Authorization: token } });
    const body = await res.json();
    sessionToken = body.token;
    const setCookie = res.headers.get("set-cookie") || "";
    sessionCookie = setCookie.split(";")[0]; // sin_session=<token>
    check("POST /auth/login mints a session", res.status === 200 && !!sessionToken && body.npub === npub(sk), `status ${res.status}`);
    check("login sets an HttpOnly session cookie", /sin_session=/.test(setCookie) && /HttpOnly/i.test(setCookie));
  }

  // 3. The session cookie alone authorizes the socket endpoint (sign once, act many).
  {
    const hit = (id, action) =>
      fetch(`${base}/api/socket/${id}/${action}`, { method: "POST", headers: { Cookie: sessionCookie } });
    const r1 = await hit(3, "on");
    const b1 = await r1.json();
    const r2 = await hit(3, "off");
    check("POST /api/socket/3/on via session cookie", r1.status === 200 && b1.ok === true && b1.action === "on", `status ${r1.status}`);
    check("same cookie reused for a second call", r2.status === 200);
    check("session carries our identity", b1.by === npub(sk));
  }

  // 3b. The session also authorizes /auth/me (identity via cookie, no signing).
  {
    const res = await fetch(`${base}/auth/me`, { headers: { Cookie: sessionCookie } });
    const body = await res.json();
    check("GET /auth/me via session cookie", res.status === 200 && body.npub === npub(sk), `status ${res.status}`);
  }

  // 4. The session token also works as a Bearer header (programmatic clients).
  {
    const res = await fetch(`${base}/api/socket/4/on`, {
      method: "POST",
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    check("session works as a Bearer token", res.status === 200, `status ${res.status}`);
  }

  // 5. No credentials => 401 on both styles.
  {
    const r1 = await fetch(`${base}/auth/whoami`);
    const r2 = await fetch(`${base}/api/socket/3/on`, { method: "POST" });
    check("missing NIP-98 token is rejected", r1.status === 401, `status ${r1.status}`);
    check("missing session is rejected", r2.status === 401, `status ${r2.status}`);
  }

  // 6. A NIP-98 token bound to another path is rejected (request binding).
  {
    const token = await sign("/auth/login", "POST"); // bound to login, not whoami
    const res = await fetch(`${base}/auth/whoami`, { headers: { Authorization: token } });
    check("NIP-98 token bound to another path is rejected", res.status === 401, `status ${res.status}`);
  }

  // 7. A tampered session token is rejected.
  {
    const tampered = sessionToken.slice(0, -3) + "AAA";
    const res = await fetch(`${base}/api/socket/3/on`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tampered}` },
    });
    check("tampered session token is rejected", res.status === 401, `status ${res.status}`);
  }

  // 8. The PWA itself is served at the root.
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
