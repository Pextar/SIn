// Live end-to-end test for the rf-socket example, focused on role-based
// authorization on top of SIn sessions.
//
//   node test/live.mjs setup <allowlistPath>   # write an allowlist with an
//                                              #   admin and a user; print both nsecs
//   SIN_TEST_ADMIN=<nsec> SIN_TEST_USER=<nsec> \
//     node test/live.mjs run <baseUrl>
//
// Each identity signs in once (POST /auth/login) to get a session cookie, then
// drives the controller with that cookie. We assert that both roles can toggle,
// but only the admin may add/remove sockets.

import { writeFileSync } from "node:fs";

import { newSecretKey, publicKeyHex, nsec, secretKeyFromNsec } from "../../../web/src/identity.js";
import { nip98Token } from "../../../web/src/signer.js";

const [mode, arg] = process.argv.slice(2);

if (mode === "setup") {
  const admin = newSecretKey();
  const user = newSecretKey();
  writeFileSync(
    arg,
    JSON.stringify({
      keys: {
        [publicKeyHex(admin)]: { label: "admin-laptop", role: "admin" },
        [publicKeyHex(user)]: { label: "guest-phone", role: "user" },
      },
    }),
  );
  // Two lines: admin nsec, then user nsec.
  process.stdout.write(`${nsec(admin)}\n${nsec(user)}\n`);
  process.exit(0);
}

if (mode === "run") {
  const base = arg.replace(/\/$/, "");
  let failures = 0;
  const check = (name, ok, extra = "") => {
    console.log(`${ok ? "ok  " : "FAIL"} ${name}${extra ? ` — ${extra}` : ""}`);
    if (!ok) failures++;
  };

  // Sign in once for an identity and return its session cookie.
  async function signIn(sk) {
    const { challenge } = await (await fetch(`${base}/auth/challenge`)).json();
    const url = `${base}/auth/login`;
    const token = nip98Token(sk, { url, method: "POST", challenge });
    const res = await fetch(url, { method: "POST", headers: { Authorization: token } });
    if (!res.ok) throw new Error(`login failed: HTTP ${res.status}`);
    return (res.headers.get("set-cookie") || "").split(";")[0]; // sin_session=...
  }
  const call = (cookie, path, { method = "GET", body } = {}) =>
    fetch(`${base}${path}`, {
      method,
      headers: { Cookie: cookie, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });

  const adminCookie = await signIn(secretKeyFromNsec(process.env.SIN_TEST_ADMIN));
  const userCookie = await signIn(secretKeyFromNsec(process.env.SIN_TEST_USER));

  // Both roles can read their identity and see their role.
  {
    const a = await (await call(adminCookie, "/auth/me")).json();
    const u = await (await call(userCookie, "/auth/me")).json();
    check("admin session reports role=admin", a.role === "admin", JSON.stringify(a));
    check("user session reports role=user", u.role === "user", JSON.stringify(u));
  }

  // Both roles can list and toggle sockets.
  {
    const res = await call(userCookie, "/api/sockets");
    const body = await res.json();
    check("user can list sockets", res.status === 200 && Array.isArray(body.sockets));

    const on = await call(userCookie, "/api/sockets/1/on", { method: "POST" });
    const onBody = await on.json();
    check("user can turn a socket on", on.status === 200 && onBody.on === true, `status ${on.status}`);

    const tog = await call(adminCookie, "/api/sockets/1/toggle", { method: "POST" });
    const togBody = await tog.json();
    check("admin can toggle a socket", tog.status === 200 && togBody.on === false);
  }

  // Only the admin may add a socket.
  {
    const denied = await call(userCookie, "/api/sockets", {
      method: "POST",
      body: { id: "9", name: "sneaky" },
    });
    check("user is forbidden from adding a socket", denied.status === 403, `status ${denied.status}`);

    const ok = await call(adminCookie, "/api/sockets", {
      method: "POST",
      body: { id: "9", name: "patio lights" },
    });
    check("admin can add a socket", ok.status === 200, `status ${ok.status}`);

    // The new socket is visible and actuatable by the user.
    const act = await call(userCookie, "/api/sockets/9/on", { method: "POST" });
    check("user can actuate the newly-added socket", act.status === 200);
  }

  // Only the admin may remove a socket.
  {
    const denied = await call(userCookie, "/api/sockets/9", { method: "DELETE" });
    check("user is forbidden from removing a socket", denied.status === 403, `status ${denied.status}`);

    const ok = await call(adminCookie, "/api/sockets/9", { method: "DELETE" });
    check("admin can remove a socket", ok.status === 200, `status ${ok.status}`);
  }

  // No session => 401; bad action => 400; missing socket => 404.
  {
    const noauth = await fetch(`${base}/api/sockets`);
    check("unauthenticated request is rejected", noauth.status === 401, `status ${noauth.status}`);

    const bad = await call(adminCookie, "/api/sockets/1/explode", { method: "POST" });
    check("invalid action is a 400", bad.status === 400, `status ${bad.status}`);

    const missing = await call(adminCookie, "/api/sockets/404/on", { method: "POST" });
    check("unknown socket is a 404", missing.status === 404, `status ${missing.status}`);
  }

  console.log(failures === 0 ? "\nall rf-socket checks passed" : `\n${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
}

console.error("usage: live.mjs setup <allowlistPath> | run <baseUrl>");
process.exit(2);
