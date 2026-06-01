// Live end-to-end test for the home-hub example, focused on role-based
// authorization on top of SIn sessions, across several device kinds + scenes.
//
//   node test/live.mjs setup <allowlistPath>   # write an allowlist with an
//                                              #   admin and a user; print both nsecs
//   SIN_TEST_ADMIN=<nsec> SIN_TEST_USER=<nsec> \
//     node test/live.mjs run <baseUrl>
//
// Each identity signs in once (POST /auth/login) to get a session cookie, then
// drives the hub with that cookie. We assert that both roles can read, actuate
// devices, and apply scenes, but only the admin may add/remove devices + scenes.

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
  const cmd = (cookie, id, command) =>
    call(cookie, `/api/devices/${id}`, { method: "POST", body: command });

  const adminCookie = await signIn(secretKeyFromNsec(process.env.SIN_TEST_ADMIN));
  const userCookie = await signIn(secretKeyFromNsec(process.env.SIN_TEST_USER));

  // Both roles can read their identity and see their role.
  {
    const a = await (await call(adminCookie, "/auth/me")).json();
    const u = await (await call(userCookie, "/auth/me")).json();
    check("admin session reports role=admin", a.role === "admin", JSON.stringify(a));
    check("user session reports role=user", u.role === "user", JSON.stringify(u));
  }

  // Any user can list devices and see all three kinds, including a read-only sensor.
  {
    const res = await call(userCookie, "/api/devices");
    const body = await res.json();
    const kinds = new Set((body.devices || []).map((d) => d.kind));
    check("user can list devices", res.status === 200 && Array.isArray(body.devices));
    check("hub reports switch, dimmer, and sensor kinds",
      kinds.has("switch") && kinds.has("dimmer") && kinds.has("sensor"),
      [...kinds].join(","));
  }

  // A switch turns on/off; a user may actuate it.
  {
    const on = await cmd(userCookie, "lamp", { type: "on" });
    const onBody = await on.json();
    check("user can switch the lamp on", on.status === 200 && onBody.on === true, `status ${on.status}`);

    const tog = await cmd(adminCookie, "lamp", { type: "toggle" });
    const togBody = await tog.json();
    check("admin can toggle the lamp off", tog.status === 200 && togBody.on === false);
  }

  // A dimmer takes a level; setting it implies "on".
  {
    const dim = await cmd(userCookie, "ceiling", { type: "level", value: 40 });
    const dimBody = await dim.json();
    check("user can set the ceiling light to 40%",
      dim.status === 200 && dimBody.level === 40 && dimBody.on === true, `status ${dim.status}`);

    const bad = await cmd(userCookie, "ceiling", { type: "level", value: 200 });
    check("an out-of-range level is a 400", bad.status === 400, `status ${bad.status}`);

    const wrong = await cmd(userCookie, "lamp", { type: "level", value: 50 });
    check("level on a plain switch is a 400", wrong.status === 400, `status ${wrong.status}`);
  }

  // Sensors are read-only: any command is rejected.
  {
    const ro = await cmd(adminCookie, "temp", { type: "on" });
    check("commanding a sensor is a 400 (read-only)", ro.status === 400, `status ${ro.status}`);
  }

  // Scenes: a user may apply, applying drives every listed device.
  {
    const list = await (await call(userCookie, "/api/scenes")).json();
    check("user can list scenes", Array.isArray(list.scenes) && list.scenes.length > 0);

    const applied = await call(userCookie, "/api/scenes/movie/apply", { method: "POST" });
    const body = await applied.json();
    const ceiling = (body.devices || []).find((d) => d.id === "ceiling");
    check("user can apply the 'movie night' scene",
      applied.status === 200 && body.applied_scene === "movie", `status ${applied.status}`);
    check("applying the scene dimmed the ceiling to 20%", ceiling && ceiling.level === 20,
      JSON.stringify(ceiling));
  }

  // Only the admin may add a device.
  {
    const denied = await call(userCookie, "/api/devices", {
      method: "POST",
      body: { kind: "switch", id: "9", name: "sneaky" },
    });
    check("user is forbidden from adding a device", denied.status === 403, `status ${denied.status}`);

    const ok = await call(adminCookie, "/api/devices", {
      method: "POST",
      body: { kind: "dimmer", id: "9", name: "patio lights" },
    });
    check("admin can add a dimmer", ok.status === 200, `status ${ok.status}`);

    // The new device is actuatable by the user.
    const act = await cmd(userCookie, "9", { type: "level", value: 75 });
    const actBody = await act.json();
    check("user can drive the newly-added dimmer", act.status === 200 && actBody.level === 75);
  }

  // Only the admin may remove a device.
  {
    const denied = await call(userCookie, "/api/devices/9", { method: "DELETE" });
    check("user is forbidden from removing a device", denied.status === 403, `status ${denied.status}`);

    const ok = await call(adminCookie, "/api/devices/9", { method: "DELETE" });
    check("admin can remove a device", ok.status === 200, `status ${ok.status}`);
  }

  // Only the admin may create/delete a scene.
  {
    const denied = await call(userCookie, "/api/scenes", {
      method: "POST",
      body: { id: "away", name: "away", steps: [{ device: "lamp", command: { type: "off" } }] },
    });
    check("user is forbidden from creating a scene", denied.status === 403, `status ${denied.status}`);

    const ok = await call(adminCookie, "/api/scenes", {
      method: "POST",
      body: { id: "away", name: "away mode", steps: [{ device: "lamp", command: { type: "off" } }] },
    });
    check("admin can create a scene", ok.status === 200, `status ${ok.status}`);

    const del = await call(adminCookie, "/api/scenes/away", { method: "DELETE" });
    check("admin can delete a scene", del.status === 200, `status ${del.status}`);
  }

  // No session => 401; missing device => 404.
  {
    const noauth = await fetch(`${base}/api/devices`);
    check("unauthenticated request is rejected", noauth.status === 401, `status ${noauth.status}`);

    const missing = await cmd(adminCookie, "404", { type: "on" });
    check("unknown device is a 404", missing.status === 404, `status ${missing.status}`);
  }

  console.log(failures === 0 ? "\nall home-hub checks passed" : `\n${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
}

console.error("usage: live.mjs setup <allowlistPath> | run <baseUrl>");
process.exit(2);
