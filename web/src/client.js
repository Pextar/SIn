// Talks to a SIn-protected server: fetch a challenge, sign the request with the
// unlocked key, and send it with the NIP-98 Authorization header.
//
// The signer is injected as `signToken(req)` so this module stays agnostic
// about where the key lives or how it was unlocked.

import { nip98Token } from "./signer.js";

export class SinClient {
  /**
   * @param {string} baseUrl       e.g. "https://sockets.local"
   * @param {string} challengePath endpoint that mints a challenge
   */
  constructor(baseUrl, challengePath = "/auth/challenge") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.challengePath = challengePath;
  }

  /** Fetch a fresh challenge string from the server. */
  async getChallenge() {
    const res = await fetch(this.baseUrl + this.challengePath, {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`challenge request failed: HTTP ${res.status}`);
    const body = await res.json();
    if (!body.challenge) throw new Error("server response had no challenge");
    return body.challenge;
  }

  /**
   * Make a per-request NIP-98 call. Fetches a challenge, signs a token bound to
   * this exact URL+method, and sends it. Best for one-off calls; the client
   * signs every request.
   *
   * @param {Uint8Array} secretKey
   * @param {string} path
   * @param {{method?: string, body?: BodyInit}} opts
   */
  async authedFetch(secretKey, path, { method = "GET", body } = {}) {
    const url = this.baseUrl + path;
    const challenge = await this.getChallenge();
    const token = nip98Token(secretKey, { url, method, challenge });
    return fetch(url, { method, body, headers: { Authorization: token } });
  }

  /**
   * Sign in once and establish a session. Performs a single NIP-98 sign-in
   * against the login endpoint; the server replies with an HttpOnly session
   * cookie (set automatically by the browser) and a token in the body.
   *
   * After this, use {@link sessionFetch} to call protected routes without
   * signing again, until the session expires.
   *
   * @param {Uint8Array} secretKey
   * @param {string} loginPath
   * @returns {Promise<{token: string, npub: string, role: string, label: string, expires_at: number}>}
   */
  async login(secretKey, loginPath = "/auth/login") {
    const url = this.baseUrl + loginPath;
    const challenge = await this.getChallenge();
    const token = nip98Token(secretKey, { url, method: "POST", challenge });
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: token },
      credentials: "same-origin", // accept the Set-Cookie
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`login failed: HTTP ${res.status} ${detail}`);
    }
    return res.json();
  }

  /**
   * Call a protected route using the session cookie established by {@link login}.
   * No key, no signing — just the cookie the browser already holds.
   *
   * @param {string} path
   * @param {{method?: string, body?: BodyInit}} opts
   */
  async sessionFetch(path, { method = "GET", body } = {}) {
    return fetch(this.baseUrl + path, { method, body, credentials: "same-origin" });
  }
}
