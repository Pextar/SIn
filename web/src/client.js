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
   * Make an authenticated request. Fetches a challenge, signs a token bound to
   * this exact URL+method, and sends it.
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
}
