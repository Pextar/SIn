// NIP-98 signing. Given an unlocked secret key, produce an Authorization token
// bound to a specific request URL, method, and server challenge.
//
// Pure crypto, no DOM — runs under Node so the interop test can check that the
// tokens we emit are accepted by the Rust `sin-core` verifier.

import { finalizeEvent } from "nostr-tools/pure";

/** NIP-98 HTTP Auth event kind. */
export const KIND_HTTP_AUTH = 27235;

/** Base64 (standard, padded) of a UTF-8 string — matches Rust's STANDARD engine. */
function base64Utf8(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/**
 * Build and sign the NIP-98 event binding this request to a challenge.
 *
 * @param {Uint8Array} secretKey
 * @param {{url: string, method: string, challenge: string, createdAt?: number}} req
 * @returns the finalized event (with id, pubkey, sig).
 */
export function buildAuthEvent(secretKey, { url, method, challenge, createdAt }) {
  const template = {
    kind: KIND_HTTP_AUTH,
    created_at: createdAt ?? Math.floor(Date.now() / 1000),
    tags: [
      ["u", url],
      ["method", method.toUpperCase()],
      ["challenge", challenge],
    ],
    content: "",
  };
  return finalizeEvent(template, secretKey);
}

/**
 * Produce the full `Authorization` header value: `Nostr <base64(event-json)>`.
 *
 * @param {Uint8Array} secretKey
 * @param {{url: string, method: string, challenge: string, createdAt?: number}} req
 */
export function nip98Token(secretKey, req) {
  const event = buildAuthEvent(secretKey, req);
  return `Nostr ${base64Utf8(JSON.stringify(event))}`;
}
