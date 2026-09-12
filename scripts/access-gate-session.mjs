/**
 * @module access-gate-session
 *
 * Signed session tokens for the access gate. A token is `<expiresAt>.<hmac>`
 * where the HMAC key is derived from the configured password, so sessions
 * survive a server restart and are all invalidated the moment the password
 * changes. No server-side session store is needed.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE_NAME = 'gev_session';
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SECRET_LABEL = 'gev-access-gate-session-v1';

/**
 * Derive the signing key from the shared password.
 *
 * @param {string} password - Configured GEV_ACCESS_PASSWORD.
 * @returns {Buffer} 32-byte HMAC key.
 */
export function deriveSessionSecret(password) {
  return createHmac('sha256', SECRET_LABEL).update(String(password)).digest();
}

function signExpiry(secret, expiresAt) {
  return createHmac('sha256', secret).update(String(expiresAt)).digest('base64url');
}

/**
 * Issue a token that stays valid for `ttlMs` from `now`.
 *
 * @param {Buffer} secret - From deriveSessionSecret.
 * @param {number} [now] - Epoch ms.
 * @param {number} [ttlMs] - Lifetime.
 * @returns {string} Cookie-safe token.
 */
export function issueSessionToken(secret, now = Date.now(), ttlMs = SESSION_TTL_MS) {
  const expiresAt = now + ttlMs;
  return `${expiresAt}.${signExpiry(secret, expiresAt)}`;
}

/**
 * Check a token's signature and expiry in constant time.
 *
 * @param {Buffer} secret - From deriveSessionSecret.
 * @param {unknown} token - Cookie value.
 * @param {number} [now] - Epoch ms.
 * @returns {boolean}
 */
export function isSessionTokenValid(secret, token, now = Date.now()) {
  if (typeof token !== 'string') return false;
  const separator = token.indexOf('.');
  if (separator <= 0) return false;
  const expiresAt = Number(token.slice(0, separator));
  const signature = token.slice(separator + 1);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) return false;
  const expected = Buffer.from(signExpiry(secret, expiresAt));
  const supplied = Buffer.from(signature);
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

/**
 * Parse a Cookie request header into a name to value map.
 *
 * @param {string|undefined} header - Raw Cookie header.
 * @returns {Record<string,string>}
 */
export function parseCookies(header) {
  const cookies = {};
  for (const part of String(header || '').split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name) cookies[name] = decodeURIComponent(value);
  }
  return cookies;
}

/**
 * Build the Set-Cookie header for a session cookie.
 *
 * @param {string} token - Value from issueSessionToken, or '' to clear.
 * @param {object} options
 * @param {boolean} options.secure - Add the Secure flag (HTTPS only).
 * @param {number} [options.maxAgeSeconds] - Lifetime; 0 clears the cookie.
 * @returns {string}
 */
export function sessionCookieHeader(token, { secure, maxAgeSeconds = SESSION_TTL_MS / 1000 }) {
  const attributes = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (secure) attributes.push('Secure');
  return attributes.join('; ');
}
