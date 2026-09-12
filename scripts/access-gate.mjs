/**
 * @module accessGate
 *
 * Shared-password gate for hosted deployments. When GEV_ACCESS_PASSWORD is
 * set, every request to the dev or preview server (page, assets, /api/*)
 * must carry HTTP Basic credentials whose password matches. The browser
 * prompts once and then attaches the credentials to every same-origin
 * request, so no client code changes are needed. Unset, the gate is off and
 * local development is unchanged.
 *
 * The health path stays open so a hosting platform's health check can reach
 * it without credentials.
 */

import { createHash, timingSafeEqual } from 'node:crypto';

export const ACCESS_GATE_HEALTH_PATH = '/healthz';
const REALM = 'God\'s Eye View';

/**
 * Pull the password out of an HTTP Basic Authorization header.
 *
 * Basic credentials are `user:password` in base64. The username is ignored;
 * a header with no colon is treated as a bare password.
 *
 * @param {string|undefined} header - Raw Authorization header value.
 * @returns {string|null} The password, or null when the header is not Basic.
 */
export function parseBasicAuthPassword(header) {
  const value = String(header || '');
  const match = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(value);
  if (!match) return null;
  let decoded = '';
  try {
    decoded = Buffer.from(match[1], 'base64').toString('utf8');
  } catch {
    return null;
  }
  const separator = decoded.indexOf(':');
  return separator === -1 ? decoded : decoded.slice(separator + 1);
}

/**
 * Constant-time password comparison. Both sides are hashed first so the
 * comparison length never depends on the candidate.
 *
 * @param {string|null} candidate - Password supplied by the client.
 * @param {string} expected - Configured password.
 * @returns {boolean}
 */
export function isPasswordMatch(candidate, expected) {
  if (typeof candidate !== 'string' || !expected) return false;
  const candidateDigest = createHash('sha256').update(candidate).digest();
  const expectedDigest = createHash('sha256').update(expected).digest();
  return timingSafeEqual(candidateDigest, expectedDigest);
}

/**
 * Build a connect-style middleware that enforces the shared password.
 *
 * @param {object} options
 * @param {string} options.password - Configured password (non-empty).
 * @param {string} [options.healthPath] - Path that bypasses the gate.
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, next: () => void) => void}
 */
export function createAccessGateMiddleware({ password, healthPath = ACCESS_GATE_HEALTH_PATH }) {
  return function accessGate(req, res, next) {
    const requestPath = String(req.url || '').split('?')[0];
    if (requestPath === healthPath) {
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
      res.end('ok');
      return;
    }

    const supplied = parseBasicAuthPassword(req.headers?.authorization);
    if (isPasswordMatch(supplied, password)) {
      next();
      return;
    }

    res.writeHead(401, {
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'Content-Type': 'text/plain',
      'Cache-Control': 'no-store',
    });
    res.end('Authentication required');
  };
}

/**
 * Vite plugin that installs the gate ahead of every other middleware on both
 * the dev and preview servers. Without a password it is an inert plugin
 * with no hooks, so the plugin list can include it unconditionally and code
 * that walks the list never meets a null entry.
 *
 * @param {string|undefined} password - Value of GEV_ACCESS_PASSWORD.
 * @returns {import('vite').Plugin}
 */
export function accessGatePlugin(password) {
  const configured = String(password || '');
  if (!configured) return { name: 'gev-access-gate', enforce: 'pre' };
  const middleware = createAccessGateMiddleware({ password: configured });
  return {
    name: 'gev-access-gate',
    enforce: 'pre',
    configureServer(server) {
      server.middlewares.use(middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use(middleware);
    },
  };
}
