/**
 * @module access-gate
 *
 * Shared-password gate for hosted deployments. When GEV_ACCESS_PASSWORD is
 * set, every request to the dev or preview server (page, assets, /api/*)
 * needs either a valid session cookie, obtained from the sign-in page at
 * /auth/login, or HTTP Basic credentials with the password (handy for curl).
 * Unset, the gate is off and local development is unchanged.
 *
 * Failed sign-ins are throttled per client and globally (see
 * access-gate-rate-limit.mjs). Behind a reverse proxy set GEV_TRUST_PROXY=1
 * so the client is identified by X-Forwarded-For instead of the proxy's
 * loopback address.
 *
 * The health path stays open so a hosting platform's health check can reach
 * it without credentials.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { createLoginRateLimiter } from './access-gate-rate-limit.mjs';
import { renderLoginPage } from './access-gate-login-page.mjs';
import {
  SESSION_COOKIE_NAME,
  deriveSessionSecret,
  isSessionTokenValid,
  issueSessionToken,
  parseCookies,
  sessionCookieHeader,
} from './access-gate-session.mjs';

export const ACCESS_GATE_HEALTH_PATH = '/healthz';
export const ACCESS_GATE_LOGIN_PATH = '/auth/login';
export const ACCESS_GATE_LOGOUT_PATH = '/auth/logout';
const MAX_LOGIN_BODY_BYTES = 4096;
const WRONG_PASSWORD_MESSAGE = 'Access code not recognised.';

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
 * Identify the client for rate limiting.
 *
 * Without a trusted proxy the socket address is the only honest signal.
 * Behind one, the proxy writes the real client address into
 * X-Forwarded-For; the rightmost entry is the hop the proxy itself saw.
 *
 * @param {import('node:http').IncomingMessage} req
 * @param {boolean} trustProxy
 * @returns {string}
 */
export function clientKeyFor(req, trustProxy) {
  if (trustProxy) {
    const forwarded = String(req.headers?.['x-forwarded-for'] || '');
    const hops = forwarded.split(',').map((hop) => hop.trim()).filter(Boolean);
    if (hops.length) return hops[hops.length - 1];
  }
  return String(req.socket?.remoteAddress || 'local');
}

/**
 * Only allow same-origin relative paths as the post-login destination.
 *
 * @param {unknown} candidate
 * @returns {string}
 */
export function safeNextPath(candidate) {
  const value = typeof candidate === 'string' ? candidate : '';
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/';
  if (value.startsWith(ACCESS_GATE_LOGIN_PATH) || value.startsWith(ACCESS_GATE_LOGOUT_PATH)) return '/';
  return value;
}

function isSecureRequest(req, trustProxy) {
  if (req.socket?.encrypted) return true;
  return trustProxy && String(req.headers?.['x-forwarded-proto'] || '').toLowerCase() === 'https';
}

function wantsHtml(req) {
  const accept = String(req.headers?.accept || '');
  return accept.includes('text/html');
}

function readFormBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    let overflow = false;
    req.on('data', (chunk) => {
      if (overflow) return;
      raw += chunk;
      if (raw.length > MAX_LOGIN_BODY_BYTES) overflow = true;
    });
    req.on('end', () => {
      if (overflow) {
        resolve({});
        return;
      }
      const fields = {};
      for (const [name, value] of new URLSearchParams(raw)) fields[name] = value;
      resolve(fields);
    });
    req.on('error', () => resolve({}));
  });
}

function sendHtml(res, status, html, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(html);
}

function sendJson(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

/**
 * Build a connect-style middleware that enforces the shared password.
 *
 * @param {object} options
 * @param {string} options.password - Configured password (non-empty).
 * @param {string} [options.healthPath] - Path that bypasses the gate.
 * @param {boolean} [options.trustProxy] - Read X-Forwarded-* from a reverse proxy.
 * @param {import('./access-gate-rate-limit.mjs').LoginRateLimiter} [options.rateLimiter]
 * @param {() => number} [options.now] - Clock, injectable for tests.
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, next: () => void) => void}
 */
export function createAccessGateMiddleware({
  password,
  healthPath = ACCESS_GATE_HEALTH_PATH,
  trustProxy = false,
  rateLimiter = createLoginRateLimiter(),
  now = () => Date.now(),
}) {
  const secret = deriveSessionSecret(password);

  function hasValidSession(req) {
    const cookies = parseCookies(req.headers?.cookie);
    return isSessionTokenValid(secret, cookies[SESSION_COOKIE_NAME], now());
  }

  function respondRateLimited(req, res, retryAfterMs, nextPath) {
    const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
    const headers = { 'Retry-After': String(retryAfterSeconds) };
    const message = `Too many attempts. Try again in ${Math.ceil(retryAfterSeconds / 60)} minute(s).`;
    if (wantsHtml(req)) {
      sendHtml(res, 429, renderLoginPage({ loginPath: ACCESS_GATE_LOGIN_PATH, nextPath, error: message }), headers);
      return;
    }
    sendJson(res, 429, { error: 'rate_limited', retryAfterSeconds }, headers);
  }

  async function handleLogin(req, res, requestPath, query) {
    const method = String(req.method || 'GET').toUpperCase();
    if (method === 'GET') {
      if (hasValidSession(req)) {
        res.writeHead(303, { Location: safeNextPath(query.get('next')), 'Cache-Control': 'no-store' });
        res.end();
        return;
      }
      sendHtml(res, 200, renderLoginPage({ loginPath: ACCESS_GATE_LOGIN_PATH, nextPath: safeNextPath(query.get('next')) }));
      return;
    }
    if (method !== 'POST') {
      res.writeHead(405, { Allow: 'GET, POST', 'Cache-Control': 'no-store' });
      res.end();
      return;
    }
    const fields = await readFormBody(req);
    const nextPath = safeNextPath(fields.next);
    const clientKey = clientKeyFor(req, trustProxy);
    const verdict = rateLimiter.check(clientKey);
    if (!verdict.allowed) {
      respondRateLimited(req, res, verdict.retryAfterMs, nextPath);
      return;
    }
    if (!isPasswordMatch(fields.password, password)) {
      rateLimiter.recordFailure(clientKey);
      sendHtml(res, 401, renderLoginPage({ loginPath: ACCESS_GATE_LOGIN_PATH, nextPath, error: WRONG_PASSWORD_MESSAGE }));
      return;
    }
    rateLimiter.recordSuccess(clientKey);
    res.writeHead(303, {
      Location: nextPath,
      'Set-Cookie': sessionCookieHeader(issueSessionToken(secret, now()), { secure: isSecureRequest(req, trustProxy) }),
      'Cache-Control': 'no-store',
    });
    res.end();
  }

  function handleLogout(req, res) {
    res.writeHead(303, {
      Location: ACCESS_GATE_LOGIN_PATH,
      'Set-Cookie': sessionCookieHeader('', { secure: isSecureRequest(req, trustProxy), maxAgeSeconds: 0 }),
      'Cache-Control': 'no-store',
    });
    res.end();
  }

  function handleBasicAuth(req, res, requestPath) {
    const clientKey = clientKeyFor(req, trustProxy);
    const verdict = rateLimiter.check(clientKey);
    if (!verdict.allowed) {
      respondRateLimited(req, res, verdict.retryAfterMs, requestPath);
      return false;
    }
    const supplied = parseBasicAuthPassword(req.headers?.authorization);
    if (isPasswordMatch(supplied, password)) {
      rateLimiter.recordSuccess(clientKey);
      return true;
    }
    rateLimiter.recordFailure(clientKey);
    sendJson(res, 401, { error: 'auth_required' });
    return false;
  }

  return function accessGate(req, res, next) {
    const [requestPath, queryString = ''] = String(req.url || '').split('?');
    const query = new URLSearchParams(queryString);

    if (requestPath === healthPath) {
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
      res.end('ok');
      return;
    }
    if (requestPath === ACCESS_GATE_LOGIN_PATH) {
      handleLogin(req, res, requestPath, query);
      return;
    }
    if (requestPath === ACCESS_GATE_LOGOUT_PATH) {
      handleLogout(req, res);
      return;
    }
    if (hasValidSession(req)) {
      next();
      return;
    }
    if (req.headers?.authorization) {
      if (handleBasicAuth(req, res, requestPath)) next();
      return;
    }
    if (wantsHtml(req)) {
      const nextPath = safeNextPath(String(req.url || '/'));
      res.writeHead(302, {
        Location: `${ACCESS_GATE_LOGIN_PATH}?next=${encodeURIComponent(nextPath)}`,
        'Cache-Control': 'no-store',
      });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'auth_required' });
  };
}

/**
 * Vite plugin that installs the gate ahead of every other middleware on both
 * the dev and preview servers. Without a password it is an inert plugin
 * with no hooks, so the plugin list can include it unconditionally and code
 * that walks the list never meets a null entry.
 *
 * @param {string|undefined} password - Value of GEV_ACCESS_PASSWORD.
 * @param {object} [options]
 * @param {boolean} [options.trustProxy] - Value of GEV_TRUST_PROXY === '1'.
 * @returns {import('vite').Plugin}
 */
export function accessGatePlugin(password, { trustProxy = false } = {}) {
  const configured = String(password || '');
  if (!configured) return { name: 'gev-access-gate', enforce: 'pre' };
  const middleware = createAccessGateMiddleware({ password: configured, trustProxy });
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
