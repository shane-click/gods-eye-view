import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  ACCESS_GATE_HEALTH_PATH,
  ACCESS_GATE_LOGIN_PATH,
  ACCESS_GATE_LOGOUT_PATH,
  accessGatePlugin,
  clientKeyFor,
  createAccessGateMiddleware,
  isPasswordMatch,
  parseBasicAuthPassword,
  safeNextPath,
} from '../scripts/access-gate.mjs';
import { createLoginRateLimiter } from '../scripts/access-gate-rate-limit.mjs';
import {
  SESSION_COOKIE_NAME,
  deriveSessionSecret,
  isSessionTokenValid,
  issueSessionToken,
  parseCookies,
} from '../scripts/access-gate-session.mjs';

const PASSWORD = 'hunter2';

function basicHeader(user, password) {
  return `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
}

function fakeResponse() {
  const response = { statusCode: 0, headers: {}, body: '', finished: null };
  response.finished = new Promise((resolve) => {
    response.writeHead = (status, headers) => {
      response.statusCode = status;
      response.headers = headers || {};
    };
    response.end = (body) => {
      response.body = String(body || '');
      resolve();
    };
  });
  return response;
}

function fakeRequest({ url = '/', method = 'GET', headers = {}, body = '', remoteAddress = '203.0.113.9' } = {}) {
  const request = new EventEmitter();
  request.url = url;
  request.method = method;
  request.headers = headers;
  request.socket = { remoteAddress };
  process.nextTick(() => {
    if (body) request.emit('data', body);
    request.emit('end');
  });
  return request;
}

async function run(middleware, requestOptions) {
  const request = fakeRequest(requestOptions);
  const response = fakeResponse();
  let passed = false;
  const nextCalled = new Promise((resolve) => {
    middleware(request, response, () => { passed = true; resolve(); });
  });
  await Promise.race([response.finished, nextCalled]);
  return { passed, response };
}

function loginPost(password, extra = {}) {
  const body = new URLSearchParams({ password, next: '/?setup=1' }).toString();
  return {
    url: ACCESS_GATE_LOGIN_PATH,
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'text/html', ...extra.headers },
    body,
    remoteAddress: extra.remoteAddress,
  };
}

test('parseBasicAuthPassword reads the password after the first colon', () => {
  assert.equal(parseBasicAuthPassword(basicHeader('anyone', 'hunter2')), 'hunter2');
  assert.equal(parseBasicAuthPassword(basicHeader('', 'pa:ss:word')), 'pa:ss:word');
  assert.equal(parseBasicAuthPassword('Bearer abc'), null);
  assert.equal(parseBasicAuthPassword(undefined), null);
});

test('isPasswordMatch accepts only the configured password', () => {
  assert.equal(isPasswordMatch('hunter2', 'hunter2'), true);
  assert.equal(isPasswordMatch('hunter', 'hunter2'), false);
  assert.equal(isPasswordMatch(null, 'hunter2'), false);
  assert.equal(isPasswordMatch('', ''), false);
});

test('session tokens verify, expire, and reject tampering', () => {
  const secret = deriveSessionSecret(PASSWORD);
  const token = issueSessionToken(secret, 1000, 5000);
  assert.equal(isSessionTokenValid(secret, token, 2000), true);
  assert.equal(isSessionTokenValid(secret, token, 6001), false, 'expired');
  assert.equal(isSessionTokenValid(deriveSessionSecret('other'), token, 2000), false, 'different password');
  assert.equal(isSessionTokenValid(secret, `${token}x`, 2000), false, 'tampered signature');
  assert.equal(isSessionTokenValid(secret, '9999999999999.abc', 2000), false, 'forged expiry');
  assert.deepEqual(parseCookies('a=1; gev_session=t%20k; b=2'), { a: '1', gev_session: 't k', b: '2' });
});

test('safeNextPath only allows same-origin relative paths', () => {
  assert.equal(safeNextPath('/?setup=1'), '/?setup=1');
  assert.equal(safeNextPath('//evil.example'), '/');
  assert.equal(safeNextPath('https://evil.example'), '/');
  assert.equal(safeNextPath(ACCESS_GATE_LOGIN_PATH), '/');
  assert.equal(safeNextPath(undefined), '/');
});

test('clientKeyFor uses the proxy header only when told to trust it', () => {
  const request = { headers: { 'x-forwarded-for': '198.51.100.7, 10.0.0.2' }, socket: { remoteAddress: '127.0.0.1' } };
  assert.equal(clientKeyFor(request, false), '127.0.0.1');
  assert.equal(clientKeyFor(request, true), '10.0.0.2');
});

test('browser page requests redirect to the login page, API requests get JSON 401', async () => {
  const middleware = createAccessGateMiddleware({ password: PASSWORD });
  const page = await run(middleware, { url: '/?setup=1', headers: { accept: 'text/html' } });
  assert.equal(page.passed, false);
  assert.equal(page.response.statusCode, 302);
  assert.equal(page.response.headers.Location, `${ACCESS_GATE_LOGIN_PATH}?next=${encodeURIComponent('/?setup=1')}`);

  const api = await run(middleware, { url: '/api/cctv/sources', headers: { accept: 'application/json' } });
  assert.equal(api.passed, false);
  assert.equal(api.response.statusCode, 401);
  assert.equal(api.response.headers['WWW-Authenticate'], undefined, 'no native browser prompt');
});

test('login page renders, a correct code sets a session cookie, and the cookie passes', async () => {
  const middleware = createAccessGateMiddleware({ password: PASSWORD, now: () => 1_000_000 });
  const page = await run(middleware, { url: `${ACCESS_GATE_LOGIN_PATH}?next=%2F%3Fsetup%3D1`, headers: { accept: 'text/html' } });
  assert.equal(page.response.statusCode, 200);
  assert.match(page.response.body, /ACCESS CODE/);
  assert.match(page.response.body, /value="\/\?setup=1"/);

  const login = await run(middleware, loginPost(PASSWORD));
  assert.equal(login.response.statusCode, 303);
  assert.equal(login.response.headers.Location, '/?setup=1');
  const cookie = login.response.headers['Set-Cookie'];
  assert.match(cookie, new RegExp(`^${SESSION_COOKIE_NAME}=`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.doesNotMatch(cookie, /Secure/, 'plain HTTP request gets no Secure flag');

  const token = decodeURIComponent(cookie.split(';')[0].split('=')[1]);
  const allowed = await run(middleware, { url: '/api/tomtom/status', headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` } });
  assert.equal(allowed.passed, true);
});

test('secure flag follows X-Forwarded-Proto only with a trusted proxy', async () => {
  const trusting = createAccessGateMiddleware({ password: PASSWORD, trustProxy: true });
  const login = await run(trusting, loginPost(PASSWORD, { headers: { 'x-forwarded-proto': 'https' } }));
  assert.match(login.response.headers['Set-Cookie'], /Secure/);

  const untrusting = createAccessGateMiddleware({ password: PASSWORD });
  const plain = await run(untrusting, loginPost(PASSWORD, { headers: { 'x-forwarded-proto': 'https' } }));
  assert.doesNotMatch(plain.response.headers['Set-Cookie'], /Secure/);
});

test('wrong codes are rejected and the sixth attempt in a window is rate limited', async () => {
  let clock = 0;
  const rateLimiter = createLoginRateLimiter({ now: () => clock, windowMs: 60_000, maxPerClient: 5 });
  const middleware = createAccessGateMiddleware({ password: PASSWORD, rateLimiter, now: () => clock });

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const wrong = await run(middleware, loginPost('nope'));
    assert.equal(wrong.response.statusCode, 401, `attempt ${attempt}`);
    assert.match(wrong.response.body, /not recognised/);
  }
  const blocked = await run(middleware, loginPost(PASSWORD));
  assert.equal(blocked.response.statusCode, 429, 'even the right code is refused while throttled');
  assert.ok(Number(blocked.response.headers['Retry-After']) > 0);

  const otherClient = await run(middleware, loginPost(PASSWORD, { remoteAddress: '203.0.113.10' }));
  assert.equal(otherClient.response.statusCode, 303, 'another client is unaffected');

  clock = 61_000;
  const afterWindow = await run(middleware, loginPost(PASSWORD));
  assert.equal(afterWindow.response.statusCode, 303, 'window elapsed');
});

test('global failure cap refuses every client', () => {
  let clock = 0;
  const limiter = createLoginRateLimiter({ now: () => clock, windowMs: 1000, maxPerClient: 100, maxGlobal: 3 });
  limiter.recordFailure('a');
  limiter.recordFailure('b');
  limiter.recordFailure('c');
  assert.equal(limiter.check('d').allowed, false);
  clock = 1001;
  assert.equal(limiter.check('d').allowed, true);
});

test('Basic credentials still pass for scripts, and bad ones count as failures', async () => {
  let clock = 0;
  const rateLimiter = createLoginRateLimiter({ now: () => clock, maxPerClient: 2 });
  const middleware = createAccessGateMiddleware({ password: PASSWORD, rateLimiter, now: () => clock });
  const ok = await run(middleware, { url: '/api/tomtom/status', headers: { authorization: basicHeader('x', PASSWORD) } });
  assert.equal(ok.passed, true);

  await run(middleware, { url: '/', headers: { authorization: basicHeader('x', 'bad') } });
  await run(middleware, { url: '/', headers: { authorization: basicHeader('x', 'bad') } });
  const throttled = await run(middleware, { url: '/', headers: { authorization: basicHeader('x', PASSWORD) } });
  assert.equal(throttled.response.statusCode, 429);
});

test('logout clears the cookie and health stays open', async () => {
  const middleware = createAccessGateMiddleware({ password: PASSWORD });
  const logout = await run(middleware, { url: ACCESS_GATE_LOGOUT_PATH, headers: { accept: 'text/html' } });
  assert.equal(logout.response.statusCode, 303);
  assert.match(logout.response.headers['Set-Cookie'], /Max-Age=0/);

  const health = await run(middleware, { url: `${ACCESS_GATE_HEALTH_PATH}?probe=1` });
  assert.equal(health.response.statusCode, 200);
  assert.equal(health.response.body, 'ok');
});

test('plugin is inert without a password and installs on both servers with one', () => {
  for (const inert of [accessGatePlugin(''), accessGatePlugin(undefined)]) {
    assert.equal(inert.name, 'gev-access-gate');
    assert.equal(inert.configureServer, undefined);
  }
  const plugin = accessGatePlugin(PASSWORD, { trustProxy: true });
  const installed = [];
  const fakeServer = { middlewares: { use: (fn) => installed.push(fn) } };
  plugin.configureServer(fakeServer);
  plugin.configurePreviewServer(fakeServer);
  assert.equal(installed.length, 2);
});
