import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ACCESS_GATE_HEALTH_PATH,
  accessGatePlugin,
  createAccessGateMiddleware,
  isPasswordMatch,
  parseBasicAuthPassword,
} from '../scripts/access-gate.mjs';

function basicHeader(user, password) {
  return `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
}

function fakeResponse() {
  const response = { statusCode: 0, headers: {}, body: '' };
  response.writeHead = (status, headers) => {
    response.statusCode = status;
    response.headers = headers || {};
  };
  response.end = (body) => {
    response.body = String(body || '');
  };
  return response;
}

function runGate(middleware, { url, authorization }) {
  const request = { url, headers: authorization ? { authorization } : {} };
  const response = fakeResponse();
  let passed = false;
  middleware(request, response, () => { passed = true; });
  return { passed, response };
}

test('parseBasicAuthPassword reads the password after the first colon', () => {
  assert.equal(parseBasicAuthPassword(basicHeader('anyone', 'hunter2')), 'hunter2');
  assert.equal(parseBasicAuthPassword(basicHeader('', 'pa:ss:word')), 'pa:ss:word');
  assert.equal(parseBasicAuthPassword(`Basic ${Buffer.from('bare').toString('base64')}`), 'bare');
  assert.equal(parseBasicAuthPassword('Bearer abc'), null);
  assert.equal(parseBasicAuthPassword(undefined), null);
});

test('isPasswordMatch accepts only the configured password', () => {
  assert.equal(isPasswordMatch('hunter2', 'hunter2'), true);
  assert.equal(isPasswordMatch('hunter', 'hunter2'), false);
  assert.equal(isPasswordMatch('hunter2 ', 'hunter2'), false);
  assert.equal(isPasswordMatch(null, 'hunter2'), false);
  assert.equal(isPasswordMatch('', ''), false);
});

test('gate challenges requests without valid credentials and lets valid ones through', () => {
  const middleware = createAccessGateMiddleware({ password: 'hunter2' });

  const denied = runGate(middleware, { url: '/api/cctv/sources' });
  assert.equal(denied.passed, false);
  assert.equal(denied.response.statusCode, 401);
  assert.match(denied.response.headers['WWW-Authenticate'], /^Basic realm=/);
  assert.equal(denied.response.headers['Cache-Control'], 'no-store');

  const wrong = runGate(middleware, { url: '/', authorization: basicHeader('me', 'nope') });
  assert.equal(wrong.passed, false);
  assert.equal(wrong.response.statusCode, 401);

  const allowed = runGate(middleware, { url: '/?setup=1', authorization: basicHeader('me', 'hunter2') });
  assert.equal(allowed.passed, true);
  assert.equal(allowed.response.statusCode, 0, 'middleware must not write a response when passing through');
});

test('health path answers without credentials and ignores its query string', () => {
  const middleware = createAccessGateMiddleware({ password: 'hunter2' });
  const health = runGate(middleware, { url: `${ACCESS_GATE_HEALTH_PATH}?probe=1` });
  assert.equal(health.passed, false);
  assert.equal(health.response.statusCode, 200);
  assert.equal(health.response.body, 'ok');
});

test('plugin is inert without a password and installs on both servers with one', () => {
  for (const inert of [accessGatePlugin(''), accessGatePlugin(undefined)]) {
    assert.equal(inert.name, 'gev-access-gate');
    assert.equal(inert.configureServer, undefined);
    assert.equal(inert.configurePreviewServer, undefined);
  }

  const plugin = accessGatePlugin('hunter2');
  assert.equal(plugin.name, 'gev-access-gate');
  assert.equal(plugin.enforce, 'pre');
  const installed = [];
  const fakeServer = { middlewares: { use: (fn) => installed.push(fn) } };
  plugin.configureServer(fakeServer);
  plugin.configurePreviewServer(fakeServer);
  assert.equal(installed.length, 2);
  assert.equal(typeof installed[0], 'function');
});
