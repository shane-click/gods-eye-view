import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CCTV_FRAME_FETCH_TIMEOUT_MS,
  compassToHeadingDeg,
  fetchCctvImageFromUpstream,
} from '../../vite.config.js';

test('CCTV upstream frame fetch supplies a bounded abort signal', async () => {
  let observedSignal = null;
  const startedAt = Date.now();
  const result = await fetchCctvImageFromUpstream('https://example.com/frame.jpg', {
    timeoutMs: 20,
    fetchImpl: (_url, options) => new Promise((_resolve, reject) => {
      observedSignal = options.signal;
      options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true });
    }),
  });

  assert.equal(result, null);
  assert.ok(observedSignal instanceof AbortSignal);
  assert.equal(observedSignal.aborted, true);
  assert.ok(Date.now() - startedAt < 500, 'test timeout should settle promptly');
  assert.ok(CCTV_FRAME_FETCH_TIMEOUT_MS < 10_000, 'production timeout must beat the active refresh cadence');
});

test('CCTV upstream frame fetch returns a valid image response', async () => {
  const result = await fetchCctvImageFromUpstream('https://example.com/frame.jpg', {
    timeoutMs: 100,
    fetchImpl: async () => new Response(Uint8Array.from([1, 2, 3]), {
      status: 200,
      headers: { 'Content-Type': 'image/jpeg' },
    }),
  });

  assert.equal(result?.ok, true);
  assert.equal(result?.contentType, 'image/jpeg');
  assert.deepEqual(result?.body, Buffer.from([1, 2, 3]));
});

test('CCTV upstream frame fetch forwards per-source request headers', async () => {
  let observedHeaders = null;
  const body = new Uint8Array([0xff, 0xd8, 0xff]);
  await fetchCctvImageFromUpstream('https://example.com/frame.jpg', {
    headers: { Accept: 'image/*', Referer: 'https://www.livetraffic.com/' },
    fetchImpl: async (_url, options) => {
      observedHeaders = options.headers;
      return {
        ok: true,
        headers: new Headers({ 'content-type': 'image/jpeg' }),
        arrayBuffer: async () => body.buffer,
      };
    },
  });

  assert.equal(observedHeaders.Accept, 'image/*');
  assert.equal(observedHeaders.Referer, 'https://www.livetraffic.com/');
  assert.equal(observedHeaders['User-Agent'], 'gods-eye-view-cctv-proxy/1.0');
});

test('compass labels convert to headings in every published spelling', () => {
  assert.equal(compassToHeadingDeg('N'), 0);
  assert.equal(compassToHeadingDeg('N-W'), 315);
  assert.equal(compassToHeadingDeg('S-E'), 135);
  assert.equal(compassToHeadingDeg('NorthEast'), 45);
  assert.equal(compassToHeadingDeg('south west'), 225);
  assert.equal(compassToHeadingDeg('nne'), 22.5);
  assert.ok(Number.isNaN(compassToHeadingDeg('Both directions')));
  assert.ok(Number.isNaN(compassToHeadingDeg('')));
  assert.ok(Number.isNaN(compassToHeadingDeg(undefined)));
});
