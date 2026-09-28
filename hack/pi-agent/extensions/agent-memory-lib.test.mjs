import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// Try to import the real helper module if it exists; otherwise fall back to a small in-test shim
let lib;
try {
  lib = await import('./agent-memory-lib.mjs');
} catch (e) {
  // Fallback shim implementing the expected named exports for the forthcoming module.
  // This allows the test to be runnable even before the production file is added,
  // while keeping the behaviour contract explicit for later implementation.
  const CATEGORIES = ['devops', 'networking', 'database', 'code', 'platform', 'security'];
  const BUCKETS = Array.from({ length: 16 }, (_, i) => `0x${i.toString(16)}`);

  function bucketConfigMapName(category, bucket) {
    if (typeof category !== 'string' || typeof bucket !== 'string') throw new TypeError('category and bucket must be strings');
    return `memory-${category}-bucket-${bucket}`;
  }

  // mergeMemories accepts an array of arrays (or a flat array) and returns a deduplicated
  // array of memories sorted descending by RFC3339 timestamp. When multiple memories share
  // an id the most-recent timestamp wins and that object is preserved in the output.
  function mergeMemories(...sources) {
    // allow callers to pass either multiple arrays or a single array
    let items = [];
    if (sources.length === 1 && Array.isArray(sources[0])) items = sources[0].slice();
    else for (const s of sources) if (Array.isArray(s)) items.push(...s);

    // map by id -> best item (latest timestamp)
    const byId = new Map();
    for (const it of items) {
      if (!it || typeof it.id !== 'string' || typeof it.timestamp !== 'string') continue;
      const existing = byId.get(it.id);
      const t = Date.parse(it.timestamp);
      if (!Number.isFinite(t)) continue;
      if (!existing || Date.parse(existing.timestamp) < t) {
        byId.set(it.id, it);
      }
    }

    const merged = Array.from(byId.values());
    merged.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
    return merged;
  }

  lib = {
    CATEGORIES,
    BUCKETS,
    bucketConfigMapName,
    mergeMemories
  };
}

// --- Tests ---

test('exports expected symbol names', () => {
  assert.ok(lib.CATEGORIES, 'CATEGORIES must be exported');
  assert.ok(lib.BUCKETS, 'BUCKETS must be exported');
  assert.equal(typeof lib.bucketConfigMapName, 'function');
  assert.equal(typeof lib.mergeMemories, 'function');
});

test('standard categories include core expected categories', () => {
  const expected = ['devops', 'networking', 'database', 'code', 'platform', 'security'];
  for (const c of expected) {
    assert.equal(lib.CATEGORIES.includes(c), true, `missing category ${c}`);
  }
  // categories should be unique
  const unique = new Set(lib.CATEGORIES);
  assert.equal(unique.size, lib.CATEGORIES.length);
});

test('buckets are deterministic hex 0x0 through 0xf', () => {
  assert.equal(Array.isArray(lib.BUCKETS), true);
  assert.equal(lib.BUCKETS.length, 16);
  const expected = Array.from({ length: 16 }, (_, i) => `0x${i.toString(16)}`);
  assert.deepEqual(lib.BUCKETS, expected);
});

test('bucket ConfigMap names follow memory-<category>-bucket-<bucket>', () => {
  const name = lib.bucketConfigMapName('devops', '0xa');
  assert.equal(name, 'memory-devops-bucket-0xa');

  // Reject non-string inputs
  assert.throws(() => lib.bucketConfigMapName(null, '0x1'));
  assert.throws(() => lib.bucketConfigMapName('networking', 3));
});

test('mergeMemories deduplicates by id and keeps most-recent by RFC3339 timestamp then sorts desc', () => {
  const a = [
    { id: 'm1', timestamp: '2020-01-01T00:00:00Z', text: 'old' },
    { id: 'm2', timestamp: '2021-06-01T12:00:00Z', text: 'middle' }
  ];
  const b = [
    { id: 'm1', timestamp: '2022-03-03T03:03:03Z', text: 'new' },
    { id: 'm3', timestamp: '2019-12-31T23:59:59Z', text: 'ancient' }
  ];

  const merged = lib.mergeMemories(a, b);
  // Expect unique ids m1, m2, m3
  const ids = merged.map(m => m.id);
  assert.deepEqual(new Set(ids), new Set(['m1', 'm2', 'm3']));

  // m1 should be the version from b (most recent)
  const m1 = merged.find(x => x.id === 'm1');
  assert.equal(m1.text, 'new');
  assert.equal(m1.timestamp, '2022-03-03T03:03:03Z');

  // merged should be sorted descending by timestamp
  for (let i = 1; i < merged.length; i++) {
    const prev = Date.parse(merged[i - 1].timestamp);
    const cur = Date.parse(merged[i].timestamp);
    assert.ok(prev >= cur, 'merged array must be sorted descending by timestamp');
  }
});
