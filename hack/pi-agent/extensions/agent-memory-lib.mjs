export const CATEGORIES = ['devops', 'networking', 'database', 'code', 'platform', 'security'];

export const BUCKETS = Array.from({ length: 16 }, (_, i) => `0x${i.toString(16)}`);

export function bucketConfigMapName(category, bucket) {
  if (typeof category !== 'string' || typeof bucket !== 'string') {
    throw new TypeError('category and bucket must be strings');
  }
  return `memory-${category}-bucket-${bucket}`;
}

// mergeMemories accepts multiple arrays or a single array argument and returns
// a deduplicated array of memories: when ids collide the item with the
// most-recent RFC3339 timestamp wins. The result is sorted descending by timestamp.
export function mergeMemories(...sources) {
  let items = [];
  if (sources.length === 1 && Array.isArray(sources[0])) {
    items = sources[0].slice();
  } else {
    for (const s of sources) {
      if (Array.isArray(s)) items.push(...s);
    }
  }

  const byId = new Map();
  for (const it of items) {
    if (!it || typeof it.id !== 'string' || typeof it.timestamp !== 'string') continue;
    const t = Date.parse(it.timestamp);
    if (!Number.isFinite(t)) continue;
    const existing = byId.get(it.id);
    if (!existing || Date.parse(existing.timestamp) < t) {
      byId.set(it.id, it);
    }
  }

  const merged = Array.from(byId.values());
  merged.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  return merged;
}
