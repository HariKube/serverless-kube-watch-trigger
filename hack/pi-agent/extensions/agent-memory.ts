import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { Type } from 'typebox';
import { CoreApi, KubeConfig } from '@kubernetes/client-node';
import * as memlib from './agent-memory-lib.mjs';

const DEFAULT_NAMESPACE_PATH = process.env.NS_PATH || '/var/run/secrets/kubernetes.io/serviceaccount/namespace';
const MEMORY_NAMESPACE = process.env.MEMORY_NAMESPACE || 'default';
const MEMORY_DECISION_URL = process.env.MEMORY_DECISION_URL || '';
const MEMORY_DECISION_TOKEN = process.env.MEMORY_DECISION_TOKEN || '';

function readNamespace() {
  try {
    return fs.readFileSync(DEFAULT_NAMESPACE_PATH, 'utf8').trim();
  } catch {
    return null;
  }
}

function shortId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

async function callDecisionEndpoint(payload: any) {
  if (!MEMORY_DECISION_URL) throw new Error('MEMORY_DECISION_URL is not configured');
  const url = new URL(MEMORY_DECISION_URL);
  const isHttps = url.protocol === 'https:';
  const body = JSON.stringify(payload);
  const options: https.RequestOptions = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body, 'utf8'),
      Accept: 'application/json'
    }
  };
  if (MEMORY_DECISION_TOKEN) {
    options.headers = { ...(options.headers || {}), Authorization: `Bearer ${MEMORY_DECISION_TOKEN}` };
  }

  if (isHttps) {
    // attempt to use in-cluster TLS settings via KubeConfig when available
    // (best-effort; not required for the external decision endpoint)
  }

  const client = isHttps ? https : http;

  return await new Promise<any>((resolve, reject) => {
    const req = client.request(url, options, res => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', chunk => (raw += chunk));
      res.on('end', () => {
        const status = res.statusCode || 0;
        if (status < 200 || status >= 300) {
          reject(new Error(`decision endpoint ${MEMORY_DECISION_URL} failed with status ${status}: ${raw.slice(0, 400)}`));
          return;
        }
        try {
          resolve(JSON.parse(raw));
        } catch (e: any) {
          reject(new Error(`decision endpoint returned invalid JSON: ${e.message}`));
        }
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

function ensureString(v: any) {
  return typeof v === 'string' ? v : '';
}

export default function registerAgentMemory(pi: any) {
  pi.registerTool({
    name: 'save_memory',
    label: 'save_memory',
    description: 'Persist a memory record into a ConfigMap-backed catalog and bucket store.',
    parameters: Type.Object({
      problem: Type.String({ description: 'Short problem summary' }),
      findings: Type.Optional(Type.Array(Type.String())),
      summary: Type.String({ description: 'Short summary to store' })
    }),
    async execute(_toolCallId: any, params: any) {
      if (!MEMORY_DECISION_URL) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'MEMORY_DECISION_URL is not set' }, null, 2) }],
          details: { status: 'error', message: 'MEMORY_DECISION_URL is not set' }
        };
      }

      const namespace = MEMORY_NAMESPACE || (readNamespace() || 'default');
      const kc = new KubeConfig();
      kc.loadFromDefault();
      const core = kc.makeApiClient(CoreApi as any);

      // Load or initialize catalog ConfigMap
      const catalogName = 'memory-catalog';
      let catalog: any = { metadata: { name: catalogName, namespace }, data: {} };
      try {
        const resp: any = await core.readNamespacedConfigMap(catalogName, namespace);
        catalog = (resp && resp.body) ? resp.body : resp;
      } catch (err: any) {
        // Create empty catalog
        try {
          const toCreate = { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: catalogName, namespace }, data: { 'catalog.json': JSON.stringify([]) } };
          const created: any = await core.createNamespacedConfigMap(namespace, toCreate as any);
          catalog = created.body || created;
        } catch (err2: any) {
          // fallthrough to try reading again
          try {
            const resp2: any = await core.readNamespacedConfigMap(catalogName, namespace);
            catalog = (resp2 && resp2.body) ? resp2.body : resp2;
          } catch (e) {
            return {
              content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'failed to initialize catalog', error: String(e?.message || e) }, null, 2) }],
              details: { status: 'error', message: 'failed to initialize catalog', error: String(e?.message || e) }
            };
          }
        }
      }

      // parse categories
      let categories: string[] = [];
      try {
        const raw = catalog?.data?.['catalog.json'] || '[]';
        categories = JSON.parse(raw);
        if (!Array.isArray(categories)) categories = [];
      } catch {
        categories = [];
      }

      // build memory text for decision
      const textParts = [ensureString(params.problem)];
      if (Array.isArray(params.findings) && params.findings.length) textParts.push(params.findings.join('\n'));
      if (params.summary) textParts.push(ensureString(params.summary));
      const decisionPayload = { text: textParts.join('\n\n'), categories };

      let decision: any;
      try {
        decision = await callDecisionEndpoint(decisionPayload);
      } catch (e: any) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'decision endpoint failed', error: String(e?.message || e) }, null, 2) }],
          details: { status: 'error', message: 'decision endpoint failed', error: String(e?.message || e) }
        };
      }

      const category = String(decision?.category || '').trim();
      const bucket = String(decision?.bucket || '').trim();
      if (!category || !bucket) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'decision endpoint returned invalid category or bucket', decision }, null, 2) }],
          details: { status: 'error', message: 'decision endpoint returned invalid category or bucket', decision }
        };
      }

      // add category to catalog if new
      if (!categories.includes(category)) {
        categories.push(category);
        // optimistic update catalog
        const attempts = 5;
        for (let attempt = 1; attempt <= attempts; attempt += 1) {
          try {
            const existingResp: any = await core.readNamespacedConfigMap(catalogName, namespace);
            const existing = (existingResp && existingResp.body) ? existingResp.body : existingResp;
            const newData = { ...(existing.data || {}), 'catalog.json': JSON.stringify(categories) };
            const toReplace = { ...existing, data: newData };
            await core.replaceNamespacedConfigMap(catalogName, namespace, toReplace as any);
            break;
          } catch (err: any) {
            const code = err?.statusCode || err?.status || 0;
            if (attempt < attempts && (code === 409 || /conflict/i.test(String(err?.message || err)))) {
              await new Promise(r => setTimeout(r, attempt * 200));
              continue;
            }
            // last resort: attempt create
            try {
              const toCreate = { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: catalogName, namespace }, data: { 'catalog.json': JSON.stringify(categories) } };
              await core.createNamespacedConfigMap(namespace, toCreate as any);
              break;
            } catch (e) {
              // ignore
            }
            break;
          }
        }
      }

      // prepare memory record
      const record = {
        id: shortId(),
        timestamp: new Date().toISOString(),
        category,
        bucket,
        problem: ensureString(params.problem),
        findings: Array.isArray(params.findings) ? params.findings : [],
        summary: ensureString(params.summary)
      };

      const baseName = memlib.bucketConfigMapName(category, bucket);
      const maxAttempts = 5;

      async function appendToConfigMapName(nameToUse: string) {
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
          try {
            // read existing or create
            let cm: any;
            try {
              const resp: any = await core.readNamespacedConfigMap(nameToUse, namespace);
              cm = (resp && resp.body) ? resp.body : resp;
            } catch (e: any) {
              // create
              const toCreate = {
                apiVersion: 'v1',
                kind: 'ConfigMap',
                metadata: { name: nameToUse, namespace, labels: { 'app.kubernetes.io/part-of': 'agent-memory', 'memory.k8s.io/category': category, 'memory.k8s.io/bucket': bucket } },
                data: { 'memories.json': JSON.stringify([record]) }
              };
              const created: any = await core.createNamespacedConfigMap(namespace, toCreate as any);
              return created.body || created;
            }

            const currentRaw = cm?.data?.['memories.json'] || '[]';
            let arr;
            try { arr = JSON.parse(currentRaw); if (!Array.isArray(arr)) arr = []; } catch { arr = []; }
            arr.push(record);
            const serialized = JSON.stringify(arr);
            // if large, signal to caller
            if (Buffer.byteLength(serialized, 'utf8') > 800 * 1024) {
              return { overflow: true };
            }

            const newCm = { ...cm, data: { ...(cm.data || {}), 'memories.json': serialized } };
            await core.replaceNamespacedConfigMap(nameToUse, namespace, newCm as any);
            return newCm;
          } catch (err: any) {
            const code = err?.statusCode || err?.status || 0;
            if (attempt < maxAttempts && (code === 409 || /conflict/i.test(String(err?.message || err)))) {
              await new Promise(r => setTimeout(r, attempt * 200));
              continue;
            }
            throw err;
          }
        }
        throw new Error('failed to append to configmap after retries');
      }

      // try append to base name, if overflow create/use -v2
      try {
        const res = await appendToConfigMapName(baseName);
        if (res && (res as any).overflow) {
          const v2 = `${baseName}-v2`;
          const res2 = await appendToConfigMapName(v2);
          return {
            content: [{ type: 'text', text: JSON.stringify({ status: 'ok', id: record.id, storedIn: v2, category, bucket }, null, 2) }],
            details: { status: 'ok', id: record.id, storedIn: v2, category, bucket }
          };
        }

        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'ok', id: record.id, storedIn: baseName, category, bucket }, null, 2) }],
          details: { status: 'ok', id: record.id, storedIn: baseName, category, bucket }
        };
      } catch (e: any) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'failed to persist memory', error: String(e?.message || e) }, null, 2) }],
          details: { status: 'error', message: 'failed to persist memory', error: String(e?.message || e) }
        };
      }
    }
  });

  pi.registerTool({
    name: 'query_memory',
    label: 'query_memory',
    description: 'Query memory records by delegating to the decision endpoint for category/bucket selection and merging found records.',
    parameters: Type.Object({
      query: Type.String({ description: 'Search query' })
    }),
    async execute(_toolCallId: any, params: any) {
      if (!MEMORY_DECISION_URL) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'MEMORY_DECISION_URL is not set' }, null, 2) }],
          details: { status: 'error', message: 'MEMORY_DECISION_URL is not set' }
        };
      }

      const namespace = MEMORY_NAMESPACE || (readNamespace() || 'default');
      const kc = new KubeConfig();
      kc.loadFromDefault();
      const core = kc.makeApiClient(CoreApi as any);

      // Load catalog
      const catalogName = 'memory-catalog';
      let categories: string[] = [];
      try {
        const resp: any = await core.readNamespacedConfigMap(catalogName, namespace);
        const cm = (resp && resp.body) ? resp.body : resp;
        const raw = cm?.data?.['catalog.json'] || '[]';
        categories = JSON.parse(raw);
        if (!Array.isArray(categories)) categories = [];
      } catch {
        categories = [];
      }

      // call decision endpoint with query + catalog
      let decision: any;
      try {
        decision = await callDecisionEndpoint({ text: ensureString(params.query), categories });
      } catch (e: any) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'decision endpoint failed', error: String(e?.message || e) }, null, 2) }],
          details: { status: 'error', message: 'decision endpoint failed', error: String(e?.message || e) }
        };
      }

      const category = String(decision?.category || '').trim();
      let buckets = decision?.buckets;
      if (!category) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'decision endpoint returned no category', decision }, null, 2) }],
          details: { status: 'error', message: 'decision endpoint returned no category', decision }
        };
      }

      if (!buckets) {
        buckets = memlib.BUCKETS;
      } else if (typeof buckets === 'string') {
        buckets = [buckets];
      } else if (!Array.isArray(buckets)) {
        buckets = memlib.BUCKETS;
      }

      // build labelSelector: app.kubernetes.io/part-of=agent-memory,memory.k8s.io/category=<category>,memory.k8s.io/bucket in (a,b)
      const encodedBuckets = buckets.map(String).map(b => b.trim()).filter(Boolean);
      const bucketSelector = encodedBuckets.length ? `memory.k8s.io/bucket in (${encodedBuckets.join(',')})` : '';
      const labelParts = [`app.kubernetes.io/part-of=agent-memory`, `memory.k8s.io/category=${category}`];
      if (bucketSelector) labelParts.push(bucketSelector);
      const labelSelector = labelParts.join(',');

      try {
        const resp: any = await core.listNamespacedConfigMap(namespace, undefined, undefined, undefined, undefined, labelSelector);
        const items = (resp && resp.body && Array.isArray(resp.body.items)) ? resp.body.items : (Array.isArray((resp as any).items) ? (resp as any).items : []);
        const allRecords: any[] = [];
        for (const it of items) {
          try {
            const raw = it?.data?.['memories.json'] || '[]';
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) allRecords.push(parsed);
          } catch {
            // skip
          }
        }

        // merge using helper
        const merged = memlib.mergeMemories(...allRecords);
        return {
          content: [{ type: 'text', text: JSON.stringify(merged, null, 2) }],
          details: { status: 'ok', count: merged.length, memories: merged }
        };
      } catch (e: any) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'failed to list or parse configmaps', error: String(e?.message || e) }, null, 2) }],
          details: { status: 'error', message: 'failed to list or parse configmaps', error: String(e?.message || e) }
        };
      }
    }
  });
}
