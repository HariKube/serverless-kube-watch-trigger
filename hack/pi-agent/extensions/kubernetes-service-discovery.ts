import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promises as fsp } from 'node:fs';
import { ApisApi, CoreApi, KubeConfig, ApiregistrationV1Api, ApiextensionsV1Api } from '@kubernetes/client-node';
import { Type } from 'typebox';

const RUNTIME_SKILL_NAME = 'kubernetes-service-discovery-runtime';
const DEFAULT_NAMESPACE_PATH = process.env.NS_PATH || '/var/run/secrets/kubernetes.io/serviceaccount/namespace';
const SERVICE_EXPOSURE_KINDS = new Set([
  'Service',
  'Ingress',
  'Gateway',
  'GatewayClass',
  'HTTPRoute',
  'GRPCRoute',
  'TCPRoute',
  'UDPRoute',
  'TLSRoute',
  'Route',
  'APIService',
  'ServiceExport',
  'ServiceImport',
  'VirtualService',
  'ServiceEntry',
  'DestinationRule',
  'DomainMapping',
  'ServerlessService'
]);

function unwrapBody<T>(response: T | { body?: T } | undefined): T | undefined {
  if (response && typeof response === 'object' && 'body' in response && response.body !== undefined) {
    return response.body;
  }
  return response as T | undefined;
}

function classifyResource(resource: any, groupVersion: string) {
  const categories = new Set<string>();
  const kind = String(resource?.kind || '');
  const name = String(resource?.name || '');
  const lower = `${groupVersion} ${kind} ${name}`.toLowerCase();

  if (groupVersion === 'v1' && (kind === 'Service' || name === 'services')) {
    categories.add('core-service');
  }
  if (kind === 'Endpoints' || kind === 'EndpointSlice' || /endpoint/.test(lower)) {
    categories.add('service-discovery-data');
  }
  if (['Ingress', 'Gateway', 'GatewayClass', 'HTTPRoute', 'GRPCRoute', 'TCPRoute', 'UDPRoute', 'TLSRoute', 'Route'].includes(kind)) {
    categories.add('traffic-entrypoint');
  }
  if (/serving\.knative\.dev/.test(lower) || ['DomainMapping', 'ServerlessService'].includes(kind)) {
    categories.add('serverless-serving');
  }
  if (/istio\.io/.test(lower) || ['VirtualService', 'ServiceEntry', 'DestinationRule'].includes(kind)) {
    categories.add('service-mesh');
  }
  if (kind === 'APIService' || kind === 'ServiceExport' || kind === 'ServiceImport') {
    categories.add('cluster-service-integration');
  }

  // NOTE: Avoid a broad substring match on "service" here because it produces noisy
  // false positives (e.g. ServiceAccount, servicemonitor). Only well-known kinds
  // and explicit categories above are considered service-related by default.
  return Array.from(categories);
}

function isServiceLikeResource(resource: any, groupVersion: string) {
  const categories = classifyResource(resource, groupVersion);
  const kind = String(resource?.kind || '');
  const name = String(resource?.name || '');

  // If any explicit category matched, consider it service-like.
  if (categories.length > 0) {
    return true;
  }

  // Well-known exposure kinds are always included.
  if (SERVICE_EXPOSURE_KINDS.has(kind)) {
    return true;
  }

  // Conservative fallback checks: match whole-word "service"/"services" tokens only
  // (so "serviceaccount" or other compound names are excluded), or explicit
  // singular/shortName hints (e.g. singularName === 'service' or shortNames === 'svc').
  const lowerCombined = `${kind} ${name} ${groupVersion}`.toLowerCase();
  if (/\b(service|services)\b/.test(lowerCombined)) {
    return true;
  }

  const singular = String(resource?.singularName || '').toLowerCase();
  if (singular === 'service') {
    return true;
  }

  const shortNames = Array.isArray(resource?.shortNames) ? resource.shortNames.map((s: any) => String(s).toLowerCase()) : [];
  if (shortNames.includes('svc') || shortNames.includes('service') || shortNames.includes('services')) {
    return true;
  }

  return false;
}

async function readNamespace() {
  try {
    return (await fsp.readFile(DEFAULT_NAMESPACE_PATH, 'utf8')).trim();
  } catch {
    return null;
  }
}

async function discoverServiceApis() {
  const kc = new KubeConfig();
  kc.loadFromDefault();

  const namespace = await readNamespace();
  const coreApi = kc.makeApiClient(CoreApi);
  const apisApi = kc.makeApiClient(ApisApi);

  const fetchedAt = new Date().toISOString();
  const coreVersions = unwrapBody<any>(await coreApi.getAPIVersions()) || {};
  const groupList = unwrapBody<any>(await apisApi.getAPIVersions()) || {};

  const preferredGroupVersions = [
    {
      group: '',
      version: 'v1',
      groupVersion: 'v1',
      path: '/api/v1'
    },
    ...((groupList.groups || [])
      .map((group: any) => ({
        group: String(group?.name || ''),
        version: String(group?.preferredVersion?.version || ''),
        groupVersion: String(group?.preferredVersion?.groupVersion || ''),
        path: `/apis/${String(group?.preferredVersion?.groupVersion || '')}`
      }))
      .filter((entry: any) => entry.groupVersion))
  ];

  const resources = [] as any[];
  const failures = [] as any[];

  for (const groupVersion of preferredGroupVersions) {
    try {
      // Use the native Kubernetes client discovery methods rather than raw HTTP requests.
      // For the core API group ("v1") use the CoreApi; for other groups use ApisApi and query the specific groupVersion path.
      let resourceList: any = null;
      if (!groupVersion.group) {
        // Core API resources: /api/v1
        // CoreApi should expose a getAPIResources method for discovery.
        const resp = await coreApi.getAPIResources();
        resourceList = unwrapBody<any>(resp) || {};
      } else {
        // Named API groups: /apis/{group}/{version}
        // ApisApi should expose a method to get resources for a specific groupVersion.
        // Use the preferred groupVersion string (e.g. "networking.k8s.io/v1").
        const resp = await apisApi.getAPIResources(groupVersion.group, groupVersion.version);
        resourceList = unwrapBody<any>(resp) || {};
      }

      const apiResources = Array.isArray(resourceList?.resources) ? resourceList.resources : [];
      for (const resource of apiResources) {
        if (!resource || typeof resource !== 'object') {
          continue;
        }
        if (String(resource.name || '').includes('/')) {
          continue;
        }
        if (!isServiceLikeResource(resource, groupVersion.groupVersion)) {
          continue;
        }
        resources.push({
          group: groupVersion.group,
          version: groupVersion.version,
          groupVersion: groupVersion.groupVersion,
          resource: resource.name,
          kind: resource.kind,
          singularName: resource.singularName || '',
          shortNames: Array.isArray(resource.shortNames) ? resource.shortNames : [],
          namespaced: Boolean(resource.namespaced),
          verbs: Array.isArray(resource.verbs) ? resource.verbs : [],
          categories: classifyResource(resource, groupVersion.groupVersion)
        });
      }
    } catch (error: any) {
      failures.push({
        groupVersion: groupVersion.groupVersion,
        path: groupVersion.path,
        message: error?.message || String(error)
      });
    }
  }

  resources.sort((left, right) => {
    const byKind = String(left.kind || '').localeCompare(String(right.kind || ''));
    if (byKind !== 0) return byKind;
    return String(left.groupVersion || '').localeCompare(String(right.groupVersion || ''));
  });

  const categoryCounts = resources.reduce((acc: Record<string, number>, resource) => {
    for (const category of resource.categories || []) {
      acc[category] = (acc[category] || 0) + 1;
    }
    return acc;
  }, {});

  return {
    status: 'ok',
    fetchedAt,
    namespace,
    coreVersions,
    apiGroupCount: Array.isArray(groupList.groups) ? groupList.groups.length : 0,
    preferredGroupVersionCount: preferredGroupVersions.length,
    matchedResourceCount: resources.length,
    categoryCounts,
    resources,
    failures
  };
}

function renderCategorySummary(snapshot: any) {
  const entries = Object.entries(snapshot.categoryCounts || {}).sort((left, right) => left[0].localeCompare(right[0]));
  if (entries.length === 0) {
    return '- No service-related API resources were discovered in the preferred API versions that were queried.';
  }
  return entries.map(([name, count]) => `- ${name}: ${count}`).join('\n');
}

function renderResourceList(snapshot: any) {
  if (!Array.isArray(snapshot.resources) || snapshot.resources.length === 0) {
    return 'No matching service-related resources were discovered.';
  }

  return snapshot.resources
    .map((resource: any) => {
      const shortNames = resource.shortNames?.length ? ` shortNames=${resource.shortNames.join(',')}` : '';
      const categories = resource.categories?.length ? ` categories=${resource.categories.join(',')}` : '';
      const verbs = resource.verbs?.length ? ` verbs=${resource.verbs.join(',')}` : '';
      return `- ${resource.kind} (${resource.groupVersion}) → resource=${resource.resource} namespaced=${resource.namespaced}${shortNames}${categories}${verbs}`;
    })
    .join('\n');
}

function renderFailures(snapshot: any) {
  if (!Array.isArray(snapshot.failures) || snapshot.failures.length === 0) {
    return '- None';
  }
  return snapshot.failures
    .map((failure: any) => `- ${failure.groupVersion} via ${failure.path}: ${failure.message}`)
    .join('\n');
}

function renderDiscoverySkill(snapshot: any) {
  if (snapshot.status !== 'ok') {
    return `---
name: ${RUNTIME_SKILL_NAME}
description: Reports the per-execution Kubernetes service discovery snapshot for the current worker.
---

# Kubernetes service discovery runtime snapshot

The extension attempted to query Kubernetes discovery once at startup, but it failed.

## Failure

\`\`\`json
${JSON.stringify(snapshot, null, 2)}
\`\`\`

## Rules

- Do not assume any service-related API exists when this discovery step fails.
- Fall back to explicit bounded reads such as \`exec_kubectl\` if you must confirm availability.
`;
  }

  return `---
name: ${RUNTIME_SKILL_NAME}
description: Service-related Kubernetes API resources discovered once at worker startup for the current cluster.
---

# Kubernetes service discovery runtime snapshot

This extension queried Kubernetes discovery exactly once during this worker execution using the in-cluster Kubernetes client configuration.
Treat the snapshot below as the source of truth for which service-related API kinds are available in this cluster right now.

## Snapshot metadata

- fetchedAt: ${snapshot.fetchedAt}
- namespace: ${snapshot.namespace || '(unknown)'}
- core versions: ${(snapshot.coreVersions?.versions || []).join(', ') || '(none reported)'}
- preferred API groups queried: ${snapshot.preferredGroupVersionCount}
- matched service-related resources: ${snapshot.matchedResourceCount}
- failed discovery requests: ${snapshot.failures?.length || 0}

## Category summary

${renderCategorySummary(snapshot)}

## Discovered service-related resources

${renderResourceList(snapshot)}

## Discovery failures

${renderFailures(snapshot)}

## Rules

- Use the exact \`kind\`, \`groupVersion\`, and \`resource\` values listed here when forming Kubernetes reads or writes.
- If a service-related kind is missing from this snapshot, do not assume the CRD or API exists.
- Prefer confirming individual objects with structured reads such as \`exec_kubectl\` + \`-o json\` before making changes.
- This snapshot is per-execution and is not refreshed automatically later in the same worker run.

## Raw snapshot

\`\`\`json
${JSON.stringify(
  {
    fetchedAt: snapshot.fetchedAt,
    namespace: snapshot.namespace,
    apiGroupCount: snapshot.apiGroupCount,
    preferredGroupVersionCount: snapshot.preferredGroupVersionCount,
    matchedResourceCount: snapshot.matchedResourceCount,
    categoryCounts: snapshot.categoryCounts,
    resources: snapshot.resources,
    failures: snapshot.failures
  },
  null,
  2
)}
\`\`\`
`;
}

function writeSkill(rootDir: string, skillName: string, content: string) {
  const skillDir = path.join(rootDir, skillName);
  fs.mkdirSync(skillDir, { recursive: true });
  fs.writeFileSync(path.join(skillDir, 'SKILL.md'), content, 'utf8');
  return skillDir;
}

function unifyCandidatesFromSources(...sources: any[]) {
  const all: any[] = [];
  for (const src of sources) {
    for (const r of src || []) {
      all.push({
        kind: r.kind,
        groupVersion: r.groupVersion || r.group || '',
        name: r.name,
        source: r.source || 'discovery'
      });
    }
  }
  const seen = new Set<string>();
  const deduped: any[] = [];
  for (const c of all) {
    const key = `${c.kind}|${c.groupVersion}|${c.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(c);
  }
  return deduped;
}

function scoreCandidate(query: string, c: any) {
  const q = String(query || '').toLowerCase();
  const kind = String(c.kind || '').toLowerCase();
  const name = String(c.name || '').toLowerCase();
  const gv = String(c.groupVersion || '').toLowerCase();

  if (!q) return 0;
  let score = 0;
  if (name === q) score += 1000;
  if (kind === q) score += 500;
  if (name.startsWith(q) || kind.startsWith(q) || gv.startsWith(q)) score += 100;
  if (name.includes(q) || kind.includes(q) || gv.includes(q)) score += 10;
  if (c.kind === 'Service') score += 5;
  return score;
}

function unifiedLookup(query: string, { apiServices = [], crdResources = [], discovered = [] }: any = {}) {
  const combined = unifyCandidatesFromSources(apiServices, crdResources, discovered);
  const scored = combined.map((c: any) => ({ candidate: c, score: scoreCandidate(query, c) }));

  scored.sort((a: any, b: any) => {
    if (a.score !== b.score) return b.score - a.score;
    const ka = String(a.candidate.kind || '');
    const kb = String(b.candidate.kind || '');
    const kcmp = ka.localeCompare(kb);
    if (kcmp !== 0) return kcmp;
    const gcmp = String(a.candidate.groupVersion || '').localeCompare(String(b.candidate.groupVersion || ''));
    if (gcmp !== 0) return gcmp;
    const ncmp = String(a.candidate.name || '').localeCompare(String(b.candidate.name || ''));
    if (ncmp !== 0) return ncmp;
    return String(a.candidate.source || '').localeCompare(String(b.candidate.source || ''));
  });

  return scored.slice(0, 20).map((s: any) => s.candidate);
}

async function tryList(api: any, methodNames: string[]) {
  for (const name of methodNames) {
    const fn = (api as any)[name];
    if (typeof fn === 'function') {
      try {
        const resp = await fn.call(api);
        const body = unwrapBody<any>(resp) || resp;
        const items = Array.isArray(body?.items) ? body.items : Array.isArray(body) ? body : [];
        return items;
      } catch (e) {
        // try next
      }
    }
  }
  return [];
}

export default function registerKubernetesServiceDiscovery(pi: any) {
  const skillRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pi-kube-service-discovery-'));
  let snapshotPromise = discoverServiceApis().catch((error: any) => ({
    status: 'error',
    fetchedAt: new Date().toISOString(),
    message: error?.message || String(error)
  }));

  let skillPathPromise: Promise<string> | null = null;

  pi.on('resources_discover', async () => {
    if (!skillPathPromise) {
      skillPathPromise = (async () => {
        const snapshot = await snapshotPromise;
        return writeSkill(skillRoot, RUNTIME_SKILL_NAME, renderDiscoverySkill(snapshot));
      })();
    }

    return {
      skillPaths: [await skillPathPromise]
    };
  });

  // Register a user-facing native lookup tool that merges service-like discovered API resources,
  // APIService objects from apiregistration, and CRD-backed resources from apiextensions.
  pi.registerTool({
    name: 'kubernetes_service_lookup',
    label: 'kubernetes_service_lookup',
    description: 'Lookup cluster service-like APIs, APIService entries, and CRD-backed resources by a query string (merged, ranked, deterministic, max 20).',
    parameters: Type.Object({
      query: Type.String({ description: 'Search query' }),
      limit: Type.Optional(Type.Number()),
      refresh: Type.Optional(Type.Boolean()),
      includeDetails: Type.Optional(Type.Boolean({ description: 'When true, attach source-specific native details to each candidate (apiService, crd, discovery).' }))
    }),
    async execute(_toolCallId: any, params: any) {
      const query = String(params?.query || '').trim();
      const limit = Math.min(Number(params?.limit || 20) || 20, 20);
      const refresh = Boolean(params?.refresh);
      const includeDetails = Boolean(params?.includeDetails || params?.details);

      if (refresh) {
        snapshotPromise = discoverServiceApis().catch((error: any) => ({ status: 'error', fetchedAt: new Date().toISOString(), message: error?.message || String(error) }));
      }

      const snapshot: any = await snapshotPromise;

      // build discovered candidates from snapshot.resources
      const discovered = (Array.isArray(snapshot?.resources) ? snapshot.resources : []).map((r: any) => ({
        kind: r.kind,
        groupVersion: r.groupVersion,
        name: r.resource,
        source: 'discovery'
      }));

      // use native kube client to list APIService and CRD objects
      const kc = new KubeConfig();
      kc.loadFromDefault();
      const apiReg = kc.makeApiClient(ApiregistrationV1Api as any);
      const apiExt = kc.makeApiClient(ApiextensionsV1Api as any);

      let apiServices: any[] = [];
      let crdResources: any[] = [];
      let rawApiServiceItems: any[] = [];
      let rawCrdItems: any[] = [];

      try {
        const items = await tryList(apiReg, ['listAPIService', 'listAPIServiceAsPromise', 'listAPIServices', 'listAPIServiceList']);
        rawApiServiceItems = items || [];
        apiServices = rawApiServiceItems.map((it: any) => ({
          kind: it?.kind || 'APIService',
          groupVersion: it?.apiVersion || 'apiregistration.k8s.io/v1',
          name: it?.metadata?.name || it?.name || '',
          source: 'apiService'
        }));
      } catch (e) {
        apiServices = [];
        rawApiServiceItems = [];
      }

      try {
        const items = await tryList(apiExt, ['listCustomResourceDefinition', 'listCustomResourceDefinitions', 'listCustomResourceDefinitionAsPromise']);
        rawCrdItems = items || [];
        crdResources = (rawCrdItems)
          .map((c: any) => {
            const versions = Array.isArray(c?.spec?.versions) ? c.spec.versions : [];
            const v = versions.find((vv: any) => vv?.served) || versions[0] || { name: '' };
            const gv = c?.spec && v?.name ? `${c.spec.group}/${v.name}` : c?.apiVersion || '';
            return {
              kind: c?.spec?.names?.kind || 'CustomResource',
              groupVersion: gv,
              name: c?.spec?.names?.plural || c?.metadata?.name || '',
              source: 'crd'
            };
          })
          .filter((x: any) => x.name);
      } catch (e) {
        crdResources = [];
        rawCrdItems = [];
      }

      const results = unifiedLookup(query, { apiServices, crdResources, discovered }).slice(0, limit);

      if (includeDetails) {
        const snapshotResources = Array.isArray(snapshot?.resources) ? snapshot.resources : [];
        const enriched = results.map((c: any) => {
          const base = { kind: c.kind, groupVersion: c.groupVersion, name: c.name, source: c.source };
          try {
            if (c.source === 'apiService') {
              const match = rawApiServiceItems.find((it: any) => String(it?.metadata?.name || it?.name || '') === String(c.name));
              const backing = match?.spec?.service ? { name: match.spec.service.name, namespace: match.spec.service.namespace } : undefined;
              const conditions = Array.isArray(match?.status?.conditions) ? match.status.conditions : [];
              const available = conditions.some((cond: any) => String(cond.type || '').toLowerCase() === 'available' && String(cond.status || '').toLowerCase() === 'true');
              return { ...base, nativeDetails: { apiService: { backingService: backing, available, conditions } } };
            }
            if (c.source === 'crd') {
              const match = rawCrdItems.find((it: any) => {
                const plural = it?.spec?.names?.plural || it?.metadata?.name || '';
                return String(plural) === String(c.name) || String(it?.metadata?.name) === String(c.name);
              });
              const group = match?.spec?.group || undefined;
              const versions = Array.isArray(match?.spec?.versions) ? match.spec.versions.map((v: any) => ({ name: v.name, served: v.served, storage: v.storage })) : [];
              const names = match?.spec?.names || undefined;
              const scope = match?.spec?.scope || undefined;
              return { ...base, nativeDetails: { crd: { group, versions, names, scope } } };
            }
            // discovery
            const match = snapshotResources.find((r: any) => String(r?.resource) === String(c.name) && String(r?.groupVersion) === String(c.groupVersion));
            if (match) {
              const { resource, verbs, namespaced, categories, shortNames, singularName } = match;
              return { ...base, nativeDetails: { discovery: { resource, verbs, namespaced, categories, shortNames, singularName } } };
            }
          } catch (e) {
            // swallow enrichment errors and return base
          }
          return base;
        });

        return {
          content: [{ type: 'text', text: JSON.stringify(enriched, null, 2) }],
          details: { status: 'ok', count: enriched.length, results: enriched }
        };
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(results, null, 2) }],
        details: { status: 'ok', count: results.length, results }
      };
    }
  });

  pi.on('session_shutdown', async () => {
    fs.rmSync(skillRoot, { recursive: true, force: true });
  });
}
