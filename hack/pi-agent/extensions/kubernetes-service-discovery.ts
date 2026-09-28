import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { promises as fsp } from 'node:fs';
import { ApisApi, CoreApi, KubeConfig } from '@kubernetes/client-node';

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

async function requestJson(kc: KubeConfig, pathname: string) {
  const cluster = kc.getCurrentCluster();
  if (!cluster?.server) {
    throw new Error('No active Kubernetes cluster is configured');
  }

  const url = new URL(pathname, cluster.server.endsWith('/') ? cluster.server : `${cluster.server}/`);
  const isHttps = url.protocol === 'https:';
  const options: https.RequestOptions = {
    method: 'GET',
    headers: {
      Accept: 'application/json'
    }
  };

  if (isHttps) {
    await kc.applyToHTTPSOptions(options);
  }

  const client = isHttps ? https : http;

  return await new Promise<any>((resolve, reject) => {
    const req = client.request(url, options, res => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', chunk => {
        raw += chunk;
      });
      res.on('end', () => {
        const statusCode = res.statusCode || 0;
        if (statusCode < 200 || statusCode >= 300) {
          reject(new Error(`GET ${pathname} failed with status ${statusCode}: ${raw.slice(0, 400)}`));
          return;
        }
        try {
          resolve(JSON.parse(raw));
        } catch (error: any) {
          reject(new Error(`GET ${pathname} returned invalid JSON: ${error.message}`));
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
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
      const resourceList = await requestJson(kc, groupVersion.path);
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

export default function registerKubernetesServiceDiscovery(pi: any) {
  const skillRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pi-kube-service-discovery-'));
  const snapshotPromise = discoverServiceApis().catch((error: any) => ({
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

  pi.on('session_shutdown', async () => {
    fs.rmSync(skillRoot, { recursive: true, force: true });
  });
}
