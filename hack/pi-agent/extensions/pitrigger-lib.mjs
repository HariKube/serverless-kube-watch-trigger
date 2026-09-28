import { randomUUID } from 'node:crypto';

const NAME_RE = /^[a-z0-9.-]+$/;
const EVENT_TYPES = ['ADDED', 'MODIFIED', 'DELETED'];
const TRACE_LABEL = 'harikube.info/trace-id';

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function ensureObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function ensureString(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value.trim();
}

function ensureInteger(value, label, { min, max } = {}) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${label} must be an integer`);
  }
  if (min !== undefined && parsed < min) {
    throw new Error(`${label} must be >= ${min}`);
  }
  if (max !== undefined && parsed > max) {
    throw new Error(`${label} must be <= ${max}`);
  }
  return parsed;
}

function ensureName(value, label) {
  const trimmed = ensureString(value, label);
  if (!NAME_RE.test(trimmed)) {
    throw new Error(`${label} may contain only lowercase letters, digits, '-' and '.'`);
  }
  return trimmed;
}

function normalizeStringMap(value, label) {
  if (value === undefined || value === null) {
    return undefined;
  }
  const raw = ensureObject(value, label);
  const out = {};
  for (const [key, candidate] of Object.entries(raw)) {
    out[ensureString(key, `${label} key`)] = ensureString(candidate, `${label}.${key}`);
  }
  return out;
}

function normalizeOwnerReferences(value, label) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value.map((candidate, index) => {
    const raw = ensureObject(candidate, `${label}[${index}]`);
    return {
      apiVersion: ensureString(raw.apiVersion, `${label}[${index}].apiVersion`),
      kind: ensureString(raw.kind, `${label}[${index}].kind`),
      name: ensureName(raw.name, `${label}[${index}].name`),
      uid: ensureString(raw.uid, `${label}[${index}].uid`)
    };
  });
}

function normalizeStringArray(value, label, { allowEmpty = true } = {}) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  const out = value.map((candidate, index) => ensureString(candidate, `${label}[${index}]`));
  if (!allowEmpty && out.length === 0) {
    throw new Error(`${label} must not be empty`);
  }
  return out;
}

function normalizeEventTypes(value, label = 'eventTypes') {
  const types = normalizeStringArray(value, label, { allowEmpty: false }) ?? EVENT_TYPES;
  return types.map((candidate, index) => {
    if (!EVENT_TYPES.includes(candidate)) {
      throw new Error(`${label}[${index}] must be one of: ${EVENT_TYPES.join(', ')}`);
    }
    return candidate;
  });
}

function trimKubeName(value, maxLength = 63) {
  const lowered = value.toLowerCase().replace(/[^a-z0-9-.]+/g, '-');
  const collapsed = lowered.replace(/-+/g, '-').replace(/^-+|-+$/g, '');
  return collapsed.slice(0, maxLength).replace(/-+$/g, '') || 'pi';
}

export const PI_TRIGGER_JOB_NAME_LABEL = 'triggers.harikube.info/pitrigger-name';

function buildTerminalJobConditionFilter(index) {
  return [
    `(and (gt (len .status.conditions) ${index})`,
    `(eq (index (index .status.conditions ${index}) "status") "True")`,
    '(or',
    `(eq (index (index .status.conditions ${index}) "type") "Complete")`,
    `(eq (index (index .status.conditions ${index}) "type") "Failed")))`
  ].join(' ');
}

export const TERMINAL_JOB_EVENT_FILTER = [
  'or',
  '.status.completionTime',
  '(and .status.conditions',
  '(or',
  buildTerminalJobConditionFilter(0),
  buildTerminalJobConditionFilter(1),
  buildTerminalJobConditionFilter(2),
  buildTerminalJobConditionFilter(3),
  '))'
].join(' ');

export function createWorkerTriggerName(sessionId, round, index) {
  return trimKubeName(`pi-session-${randomUUID().replace(/-/g, '').slice(0, 8)}-${sessionId}-r${round}-w${index}-trigger`);
}

export function buildPiTriggerManifest({
  name,
  namespace,
  labels,
  annotations,
  ownerReferences,
  resource,
  namespaces,
  labelSelectors,
  fieldSelectors,
  eventTypes,
  eventFilter,
  sendInitialEvents,
  maxJobs,
  timeout,
  agent
}) {
  const normalizedName = ensureName(name, 'name');
  const normalizedNamespace = ensureName(namespace, 'namespace');
  const normalizedResource = ensureObject(resource, 'resource');
  const normalizedAgent = clone(ensureObject(agent, 'agent'));
  const normalizedLabels = normalizeStringMap(labels, 'labels');
  const normalizedAnnotations = normalizeStringMap(annotations, 'annotations');
  const normalizedOwnerReferences = normalizeOwnerReferences(ownerReferences, 'ownerReferences');

  const spec = {
    resource: {
      apiVersion: ensureString(normalizedResource.apiVersion, 'resource.apiVersion'),
      kind: ensureString(normalizedResource.kind, 'resource.kind')
    },
    namespaces: normalizeStringArray(namespaces, 'namespaces') ?? [normalizedNamespace],
    eventTypes: normalizeEventTypes(eventTypes)
  };

  const normalizedLabelSelectors = normalizeStringArray(labelSelectors, 'labelSelectors');
  if (normalizedLabelSelectors?.length) {
    spec.labelSelectors = normalizedLabelSelectors;
  }

  const normalizedFieldSelectors = normalizeStringArray(fieldSelectors, 'fieldSelectors');
  if (normalizedFieldSelectors?.length) {
    spec.fieldSelectors = normalizedFieldSelectors;
  }

  if (typeof eventFilter === 'string' && eventFilter.trim()) {
    spec.eventFilter = eventFilter.trim();
  }
  if (sendInitialEvents !== undefined) {
    spec.sendInitialEvents = Boolean(sendInitialEvents);
  }
  if (maxJobs !== undefined) {
    spec.maxJobs = ensureInteger(maxJobs, 'maxJobs', { min: 1 });
  }
  if (timeout !== undefined && timeout !== null && String(timeout).trim()) {
    spec.timeout = ensureString(timeout, 'timeout');
  }

  spec.agent = normalizedAgent;

  const metadata = {
    name: normalizedName,
    namespace: normalizedNamespace
  };
  if (normalizedOwnerReferences?.length) {
    metadata.ownerReferences = normalizedOwnerReferences;
  }
  if (normalizedLabels && Object.keys(normalizedLabels).length > 0) {
    metadata.labels = normalizedLabels;
  }
  if (normalizedAnnotations && Object.keys(normalizedAnnotations).length > 0) {
    metadata.annotations = normalizedAnnotations;
  }

  return {
    apiVersion: 'triggers.harikube.info/v1',
    kind: 'PiTrigger',
    metadata,
    spec
  };
}

export function buildWorkerPiTriggerManifest({ triggerName, namespace, ownerReferences, sessionId, round, worker, traceId, timeout, agent }) {
  const rawWorker = ensureObject(worker, 'worker');
  const index = ensureInteger(rawWorker.index, 'worker.index', { min: 1 });
  const outputLocation = typeof rawWorker.outputLocation === 'string' ? rawWorker.outputLocation.trim() : '';

  return buildPiTriggerManifest({
    name: triggerName,
    namespace,
    ownerReferences,
    labels: {
      'harikube.info/session': ensureString(sessionId, 'sessionId'),
      'harikube.info/round': String(ensureInteger(round, 'round', { min: 1 })),
      'harikube.info/worker': String(index),
      ...(traceId ? { [TRACE_LABEL]: ensureName(traceId, 'traceId') } : {})
    },
    annotations: {
      'harikube.info/session-secret': ensureName(ownerReferences?.[0]?.name || '', 'ownerReferences[0].name'),
      'harikube.info/output-location': outputLocation
    },
    resource: {
      apiVersion: 'batch/v1',
      kind: 'Job'
    },
    namespaces: [namespace],
    labelSelectors: [`${PI_TRIGGER_JOB_NAME_LABEL}=${ensureName(triggerName, 'triggerName')}`],
    eventTypes: ['ADDED', 'MODIFIED'],
    eventFilter: TERMINAL_JOB_EVENT_FILTER,
    sendInitialEvents: true,
    maxJobs: 1,
    timeout,
    agent
  });
}

export function buildApplyPayload(items) {
  const normalized = Array.isArray(items) ? items.filter(Boolean) : [];
  if (normalized.length === 0) {
    return '';
  }
  if (normalized.length === 1) {
    return JSON.stringify(normalized[0], null, 2);
  }
  return JSON.stringify({ apiVersion: 'v1', kind: 'List', items: normalized }, null, 2);
}

export async function applyPiTriggerManifests(items, namespace, kubectl) {
  const payload = buildApplyPayload(items);
  if (!payload) {
    return undefined;
  }
  return await kubectl({
    command: 'apply -f -',
    namespace,
    input: payload
  });
}
