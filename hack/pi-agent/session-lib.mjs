import { randomUUID } from 'node:crypto';

const NAME_RE = /^[a-z0-9.-]+$/;
const LABEL_KEY_RE = /^[a-z0-9./-]+$/;
const ID_RE = /^[a-z0-9-]+$/;
const TRACE_LABEL = 'harikube.info/trace-id';
const REQUIRED_AGENT_PATHS = [
  ['image', ['image']],
  ['configSecretRef.name', ['configSecretRef', 'name']],
  ['promptsConfigMapRef.name', ['promptsConfigMapRef', 'name']],
  ['skillsConfigMapRef.name', ['skillsConfigMapRef', 'name']]
];

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function getPath(object, path) {
  return path.reduce((current, key) => current?.[key], object);
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

function ensureNumber(value, label, { min, max } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${label} must be a finite number`);
  }
  if (min !== undefined && parsed < min) {
    throw new Error(`${label} must be >= ${min}`);
  }
  if (max !== undefined && parsed > max) {
    throw new Error(`${label} must be <= ${max}`);
  }
  return parsed;
}

function parseDurationMinutes(value, label) {
  const source = ensureString(value, label);
  const matcher = /([0-9]+(?:\.[0-9]+)?)(ns|us|µs|μs|ms|s|m|h)/g;
  let totalMinutes = 0;
  let consumed = '';
  let match;
  while ((match = matcher.exec(source)) !== null) {
    const amount = Number(match[1]);
    const unit = match[2];
    consumed += match[0];
    switch (unit) {
      case 'ns':
        totalMinutes += amount / 1e9 / 60;
        break;
      case 'us':
      case 'µs':
      case 'μs':
        totalMinutes += amount / 1e6 / 60;
        break;
      case 'ms':
        totalMinutes += amount / 1000 / 60;
        break;
      case 's':
        totalMinutes += amount / 60;
        break;
      case 'm':
        totalMinutes += amount;
        break;
      case 'h':
        totalMinutes += amount * 60;
        break;
      default:
        throw new Error(`${label} contains unsupported duration unit ${unit}`);
    }
  }
  if (!consumed || consumed !== source) {
    throw new Error(`${label} must be a valid Go-style duration like 10m, 90s, or 1h30m`);
  }
  return totalMinutes;
}

function ensureOneOf(value, label, allowed) {
  const normalized = ensureString(value, label);
  if (!allowed.includes(normalized)) {
    throw new Error(`${label} must be one of: ${allowed.join(', ')}`);
  }
  return normalized;
}

function ensureName(value, label) {
  const trimmed = ensureString(value, label);
  if (!NAME_RE.test(trimmed)) {
    throw new Error(`${label} may contain only lowercase letters, digits, '-' and '.'`);
  }
  return trimmed;
}

function ensureTraceId(value, label) {
  const trimmed = ensureName(value, label);
  if (trimmed.length > 63) {
    throw new Error(`${label} must be 63 characters or fewer`);
  }
  return trimmed;
}

function trimKubeName(value, maxLength = 63) {
  const lowered = value.toLowerCase().replace(/[^a-z0-9-.]+/g, '-');
  const collapsed = lowered.replace(/-+/g, '-').replace(/^-+|-+$/g, '');
  return collapsed.slice(0, maxLength).replace(/-+$/g, '') || 'pi';
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value, null, 2), 'utf8').toString('base64');
}

function decodeJsonBase64(value, label) {
  try {
    return JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
  } catch (error) {
    throw new Error(`${label} is not valid base64-encoded JSON: ${error.message}`);
  }
}

function normalizeOwnerReference(value, label) {
  if (value === undefined || value === null) {
    return undefined;
  }
  const raw = ensureObject(value, label);
  return {
    apiVersion: ensureString(raw.apiVersion, `${label}.apiVersion`),
    kind: ensureString(raw.kind, `${label}.kind`),
    name: ensureName(raw.name, `${label}.name`),
    uid: ensureString(raw.uid, `${label}.uid`)
  };
}

function createWorkerTriggerName(sessionId, round, index) {
  return trimKubeName(`pi-session-${randomUUID().replace(/-/g, '').slice(0, 8)}-${sessionId}-r${round}-w${index}-trigger`);
}

const PI_TRIGGER_JOB_NAME_LABEL = 'triggers.harikube.info/pitrigger-name';

function buildSessionCleanup({ sessionId, namespace, secretName, round, workers }) {
  const workerCleanup = Array.isArray(workers)
    ? workers
        .map(candidate => {
          const index = Number(candidate?.index);
          const triggerName = typeof candidate?.triggerName === 'string' ? candidate.triggerName.trim() : '';
          if (!Number.isInteger(index) || index < 1 || !triggerName) {
            return undefined;
          }
          const labelSelector = `${PI_TRIGGER_JOB_NAME_LABEL}=${triggerName}`;
          return {
            index,
            triggerName,
            piTrigger: {
              apiVersion: 'triggers.harikube.info/v1',
              kind: 'PiTrigger',
              name: triggerName,
              namespace
            },
            job: {
              apiVersion: 'batch/v1',
              kind: 'Job',
              namespace,
              labelSelector
            }
          };
        })
        .filter(Boolean)
    : [];

  return {
    sessionId,
    round,
    namespace,
    sessionSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      name: secretName,
      namespace
    },
    workerTriggerNames: workerCleanup.map(worker => worker.triggerName),
    workers: workerCleanup
  };
}

function buildTerminalJobConditionFilter(index) {
  return [
    `(and (gt (len .status.conditions) ${index})`,
    `(eq (index (index .status.conditions ${index}) "status") "True")`,
    '(or',
    `(eq (index (index .status.conditions ${index}) "type") "Complete")`,
    `(eq (index (index .status.conditions ${index}) "type") "Failed")))`
  ].join(' ');
}

const TERMINAL_JOB_EVENT_FILTER = [
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

function normalizeWorker(worker, defaults, sessionId, namespace, round, cleanedPrompt, previousWorker) {
  const raw = ensureObject(worker, 'worker');
  const index = ensureInteger(raw.index, 'worker.index', { min: 1 });
  const task = ensureString(raw.task, `worker ${index} task`);
  const expectedResult = typeof raw.expectedResult === 'string' ? raw.expectedResult.trim() : '';
  const outputLocation = typeof raw.outputLocation === 'string' ? raw.outputLocation.trim() : '';
  const completed = Boolean(raw.completed);
  const result = typeof raw.result === 'string' ? raw.result.trim() : undefined;
  const triggerNameSource =
    (typeof raw.triggerName === 'string' && raw.triggerName.trim()) ||
    (typeof previousWorker?.triggerName === 'string' && previousWorker.triggerName.trim());
  const triggerName = triggerNameSource
    ? ensureName(triggerNameSource, `worker ${index} triggerName`)
    : createWorkerTriggerName(sessionId, round, index);
  const prompt = buildWorkerPrompt({
    defaults,
    sessionId,
    namespace,
    round,
    worker: { index, task, expectedResult, outputLocation },
    cleanedPrompt
  });

  // Preserve existing runtime metadata when present and provide explicit lifecycle/outcome
  const jobName =
    (typeof raw.job === 'string' && raw.job.trim()) ||
    (typeof raw.jobName === 'string' && raw.jobName.trim()) ||
    (typeof previousWorker?.job === 'string' && previousWorker.job.trim()) ||
    (typeof previousWorker?.jobName === 'string' && previousWorker.jobName.trim()) ||
    undefined;

  // state: one of 'pending', 'running', 'succeeded', 'failed', 'timeout'
  let state = previousWorker?.state;
  if (!state) {
    if (completed) {
      // if previous outcome is known prefer it, otherwise infer success unless result text suggests failure/timeout
      const prevOutcome = previousWorker?.outcome;
      if (prevOutcome) {
        state = prevOutcome;
      } else if (result) {
        if (/timeout|timed out/i.test(result)) {
          state = 'timeout';
        } else if (/failed|error|exception/i.test(result)) {
          state = 'failed';
        } else {
          state = 'succeeded';
        }
      } else {
        state = 'succeeded';
      }
    } else {
      state = 'pending';
    }
  }

  const outcome = previousWorker?.outcome || (completed ? (state === 'timeout' ? 'timeout' : state === 'failed' ? 'failed' : 'succeeded') : undefined);

  return {
    index,
    task,
    expectedResult,
    outputLocation,
    completed,
    result,
    namespace,
    triggerName,
    job: jobName,
    jobName: jobName,
    state,
    outcome,
    prompt
  };
}

export function normalizeSubAgentDefaults(rawDefaults, fallbackNamespace = 'default') {
  const raw = ensureObject(rawDefaults, 'subAgentDefaults');
  const agent = clone(ensureObject(raw.agent, 'subAgentDefaults.agent'));

  for (const [label, path] of REQUIRED_AGENT_PATHS) {
    ensureString(getPath(agent, path), `subAgentDefaults.agent.${label}`);
  }

  const namespace = ensureName(raw.namespace ?? fallbackNamespace, 'subAgentDefaults.namespace');
  const leaseDurationSeconds = ensureInteger(raw.leaseDurationSeconds ?? 15, 'subAgentDefaults.leaseDurationSeconds', {
    min: 1
  });
  const maxParallel = ensureInteger(raw.maxParallel ?? 5, 'subAgentDefaults.maxParallel', {
    min: 1,
    max: 5
  });

  ensureName(agent.configSecretRef.name, 'subAgentDefaults.agent.configSecretRef.name');
  ensureName(agent.promptsConfigMapRef.name, 'subAgentDefaults.agent.promptsConfigMapRef.name');
  ensureName(agent.skillsConfigMapRef.name, 'subAgentDefaults.agent.skillsConfigMapRef.name');
  if (agent.serviceAccountName) {
    ensureName(agent.serviceAccountName, 'subAgentDefaults.agent.serviceAccountName');
  }

  const piTriggerTimeout =
    typeof raw.piTriggerTimeout === 'string' && raw.piTriggerTimeout.trim()
      ? raw.piTriggerTimeout.trim()
      : typeof agent.timeout === 'string' && agent.timeout.trim()
      ? ensureString(agent.timeout, 'subAgentDefaults.agent.timeout')
      : '24h';
  const traceId =
    typeof raw.traceId === 'string' && raw.traceId.trim() ? ensureTraceId(raw.traceId, 'subAgentDefaults.traceId') : undefined;

  return {
    ...clone(raw),
    namespace,
    leaseDurationSeconds,
    maxParallel,
    piTriggerTimeout,
    ...(traceId ? { traceId } : {}),
    agent
  };
}

export function buildDefaultsPrefix(defaults) {
  return `sub-agent defaults base64://${Buffer.from(
    JSON.stringify(defaults),
    'utf8'
  ).toString('base64')}`;
}

export function decideSubagentStrategy({
  task,
  proposedAction,
  estimatedSteps,
  estimatedMinutes,
  independentWorkUnits = 1,
  maxParallel = 5,
  workerTimeout
}) {
  const taskSummary = ensureString(task, 'task');
  const action = proposedAction === undefined ? undefined : ensureOneOf(proposedAction, 'proposedAction', ['stay-local', 'delegate']);
  const steps = estimatedSteps === undefined ? undefined : ensureInteger(estimatedSteps, 'estimatedSteps', { min: 1 });
  const minutes = estimatedMinutes === undefined ? undefined : ensureNumber(estimatedMinutes, 'estimatedMinutes', { min: 0 });
  const workUnits = ensureInteger(independentWorkUnits, 'independentWorkUnits', { min: 1 });
  const parallelLimit = ensureInteger(maxParallel, 'maxParallel', { min: 1, max: 5 });
  const timeoutMinutes = workerTimeout === undefined ? undefined : parseDurationMinutes(workerTimeout, 'workerTimeout');

  const checks = [];
  const warnings = [];
  const exceedsStepLimit = steps !== undefined && steps > 5;
  const exceedsMinuteLimit = minutes !== undefined && minutes > 2;
  const canSplitSafely = workUnits > 1;
  const timeoutThresholdMinutes = timeoutMinutes === undefined ? undefined : timeoutMinutes * 0.75;
  const exceedsTimeoutSafetyWindow =
    minutes !== undefined && timeoutThresholdMinutes !== undefined ? minutes >= timeoutThresholdMinutes : false;

  if (steps === undefined) {
    warnings.push('estimatedSteps is missing; decision confidence is reduced.');
    checks.push({ status: 'warn', message: 'Estimated step count was not provided.' });
  } else {
    checks.push({
      status: exceedsStepLimit ? 'warn' : 'pass',
      message: exceedsStepLimit
        ? `Estimated ${steps} steps exceeds the stay-local guideline of 5.`
        : `Estimated ${steps} steps fits within the stay-local guideline.`
    });
  }

  if (minutes === undefined) {
    warnings.push('estimatedMinutes is missing; decision confidence is reduced.');
    checks.push({ status: 'warn', message: 'Estimated duration was not provided.' });
  } else {
    checks.push({
      status: exceedsMinuteLimit ? 'warn' : 'pass',
      message: exceedsMinuteLimit
        ? `Estimated ${minutes} minutes exceeds the stay-local guideline of 2.`
        : `Estimated ${minutes} minutes fits within the stay-local guideline.`
    });
  }

  if (timeoutMinutes === undefined) {
    warnings.push('workerTimeout is missing; timeout-safety delegation checks are reduced.');
    checks.push({ status: 'warn', message: 'Worker timeout was not provided.' });
  } else {
    checks.push({
      status: exceedsTimeoutSafetyWindow ? 'warn' : 'pass',
      message: exceedsTimeoutSafetyWindow
        ? `Estimated ${minutes} minutes reaches the 75% timeout safety threshold of ${timeoutThresholdMinutes} minutes for worker timeout ${workerTimeout}.`
        : `Estimated duration stays below the 75% timeout safety threshold of ${timeoutThresholdMinutes} minutes for worker timeout ${workerTimeout}.`
    });
  }

  checks.push({
    status: canSplitSafely ? 'pass' : 'info',
    message: canSplitSafely
      ? `Work is parallelizable across ${workUnits} independent stream(s).`
      : 'Work is a single dependent stream.'
  });

  const recommendedAction = exceedsTimeoutSafetyWindow || exceedsStepLimit || exceedsMinuteLimit || canSplitSafely ? 'delegate' : 'stay-local';
  const recommendedWorkers = recommendedAction === 'delegate' ? Math.max(1, Math.min(workUnits, parallelLimit)) : 0;
  if (recommendedAction === 'delegate' && workUnits > parallelLimit) {
    warnings.push(`Requested ${workUnits} independent work units but maxParallel limits dispatch to ${parallelLimit}.`);
  }

  let confidence = 'high';
  if (steps === undefined && minutes === undefined) {
    confidence = 'low';
  } else if (steps === undefined || minutes === undefined) {
    confidence = 'medium';
  }

  const approved = action === undefined ? true : action === recommendedAction;
  checks.push({
    status: approved ? 'pass' : 'fail',
    message:
      action === undefined
        ? `Recommended action is "${recommendedAction}".`
        : approved
          ? `Proposed action "${action}" matches the recommendation.`
          : `Proposed action "${action}" should change to "${recommendedAction}".`
  });

  const reason =
    recommendedAction === 'delegate'
      ? exceedsTimeoutSafetyWindow
        ? `Delegate this task asynchronously because the estimate approaches the worker timeout safety window${canSplitSafely ? ' and it also has parallelizable work' : ''}.`
        : `Delegate this task because it exceeds the local-work guideline${canSplitSafely ? ' and has parallelizable work' : ''}.`
      : 'Keep this task local because it is short, bounded, and single-stream.';

  return {
    task: taskSummary,
    proposedAction: action,
    approved,
    recommendedAction,
    recommendedWorkers,
    confidence,
    reason,
    workerTimeout: workerTimeout === undefined ? undefined : ensureString(workerTimeout, 'workerTimeout'),
    timeoutThresholdMinutes,
    exceedsTimeoutSafetyWindow,
    warnings,
    checks
  };
}

export function extractSubAgentDefaults(prompt, fallbackNamespace = 'default') {
  const source = typeof prompt === 'string' ? prompt : '';
  const match = source.match(/^\s*sub-agent defa(?:ults|uls) base64:\/\/([^\s]+)\s*/i);
  if (!match) {
    return {
      found: false,
      cleanedPrompt: source,
      subAgentDefaults: undefined
    };
  }

  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(match[1], 'base64').toString('utf8'));
  } catch (error) {
    throw new Error(`sub-agent defaults prefix is invalid: ${error.message}`);
  }

  return {
    found: true,
    cleanedPrompt: source.slice(match[0].length).replace(/^\s+/, ''),
    subAgentDefaults: normalizeSubAgentDefaults(decoded, fallbackNamespace)
  };
}

export function createSessionId() {
  return trimKubeName(`s-${randomUUID()}`);
}

export function buildWorkerPrompt({ defaults, sessionId, namespace, round, worker, cleanedPrompt = '' }) {
  return [
    `Session ID: ${sessionId}`,
    `Namespace: ${namespace}`,
    `Session Secret Label: harikube.info/session=${sessionId}`,
    `Round: ${round}`,
    `Worker Index: ${worker.index}`,
    'Sub-agent defaults are available from the `pi-subagent-defaults-runtime` skill for this execution.',
    '',
    'Task:',
    worker.task,
    worker.expectedResult ? `\nExpected Result:\n${worker.expectedResult}` : '',
    worker.outputLocation ? `\nOutput Location:\n${worker.outputLocation}` : '',
    cleanedPrompt ? `\nOriginal Prompt:\n${cleanedPrompt}` : '',
    '\nWhen you finish, return a short summary suitable for parent-session merge.'
  ]
    .filter(Boolean)
    .join('\n');
}

export function prepareSessionHibernation({
  subAgentDefaults,
  originalPrompt,
  cleanedPrompt = '',
  workSoFar = '',
  nextStep,
  workers,
  sessionId,
  secretName,
  round,
  previousContext,
  existingSecretJson,
  sourceOwnerReference
}) {
  const previous = previousContext ? ensureObject(previousContext, 'previousContext') : undefined;
  const defaults = normalizeSubAgentDefaults(
    subAgentDefaults ?? previous?.subAgentDefaults,
    previous?.namespace ?? 'default'
  );
  const parentPrompt = ensureString(originalPrompt ?? previous?.originalPrompt ?? cleanedPrompt, 'originalPrompt');
  const normalizedPrompt = typeof cleanedPrompt === 'string' && cleanedPrompt.trim() ? cleanedPrompt.trim() : parentPrompt;
  const next = ensureString(nextStep, 'nextStep');
  const rawWorkers = Array.isArray(workers) ? workers : [];
  if (rawWorkers.length === 0) {
    throw new Error('workers must contain at least one item');
  }

  const resolvedSessionId = ensureSessionId(sessionId ?? previous?.id ?? createSessionId(), 'sessionId');
  const resolvedRound = round ?? ((previous?.round ?? 0) + 1);
  const resolvedSecretName = trimKubeName(secretName ?? previous?.secretName ?? `pi-session-${resolvedSessionId}`);
  const resolvedOwnerReference = normalizeOwnerReference(
    sourceOwnerReference ?? previous?.sourceOwnerReference,
    'sourceOwnerReference'
  );
  const secretOwnerReferences = resolvedOwnerReference ? [resolvedOwnerReference] : undefined;
  const previousWorkersByIndex =
    previous?.round === resolvedRound && Array.isArray(previous?.workers)
      ? new Map(
          previous.workers
            .map(candidate => [Number(candidate?.index), candidate])
            .filter(([index]) => Number.isInteger(index) && index >= 1)
        )
      : new Map();
  const normalizedWorkers = rawWorkers.map(worker =>
    normalizeWorker(
      worker,
      defaults,
      resolvedSessionId,
      defaults.namespace,
      resolvedRound,
      normalizedPrompt,
      previousWorkersByIndex.get(Number(worker?.index))
    )
  );
  const pendingWorkers = normalizedWorkers.filter(worker => !worker.completed);
  const cleanup = buildSessionCleanup({
    sessionId: resolvedSessionId,
    namespace: defaults.namespace,
    secretName: resolvedSecretName,
    round: resolvedRound,
    workers: normalizedWorkers
  });
  const existingSecret = existingSecretJson ? resolveSecret(existingSecretJson) : undefined;

  if (existingSecret) {
    if (existingSecret.metadata?.name !== resolvedSecretName) {
      throw new Error(
        `existingSecretJson metadata.name must be ${resolvedSecretName}, got ${existingSecret.metadata?.name || '(missing)'}`
      );
    }
    if (existingSecret.metadata?.namespace !== defaults.namespace) {
      throw new Error(
        `existingSecretJson metadata.namespace must be ${defaults.namespace}, got ${existingSecret.metadata?.namespace || '(missing)'}`
      );
    }
  }

  const existingSecretUid =
    typeof existingSecret?.metadata?.uid === 'string' && existingSecret.metadata.uid.trim()
      ? existingSecret.metadata.uid.trim()
      : undefined;
  const triggerOwnerReferences = existingSecretUid
    ? [
        {
          apiVersion: 'v1',
          kind: 'Secret',
          name: resolvedSecretName,
          uid: existingSecretUid
        }
      ]
    : undefined;
  const requiresSecretOwnershipPass = pendingWorkers.length > 0 && !existingSecretUid;

  const context = {
    operation: 'pi-session-hibernate',
    id: resolvedSessionId,
    namespace: defaults.namespace,
    secretName: resolvedSecretName,
    round: resolvedRound,
    ...(defaults.traceId ? { traceId: defaults.traceId } : {}),
    subAgentDefaults: defaults,
    originalPrompt: parentPrompt,
    cleanedPrompt: normalizedPrompt,
    workSoFar,
    nextStep: next,
    workers: normalizedWorkers.map(({ prompt, ...worker }) => worker),
    cleanup,
    ...(resolvedOwnerReference ? { sourceOwnerReference: resolvedOwnerReference } : {}),
    requiresSecretOwnershipPass,
    // explicit persisted pending count so wake-up can derive authoritative state
    pendingCount: pendingWorkers.length,
    status: pendingWorkers.length === 0 ? 'merging' : 'hibernated'
  };

  const secretManifest = existingSecret
    ? clone(existingSecret)
    : {
        apiVersion: 'v1',
        kind: 'Secret',
        metadata: {
          name: resolvedSecretName,
          namespace: defaults.namespace
        },
        type: 'Opaque'
      };

  secretManifest.metadata = {
    ...(secretManifest.metadata || {}),
    name: resolvedSecretName,
    namespace: defaults.namespace,
    ...(secretOwnerReferences ? { ownerReferences: secretOwnerReferences } : {}),
    labels: {
      ...(secretManifest.metadata?.labels || {}),
      'harikube.info/session': resolvedSessionId,
      'harikube.info/round': String(resolvedRound),
      'harikube.info/pending-subagents': String(pendingWorkers.length),
      ...(defaults.traceId ? { [TRACE_LABEL]: defaults.traceId } : {})
    }
  };
  secretManifest.type = secretManifest.type || 'Opaque';

  // compute and persist aggregate counts so wake-up can tell completion vs failures/timeouts
  const agg = {
    total: Array.isArray(context.workers) ? context.workers.length : 0,
    pending: 0,
    running: 0,
    succeeded: 0,
    failed: 0,
    timedOut: 0,
    completed: 0
  };
  for (const w of context.workers || []) {
    const s = w?.state;
    if (s === 'running') agg.running++;
    else if (s === 'succeeded') agg.succeeded++;
    else if (s === 'failed') agg.failed++;
    else if (s === 'timeout' || s === 'timedout') agg.timedOut++;
    else agg.pending++;
    if (w?.completed) agg.completed++;
  }
  context.aggregate = agg;
  context.aggregate.allSucceeded = agg.completed > 0 && agg.failed === 0 && agg.timedOut === 0 && agg.succeeded === agg.completed;
  context.aggregate.completedWithFailures = agg.completed > 0 && agg.failed > 0;
  context.aggregate.completedWithTimeouts = agg.completed > 0 && agg.timedOut > 0;

  secretManifest.data = {
    ...(secretManifest.data || {}),
    'context.json': encodeJson(context)
  };
  delete secretManifest.stringData;

  const leaseManifests = [];

  const triggerManifests = triggerOwnerReferences
    ? pendingWorkers.map(worker => ({
        apiVersion: 'triggers.harikube.info/v1',
        kind: 'PiTrigger',
        metadata: {
          name: worker.triggerName,
          namespace: defaults.namespace,
          ownerReferences: triggerOwnerReferences,
          labels: {
            'harikube.info/session': resolvedSessionId,
            'harikube.info/round': String(resolvedRound),
            'harikube.info/worker': String(worker.index),
            ...(defaults.traceId ? { [TRACE_LABEL]: defaults.traceId } : {})
          },
          annotations: {
            'harikube.info/session-secret': resolvedSecretName,
            'harikube.info/output-location': worker.outputLocation || ''
          }
        },
        spec: {
          resource: {
            apiVersion: 'batch/v1',
            kind: 'Job'
          },
          namespaces: [defaults.namespace],
          labelSelectors: [`${PI_TRIGGER_JOB_NAME_LABEL}=${worker.triggerName}`],
          eventTypes: ['ADDED', 'MODIFIED'],
          eventFilter: TERMINAL_JOB_EVENT_FILTER,
          sendInitialEvents: true,
          maxJobs: 1,
          timeout: defaults.piTriggerTimeout,
          agent: defaults.agent
        }
      }))
    : [];

  return {
    sessionId: resolvedSessionId,
    namespace: defaults.namespace,
    secretName: resolvedSecretName,
    round: resolvedRound,
    pendingSubagents: pendingWorkers.length,
    workSoFar,
    nextStep: next,
    context,
    cleanup,
    requiresSecretOwnershipPass,
    secretManifest,
    leaseManifests,
    triggerManifests,
    workers: normalizedWorkers,
    exitReason: `Hibernated: session ${resolvedSessionId} round ${resolvedRound} waiting for ${pendingWorkers.length} sub-agents`
  };
}

function ensureSessionId(value, label) {
  const sessionId = ensureString(value, label);
  if (!ID_RE.test(sessionId)) {
    throw new Error(`${label} may contain only lowercase letters, digits, and '-'`);
  }
  return sessionId;
}

function parseLine(prompt, label) {
  const match = prompt.match(new RegExp(`^${label}:\\s*(.+)$`, 'im'));
  return match?.[1]?.trim();
}

export function parseWakeupPrompt(prompt) {
  const source = typeof prompt === 'string' ? prompt : '';
  const sessionId = parseLine(source, 'Session ID');
  const namespace = parseLine(source, 'Namespace');
  const sessionSecretLabel = parseLine(source, 'Session Secret Label');
  const roundText = parseLine(source, 'Round');
  const workerIndexText = parseLine(source, 'Worker Index');
  const jobName = parseLine(source, 'Job');

  const hasWakeupLines = Boolean(
    sessionId && namespace && sessionSecretLabel && roundText && workerIndexText
  );

  if (!hasWakeupLines) {
    return { isWakeup: false };
  }

  const round = ensureInteger(roundText, 'Round', { min: 1 });
  const workerIndex = ensureInteger(workerIndexText, 'Worker Index', { min: 1 });
  const [labelKey, labelValue] = sessionSecretLabel.split('=');
  if (!labelKey || !labelValue || !LABEL_KEY_RE.test(labelKey) || !ID_RE.test(labelValue)) {
    throw new Error(
      'Session Secret Label must have the form key=value using lowercase letters, digits, dashes, dots, and optional / in the key'
    );
  }

  return {
    isWakeup: true,
    sessionId: ensureSessionId(sessionId, 'Session ID'),
    namespace: ensureName(namespace, 'Namespace'),
    sessionSecretLabel,
    round,
    workerIndex,
    jobName: jobName ? trimKubeName(jobName) : undefined,
    timeout: /timed out|timeout/i.test(source)
  };
}

function resolveSecret(secretInput) {
  if (secretInput === undefined || secretInput === null || secretInput === '') {
    return undefined;
  }
  const parsed = typeof secretInput === 'string' ? JSON.parse(secretInput) : clone(secretInput);
  if (parsed?.kind === 'Status' && parsed?.reason === 'NotFound') {
    return undefined;
  }
  if (parsed?.kind === 'List') {
    if (!Array.isArray(parsed.items) || parsed.items.length === 0) {
      return undefined;
    }
    if (parsed.items.length !== 1) {
      throw new Error('expected exactly one Secret in the list response');
    }
    return parsed.items[0];
  }
  if (parsed?.kind !== 'Secret') {
    throw new Error('expected a Secret JSON object, Secret List response, or NotFound Status');
  }
  return parsed;
}

function readContextFromSecret(secret) {
  const encoded = secret?.data?.['context.json'];
  if (!encoded) {
    throw new Error('Secret does not contain data["context.json"]');
  }
  return decodeJsonBase64(encoded, 'context.json');
}

export function inspectJob(jobJson, eventsJson) {
  const job = jobJson ? (typeof jobJson === 'string' ? JSON.parse(jobJson) : clone(jobJson)) : undefined;
  const events = eventsJson
    ? typeof eventsJson === 'string'
      ? JSON.parse(eventsJson)
      : clone(eventsJson)
    : undefined;

  if (!job) {
    return { outcome: 'timeout', summary: 'Timed out before a Job was available.' };
  }

  const conditions = Array.isArray(job.status?.conditions) ? job.status.conditions : [];
  const complete = conditions.find(condition => condition.type === 'Complete' && condition.status === 'True');
  const failed = conditions.find(condition => condition.type === 'Failed' && condition.status === 'True');

  const eventItems = Array.isArray(events?.items) ? events.items : [];
  const latestEvent = eventItems.at(-1);
  const eventSummary = latestEvent?.message || latestEvent?.reason || '';

  if (complete) {
    return { outcome: 'succeeded', summary: eventSummary || complete.message || 'Job completed successfully.' };
  }
  if (failed) {
    return { outcome: 'failed', summary: eventSummary || failed.message || 'Job failed.' };
  }
  if (job.status?.active) {
    return { outcome: 'not-ready', summary: 'Job is still active.' };
  }

  return {
    outcome: 'failed',
    summary: eventSummary || 'Job finished without a clear success condition.'
  };
}

export function processSessionWakeup({ prompt, secretJson, workerSummary = '', jobJson, eventsJson }) {
  const promptInfo = parseWakeupPrompt(prompt);
  if (!promptInfo.isWakeup) {
    return {
      action: 'skip',
      reason: 'No wake-up lines found in the prompt.'
    };
  }

  const secret = resolveSecret(secretJson);
  if (!secret) {
    return {
      action: 'secret-not-found',
      reason: `Session Secret not found for session ${promptInfo.sessionId}.`,
      promptInfo,
      exitReason: `Goodbye: session ${promptInfo.sessionId} secret not found.`
    };
  }
  const context = readContextFromSecret(secret);
  // Ensure stored worker records always carry explicit state and outcome fields
  if (Array.isArray(context.workers)) {
    context.workers = context.workers.map(w => {
      const copy = { ...(w || {}) };
      const completed = Boolean(copy?.completed);
      const outcome = copy?.outcome;
      const state = copy?.state;

      // infer missing state from outcome/result/completed when possible
      if (!state) {
        if (completed) {
          if (outcome) {
            copy.state = outcome === 'timeout' ? 'timeout' : outcome === 'failed' ? 'failed' : 'succeeded';
          } else if (typeof copy?.result === 'string') {
            if (/timeout|timed out/i.test(copy.result)) copy.state = 'timeout';
            else if (/failed|error|exception/i.test(copy.result)) copy.state = 'failed';
            else copy.state = 'succeeded';
          } else {
            copy.state = 'succeeded';
          }
        } else {
          copy.state = 'pending';
        }
      }

      if (copy.outcome === undefined) {
        if (completed) {
          copy.outcome = copy.state === 'timeout' ? 'timeout' : copy.state === 'failed' ? 'failed' : copy.state === 'succeeded' ? 'succeeded' : undefined;
        } else {
          copy.outcome = undefined;
        }
      }

      return copy;
    });
  }

  if (context.id !== promptInfo.sessionId || context.namespace !== promptInfo.namespace) {
    return {
      action: 'stale-round',
      reason: 'Prompt session does not match the stored context.'
    };
  }
  if (Number(context.round) !== promptInfo.round) {
    return {
      action: 'stale-round',
      reason: `Prompt round ${promptInfo.round} does not match current round ${context.round}.`
    };
  }

  const worker = Array.isArray(context.workers)
    ? context.workers.find(candidate => Number(candidate.index) === promptInfo.workerIndex)
    : undefined;
  if (!worker) {
    throw new Error(`worker ${promptInfo.workerIndex} is missing from context.workers`);
  }

  const cleanup =
    context.cleanup && typeof context.cleanup === 'object'
      ? clone(context.cleanup)
      : buildSessionCleanup({
          sessionId: context.id ?? promptInfo.sessionId,
          namespace: context.namespace ?? promptInfo.namespace,
          secretName: context.secretName ?? secret.metadata?.name ?? `pi-session-${promptInfo.sessionId}`,
          round: Number(context.round) || promptInfo.round,
          workers: Array.isArray(context.workers) ? context.workers : []
        });

  const jobState = promptInfo.timeout ? { outcome: 'timeout', summary: 'Worker timed out.' } : inspectJob(jobJson, eventsJson);
  if (jobState.outcome === 'not-ready') {
    return {
      action: 'not-ready',
      reason: jobState.summary,
      promptInfo,
      context,
      cleanup
    };
  }

  const resultKey = `result-r${promptInfo.round}-w${promptInfo.workerIndex}.json`;
  if (secret.data?.[resultKey]) {
    return {
      action: 'already-reported',
      reason: `Session ${promptInfo.sessionId} round ${promptInfo.round}: worker ${promptInfo.workerIndex} already reported.`,
      promptInfo,
      context,
      cleanup
    };
  }

  // Derive pending state from authoritative sources: context.workers and existing result entries in the Secret
  const workersArray = Array.isArray(context.workers) ? context.workers : [];
  const existingResultKeys = Object.keys(secret.data || {}).filter(key => key.startsWith(`result-r${promptInfo.round}-w`));
  const completedIndexes = new Set();

  // mark workers already marked completed in context
  for (const w of workersArray) {
    const idx = Number(w?.index);
    if (Number.isInteger(idx) && w?.completed) {
      completedIndexes.add(idx);
    }
  }

  // mark workers with existing result files in the Secret
  for (const key of existingResultKeys) {
    const m = key.match(/result-r\d+-w(\d+)\.json$/);
    if (m) {
      const idx = Number(m[1]);
      if (Number.isInteger(idx)) {
        completedIndexes.add(idx);
      }
    }
  }

  // include the current reporting worker as completed (we'll persist its result below)
  completedIndexes.add(promptInfo.workerIndex);

  // pending workers are those in context.workers whose index is not in completedIndexes
  const pendingCount = workersArray.filter(w => {
    const idx = Number(w?.index);
    return Number.isInteger(idx) && !completedIndexes.has(idx);
  }).length;

  // prefer stored job identity (context.workers[*].job or jobName) over prompt-derived job name
  const jobIdentity = worker?.job || worker?.jobName || promptInfo.jobName || null;

  const result = {
    round: promptInfo.round,
    index: promptInfo.workerIndex,
    job: jobIdentity,
    outcome: jobState.outcome,
    summary: (workerSummary || jobState.summary || jobState.outcome).trim()
  };

  const updatedSecret = clone(secret);
  updatedSecret.metadata = updatedSecret.metadata || {};
  // keep the Secret label as advisory but keep it synchronized to the derived pending count
  updatedSecret.metadata.labels = {
    ...(updatedSecret.metadata.labels || {}),
    'harikube.info/session': promptInfo.sessionId,
    'harikube.info/round': String(promptInfo.round),
    'harikube.info/pending-subagents': String(pendingCount)
  };
  updatedSecret.data = {
    ...(updatedSecret.data || {}),
    [resultKey]: encodeJson(result)
  };

  // persist the reporting worker's completion/result into the returned context.workers
  const updatedContext = clone(context);
  updatedContext.workers = Array.isArray(updatedContext.workers)
    ? updatedContext.workers.map(w => {
        const idx = Number(w?.index);
        if (Number.isInteger(idx) && idx === promptInfo.workerIndex) {
          const updated = {
            ...w,
            completed: true,
            result: (result.summary || '').trim(),
            state: jobState.outcome === 'timeout' ? 'timeout' : jobState.outcome === 'succeeded' ? 'succeeded' : jobState.outcome,
            outcome: jobState.outcome,
            job: jobIdentity,
            jobName: jobIdentity
          };
          return updated;
        }
        return w;
      })
    : updatedContext.workers;

  // recompute aggregate counts and session status
  const agg = {
    total: Array.isArray(updatedContext.workers) ? updatedContext.workers.length : 0,
    pending: 0,
    running: 0,
    succeeded: 0,
    failed: 0,
    timedOut: 0,
    completed: 0
  };
  for (const w of updatedContext.workers || []) {
    const s = w?.state;
    if (s === 'running') agg.running++;
    else if (s === 'succeeded') agg.succeeded++;
    else if (s === 'failed') agg.failed++;
    else if (s === 'timeout' || s === 'timedout') agg.timedOut++;
    else agg.pending++;
    if (w?.completed) agg.completed++;
  }
  updatedContext.aggregate = agg;
  updatedContext.aggregate.allSucceeded = agg.completed > 0 && agg.failed === 0 && agg.timedOut === 0 && agg.succeeded === agg.completed;
  updatedContext.aggregate.completedWithFailures = agg.completed > 0 && agg.failed > 0;
  updatedContext.aggregate.completedWithTimeouts = agg.completed > 0 && agg.timedOut > 0;

  updatedContext.status = pendingCount === 0 ? 'merging' : 'hibernated';
  updatedContext.cleanup = cleanup;
  updatedSecret.data['context.json'] = encodeJson(updatedContext);

  // compute a top-level aggregate outcome when we're merging so callers can distinguish
  // an overall completed-with-failures/timeouts state from a single-worker failure
  const summaryCounts = { succeeded: agg.succeeded, failed: agg.failed, timeout: agg.timedOut };
  if (pendingCount === 0) {
    if (updatedContext.aggregate.completedWithFailures) {
      result.outcome = 'completed-with-failures';
    } else if (updatedContext.aggregate.completedWithTimeouts) {
      result.outcome = 'completed-with-timeouts';
    } else if (updatedContext.aggregate.allSucceeded) {
      result.outcome = 'succeeded';
    }
  }

  return {
    action: pendingCount === 0 ? 'merge' : 'wait',
    promptInfo,
    context: updatedContext,
    cleanup,
    pendingCount,
    result,
    summaryCounts,
    replacementSecret: updatedSecret,
    replacementSecretJson: JSON.stringify(updatedSecret, null, 2),
    exitReason:
      pendingCount === 0
        ? `Session ${promptInfo.sessionId} round ${promptInfo.round}: merging results from ${Array.isArray(context.workers) ? context.workers.length : 0} workers`
        : `Session ${promptInfo.sessionId} round ${promptInfo.workerIndex} recorded, ${pendingCount} pending`
  };
}

