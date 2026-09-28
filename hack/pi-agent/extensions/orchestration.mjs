import {
  decideSubagentStrategy,
  extractSubAgentDefaults,
  normalizeSubAgentDefaults,
  parseWakeupPrompt,
  prepareSessionHibernation,
  processSessionWakeup
} from './session-lib.mjs';
import { execKubectlCommand, isConflict } from './kubectl-lib.mjs';
import { applyPiTriggerManifests, buildPiTriggerManifest } from './pitrigger-lib.mjs';

const PI_SUBAGENT_DEFAULTS_ENV = 'PI_SUBAGENT_DEFAULTS_BASE64';

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function ensureString(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value.trim();
}

function decodeRuntimeDefaults(env = process.env) {
  const encoded = env?.[PI_SUBAGENT_DEFAULTS_ENV]?.trim();
  if (!encoded) {
    return undefined;
  }

  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  } catch (error) {
    throw new Error(`${PI_SUBAGENT_DEFAULTS_ENV} must contain base64-encoded JSON: ${error.message}`);
  }

  return normalizeSubAgentDefaults(parsed, 'default');
}

export function resolveSubagentDefaults({
  prompt = '',
  fallbackNamespace = 'default',
  subAgentDefaults,
  env = process.env
} = {}) {
  const extracted = extractSubAgentDefaults(prompt, fallbackNamespace);

  if (subAgentDefaults) {
    return {
      source: 'provided',
      found: true,
      cleanedPrompt: extracted.cleanedPrompt,
      subAgentDefaults: normalizeSubAgentDefaults(subAgentDefaults, fallbackNamespace)
    };
  }

  const runtimeDefaults = decodeRuntimeDefaults(env);
  if (runtimeDefaults) {
    return {
      source: 'runtime',
      found: true,
      cleanedPrompt: extracted.cleanedPrompt,
      subAgentDefaults: runtimeDefaults
    };
  }

  return {
    source: extracted.found ? 'prompt' : 'none',
    ...extracted
  };
}

export function chooseExecutionMode({
  task,
  proposedAction,
  estimatedSteps,
  estimatedMinutes,
  independentWorkUnits = 1,
  maxParallel,
  workerTimeout,
  contextHeavy = false,
  preferHeadless = true,
  prompt = '',
  fallbackNamespace = 'default',
  subAgentDefaults,
  env = process.env
} = {}) {
  const defaultsResult = resolveSubagentDefaults({ prompt, fallbackNamespace, subAgentDefaults, env });
  const resolvedDefaults = defaultsResult.subAgentDefaults;
  const resolvedMaxParallel = maxParallel ?? resolvedDefaults?.maxParallel ?? 5;
  const resolvedWorkerTimeout = workerTimeout ?? resolvedDefaults?.piTriggerTimeout ?? resolvedDefaults?.agent?.timeout;
  const decision = decideSubagentStrategy({
    task,
    proposedAction,
    estimatedSteps,
    estimatedMinutes,
    independentWorkUnits,
    maxParallel: resolvedMaxParallel,
    workerTimeout: resolvedWorkerTimeout
  });

  const selectedMode =
    decision.recommendedAction === 'delegate'
      ? 'delegate'
      : contextHeavy && preferHeadless
        ? 'headless'
        : 'stay-local';

  const modeReason =
    selectedMode === 'delegate'
      ? decision.reason
      : selectedMode === 'headless'
        ? 'Use headless execution because the work is still a single bounded stream but would otherwise consume too much parent context.'
        : decision.reason;

  // If delegation was chosen and the decision exposed a derived sub-agent timeout, propagate that
  // timeout into the resolved sub-agent defaults so both the PiTrigger controller timeout
  // (piTriggerTimeout) and the worker runtime (agent.timeout) reflect the derived value.
  const propagatedSubAgentDefaults = (() => {
    if (selectedMode !== 'delegate' || !resolvedDefaults || decision.subagentTimeoutMinutes === undefined) {
      return resolvedDefaults;
    }
    const minutes = decision.subagentTimeoutMinutes;
    const duration = `${minutes}m`;
    const modified = clone(resolvedDefaults);
    modified.piTriggerTimeout = duration;
    modified.agent = modified.agent || {};
    modified.agent.timeout = duration;
    return modified;
  })();

  return {
    ...decision,
    selectedMode,
    modeReason,
    defaultsSource: defaultsResult.source,
    cleanedPrompt: defaultsResult.cleanedPrompt,
    subAgentDefaults: propagatedSubAgentDefaults,
    maxParallel: resolvedMaxParallel,
    workerTimeout: resolvedWorkerTimeout,
    contextHeavy: Boolean(contextHeavy),
    preferHeadless: Boolean(preferHeadless)
  };
}

export async function orchestrateSubagentExecution(
  {
    task,
    proposedAction,
    estimatedSteps,
    estimatedMinutes,
    independentWorkUnits = 1,
    maxParallel,
    workerTimeout,
    contextHeavy = false,
    preferHeadless = true,
    prompt = '',
    fallbackNamespace = 'default',
    subAgentDefaults,
    delegation
  } = {},
  { kubectl = execKubectlCommand, env = process.env } = {}
) {
  const decision = chooseExecutionMode({
    task,
    proposedAction,
    estimatedSteps,
    estimatedMinutes,
    independentWorkUnits,
    maxParallel,
    workerTimeout,
    contextHeavy,
    preferHeadless,
    prompt,
    fallbackNamespace,
    subAgentDefaults,
    env
  });

  if (decision.selectedMode !== 'delegate') {
    return {
      status: 'planned',
      selectedMode: decision.selectedMode,
      decision
    };
  }

  if (!delegation?.nextStep || !Array.isArray(delegation?.workers) || delegation.workers.length === 0) {
    return {
      status: 'needs-delegation-input',
      selectedMode: decision.selectedMode,
      decision,
      reason: 'Delegated execution requires delegation.nextStep and at least one worker.'
    };
  }

  const hibernated = await hibernateSession(
    {
      prompt,
      fallbackNamespace,
      subAgentDefaults: decision.subAgentDefaults ?? subAgentDefaults,
      originalPrompt: delegation.originalPrompt ?? decision.cleanedPrompt ?? prompt,
      cleanedPrompt: delegation.cleanedPrompt ?? decision.cleanedPrompt,
      workSoFar: delegation.workSoFar,
      nextStep: delegation.nextStep,
      workers: delegation.workers,
      sessionId: delegation.sessionId,
      secretName: delegation.secretName,
      round: delegation.round,
      previousContext: delegation.previousContext,
      sourceOwnerReference: delegation.sourceOwnerReference
    },
    { kubectl, env }
  );

  return {
    ...hibernated,
    decision,
    selectedMode: decision.selectedMode
  };
}

function buildApplyPayload(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return undefined;
  }
  if (items.length === 1) {
    return JSON.stringify(items[0], null, 2);
  }
  return JSON.stringify({ apiVersion: 'v1', kind: 'List', items }, null, 2);
}

function parseMaybeJson(stdout) {
  const source = String(stdout || '').trim();
  if (!source) {
    return undefined;
  }
  return JSON.parse(source);
}

async function getSecretByName(secretName, namespace, kubectl) {
  const result = await kubectl({
    command: `get secret ${secretName} -o json --ignore-not-found`,
    namespace
  });
  const parsed = parseMaybeJson(result.stdout);
  return parsed ? JSON.stringify(parsed) : undefined;
}

async function getSecretByLabel(labelSelector, namespace, kubectl) {
  const result = await kubectl({
    command: `get secret -l ${labelSelector} -o json`,
    namespace
  });
  return JSON.stringify(parseMaybeJson(result.stdout) || { apiVersion: 'v1', kind: 'List', items: [] });
}

async function applyObjects(items, namespace, kubectl) {
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

async function replaceObject(jsonPayload, namespace, kubectl) {
  return await kubectl({
    command: 'replace -f -',
    namespace,
    input: ensureString(jsonPayload, 'replacementSecretJson')
  });
}

export async function hibernateSession(
  {
    prompt = '',
    fallbackNamespace = 'default',
    subAgentDefaults,
    originalPrompt,
    cleanedPrompt,
    workSoFar,
    nextStep,
    workers,
    sessionId,
    secretName,
    round,
    previousContext,
    sourceOwnerReference
  },
  { kubectl = execKubectlCommand, env = process.env } = {}
) {
  const defaultsResult = resolveSubagentDefaults({
    prompt,
    fallbackNamespace,
    subAgentDefaults,
    env
  });
  if (!defaultsResult.found || !defaultsResult.subAgentDefaults) {
    throw new Error('sub-agent defaults are required to hibernate a session');
  }

  const basePrepared = prepareSessionHibernation({
    subAgentDefaults: defaultsResult.subAgentDefaults,
    originalPrompt: originalPrompt ?? defaultsResult.cleanedPrompt ?? prompt,
    cleanedPrompt: cleanedPrompt ?? defaultsResult.cleanedPrompt,
    workSoFar,
    nextStep,
    workers,
    sessionId,
    secretName,
    round,
    previousContext,
    sourceOwnerReference
  });

  const existingSecretJson = await getSecretByName(basePrepared.secretName, basePrepared.namespace, kubectl);
  let prepared = existingSecretJson
    ? prepareSessionHibernation({
        subAgentDefaults: defaultsResult.subAgentDefaults,
        originalPrompt: originalPrompt ?? defaultsResult.cleanedPrompt ?? prompt,
        cleanedPrompt: cleanedPrompt ?? defaultsResult.cleanedPrompt,
        workSoFar,
        nextStep,
        workers,
        sessionId: basePrepared.sessionId,
        secretName: basePrepared.secretName,
        round: basePrepared.round,
        previousContext,
        existingSecretJson,
        sourceOwnerReference
      })
    : basePrepared;

  const operations = [];
  const firstSecretWrite = await applyObjects([prepared.secretManifest], prepared.namespace, kubectl);
  if (firstSecretWrite) {
    operations.push({ type: 'apply-secret', commandExecuted: firstSecretWrite.commandExecuted });
  }

  if (prepared.requiresSecretOwnershipPass) {
    const refetchedSecretJson = await getSecretByName(prepared.secretName, prepared.namespace, kubectl);
    if (!refetchedSecretJson) {
      throw new Error(`session Secret ${prepared.secretName} was not readable after creation`);
    }
    prepared = prepareSessionHibernation({
      subAgentDefaults: defaultsResult.subAgentDefaults,
      originalPrompt: originalPrompt ?? defaultsResult.cleanedPrompt ?? prompt,
      cleanedPrompt: cleanedPrompt ?? defaultsResult.cleanedPrompt,
      workSoFar,
      nextStep,
      workers,
      sessionId: prepared.sessionId,
      secretName: prepared.secretName,
      round: prepared.round,
      previousContext,
      existingSecretJson: refetchedSecretJson,
      sourceOwnerReference
    });
    const secondSecretWrite = await applyObjects([prepared.secretManifest], prepared.namespace, kubectl);
    if (secondSecretWrite) {
      operations.push({ type: 'apply-secret-owned-context', commandExecuted: secondSecretWrite.commandExecuted });
    }
  }

  const triggerWrite = await applyPiTriggerManifests(prepared.triggerManifests, prepared.namespace, kubectl);
  if (triggerWrite) {
    operations.push({ type: 'apply-triggers', commandExecuted: triggerWrite.commandExecuted });
  }

  return {
    status: 'hibernated',
    defaultsSource: defaultsResult.source,
    operations,
    ...prepared
  };
}

export async function createPiTrigger(
  {
    prompt = '',
    fallbackNamespace = 'default',
    subAgentDefaults,
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
    provider,
    model,
    serviceAccountName,
    agent,
    apply = true
  },
  { kubectl = execKubectlCommand, env = process.env } = {}
) {
  const defaultsResult =
    subAgentDefaults !== undefined || prompt
      ? resolveSubagentDefaults({
          prompt,
          fallbackNamespace,
          subAgentDefaults,
          env
        })
      : { found: false, source: 'none', cleanedPrompt: prompt, subAgentDefaults: undefined };

  const resolvedNamespace = namespace ?? defaultsResult.subAgentDefaults?.namespace ?? fallbackNamespace;
  const inheritedAgent = defaultsResult.subAgentDefaults?.agent;
  if (!inheritedAgent && !agent) {
    throw new Error('agent is required when sub-agent defaults do not provide one');
  }
  const resolvedAgent = {
    ...(inheritedAgent ? clone(inheritedAgent) : {}),
    ...(agent ? clone(agent) : {}),
    ...(provider ? { provider } : {}),
    ...(model ? { model } : {}),
    ...(serviceAccountName ? { serviceAccountName } : {})
  };

  const manifest = buildPiTriggerManifest({
    name,
    namespace: resolvedNamespace,
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
    agent: resolvedAgent
  });

  const write = apply ? await applyPiTriggerManifests([manifest], resolvedNamespace, kubectl) : undefined;

  return {
    status: apply ? 'created' : 'prepared',
    defaultsSource: defaultsResult.source,
    namespace: resolvedNamespace,
    manifest,
    ...(write ? { write: { type: 'apply-trigger', commandExecuted: write.commandExecuted } } : {})
  };
}

export async function handleSessionWakeup(
  { prompt, workerSummary = '', maxAttempts = 5 },
  { kubectl = execKubectlCommand } = {}
) {
  const promptInfo = parseWakeupPrompt(prompt);
  if (!promptInfo.isWakeup) {
    return {
      action: 'skip',
      reason: 'No wake-up lines found in the prompt.'
    };
  }

  const secretJson = await getSecretByLabel(promptInfo.sessionSecretLabel, promptInfo.namespace, kubectl);
  if (promptInfo.timeout) {
    const jobJson = promptInfo.jobName
      ? JSON.stringify(
          parseMaybeJson(
            (
              await kubectl({
                command: `get job ${promptInfo.jobName} -o json --ignore-not-found`,
                namespace: promptInfo.namespace
              })
            ).stdout
          )
        )
      : undefined;
    const eventsJson = promptInfo.jobName
      ? (
          await kubectl({
            command: `get events --field-selector involvedObject.kind=Job,involvedObject.name=${promptInfo.jobName} -o json`,
            namespace: promptInfo.namespace
          })
        ).stdout
      : undefined;
    const podsJson = promptInfo.jobName
      ? JSON.stringify(
          parseMaybeJson(
            (
              await kubectl({
                command: `get pods -l job-name=${promptInfo.jobName} -o json --ignore-not-found`,
                namespace: promptInfo.namespace
              })
            ).stdout
          )
        )
      : undefined;

    let latestSecretJson = secretJson;
    let lastConflict;

    for (let attempt = 1; attempt <= Math.max(1, Math.trunc(maxAttempts || 5)); attempt += 1) {
      const result = processSessionWakeup({ prompt, secretJson: latestSecretJson, workerSummary, jobJson, eventsJson, podsJson });

      if (!(result.action === 'wait' || result.action === 'merge')) {
        return {
          ...result,
          fetched: {
            secret: true,
            job: Boolean(promptInfo.jobName),
            events: Boolean(promptInfo.jobName),
            pods: Boolean(promptInfo.jobName)
          }
        };
      }

      try {
        const writeResult = await replaceObject(result.replacementSecretJson, promptInfo.namespace, kubectl);
        return {
          ...result,
          attempts: attempt,
          fetched: {
            secret: true,
            job: Boolean(promptInfo.jobName),
            events: Boolean(promptInfo.jobName),
            pods: Boolean(promptInfo.jobName)
          },
          write: {
            type: 'replace-secret',
            commandExecuted: writeResult.commandExecuted
          }
        };
      } catch (error) {
        if (!(attempt < maxAttempts && isConflict(error?.stderr))) {
          throw error;
        }
        lastConflict = error;
        latestSecretJson = await getSecretByLabel(promptInfo.sessionSecretLabel, promptInfo.namespace, kubectl);
      }
    }

    throw new Error(lastConflict?.stderr || lastConflict?.message || 'failed to update session Secret');
  }

  const jobJson = promptInfo.jobName
    ? JSON.stringify(
        parseMaybeJson(
          (
            await kubectl({
              command: `get job ${promptInfo.jobName} -o json --ignore-not-found`,
              namespace: promptInfo.namespace
            })
          ).stdout
        )
      )
    : undefined;
  const eventsJson = promptInfo.jobName
    ? (
        await kubectl({
          command: `get events --field-selector involvedObject.kind=Job,involvedObject.name=${promptInfo.jobName} -o json`,
          namespace: promptInfo.namespace
        })
      ).stdout
    : undefined;

  let latestSecretJson = secretJson;
  let lastConflict;

  for (let attempt = 1; attempt <= Math.max(1, Math.trunc(maxAttempts || 5)); attempt += 1) {
    const result = processSessionWakeup({
      prompt,
      secretJson: latestSecretJson,
      workerSummary,
      jobJson,
      eventsJson
    });

    if (!(result.action === 'wait' || result.action === 'merge')) {
      return {
        ...result,
        fetched: {
          secret: true,
          job: Boolean(promptInfo.jobName),
          events: Boolean(promptInfo.jobName)
        }
      };
    }

    try {
      const writeResult = await replaceObject(result.replacementSecretJson, promptInfo.namespace, kubectl);
      return {
        ...result,
        attempts: attempt,
        fetched: {
          secret: true,
          job: Boolean(promptInfo.jobName),
          events: Boolean(promptInfo.jobName)
        },
        write: {
          type: 'replace-secret',
          commandExecuted: writeResult.commandExecuted
        }
      };
    } catch (error) {
      if (!(attempt < maxAttempts && isConflict(error?.stderr))) {
        throw error;
      }
      lastConflict = error;
      latestSecretJson = await getSecretByLabel(promptInfo.sessionSecretLabel, promptInfo.namespace, kubectl);
    }
  }

  throw new Error(lastConflict?.stderr || lastConflict?.message || 'failed to update session Secret');
}
