import test from 'node:test';
import assert from 'node:assert/strict';
import {
  prepareSessionHibernation,
  buildDefaultsPrefix
} from './session-lib.mjs';
import {
  chooseExecutionMode,
  handleSessionWakeup,
  hibernateSession,
  orchestrateSubagentExecution,
  resolveSubagentDefaults
} from './orchestration.mjs';

function sampleDefaults() {
  return {
    namespace: 'demo',
    traceId: '123e4567-e89b-12d3-a456-426614174000-1735689600',
    leaseDurationSeconds: 30,
    maxParallel: 3,
    agent: {
      image: 'example.com/pi:1.0.0',
      configSecretRef: { name: 'pi-config' },
      promptsConfigMapRef: { name: 'pi-prompts' },
      skillsConfigMapRef: { name: 'pi-skills' },
      serviceAccountName: 'pi-runner',
      timeout: '10m'
    }
  };
}

function buildStoredSecret(prepared, extraData = {}) {
  return {
    ...prepared.secretManifest,
    metadata: {
      ...(prepared.secretManifest.metadata || {}),
      uid: 'secret-uid-1',
      resourceVersion: '7'
    },
    data: {
      ...(prepared.secretManifest.data || {}),
      'context.json': Buffer.from(JSON.stringify(prepared.context, null, 2), 'utf8').toString('base64'),
      ...extraData
    }
  };
}

function buildWakeupPrompt({ sessionId = 's-demo', namespace = 'demo', round = 1, workerIndex = 1, jobName, timeout = false } = {}) {
  return [
    `Session ID: ${sessionId}`,
    `Namespace: ${namespace}`,
    `Session Secret Label: harikube.info/session=${sessionId}`,
    `Round: ${round}`,
    `Worker Index: ${workerIndex}`,
    ...(jobName ? [`Job: ${jobName}`] : []),
    ...(timeout ? ['Worker timed out.'] : [])
  ].join('\n');
}

function createFakeKubectl(initialSecrets = {}, options = {}) {
  const secrets = new Map(Object.entries(initialSecrets));
  const triggers = [];
  const calls = [];
  let nextResourceVersion = 10;
  let remainingReplaceConflicts = Math.max(0, Math.trunc(options.replaceConflicts || 0));

  const clone = value => JSON.parse(JSON.stringify(value));
  const parseInput = input => (input ? JSON.parse(input) : undefined);
  const normalizeItems = payload => {
    if (!payload) return [];
    return payload.kind === 'List' ? payload.items || [] : [payload];
  };

  const tool = async ({ command, namespace, input }) => {
    calls.push({ command, namespace, input });

    const getSecretByName = command.match(/^get secret ([^\s]+) -o json --ignore-not-found$/);
    if (getSecretByName) {
      const secret = secrets.get(`${namespace}/${getSecretByName[1]}`);
      return { stdout: secret ? JSON.stringify(clone(secret)) : '', stderr: '', commandExecuted: command };
    }

    if (/^get secret -l /.test(command) && / -o json$/.test(command)) {
      const selector = command.match(/^get secret -l (.+) -o json$/)?.[1] || '';
      const [key, value] = selector.split('=');
      const items = [...secrets.values()].filter(secret => secret.metadata?.namespace === namespace && secret.metadata?.labels?.[key] === value);
      return {
        stdout: JSON.stringify({ apiVersion: 'v1', kind: 'List', items: clone(items) }),
        stderr: '',
        commandExecuted: command
      };
    }

    if (command === 'apply -f -') {
      const payload = parseInput(input);
      for (const item of normalizeItems(payload)) {
        if (item.kind === 'Secret') {
          const key = `${namespace}/${item.metadata.name}`;
          const existing = secrets.get(key);
          const secret = clone(item);
          secret.metadata = {
            ...(secret.metadata || {}),
            namespace,
            uid: secret.metadata?.uid || existing?.metadata?.uid || 'secret-uid-1',
            resourceVersion: String(nextResourceVersion++)
          };
          secrets.set(key, secret);
        } else if (item.kind === 'PiTrigger') {
          triggers.push(clone(item));
        }
      }
      return { stdout: '', stderr: '', commandExecuted: command };
    }

    if (command === 'replace -f -') {
      if (remainingReplaceConflicts > 0) {
        remainingReplaceConflicts -= 1;
        throw {
          exitCode: 1,
          stdout: '',
          stderr: 'Error from server (Conflict): the object has been modified; please apply your changes to the latest version and try again'
        };
      }

      const payload = parseInput(input);
      const key = `${namespace}/${payload.metadata.name}`;
      const existing = secrets.get(key);
      if (!existing) {
        throw new Error(`missing secret for replace: ${key}`);
      }
      const secret = clone(payload);
      secret.metadata = {
        ...(secret.metadata || {}),
        namespace,
        uid: existing.metadata.uid,
        resourceVersion: String(nextResourceVersion++)
      };
      secrets.set(key, secret);
      return { stdout: '', stderr: '', commandExecuted: command };
    }

    const getJob = command.match(/^get job ([^\s]+) -o json --ignore-not-found$/);
    if (getJob) {
      return {
        stdout: JSON.stringify({ status: { conditions: [{ type: 'Complete', status: 'True', message: 'done' }] } }),
        stderr: '',
        commandExecuted: command
      };
    }

    if (/^get events --field-selector /.test(command)) {
      return {
        stdout: JSON.stringify({ items: [{ reason: 'Completed', message: 'Job finished.' }] }),
        stderr: '',
        commandExecuted: command
      };
    }

    throw new Error(`unexpected kubectl command: ${command}`);
  };

  return {
    kubectl: tool,
    calls,
    secrets,
    triggers
  };
}

test('resolveSubagentDefaults prefers injected runtime defaults over legacy prompt prefixes', () => {
  const runtimeDefaults = sampleDefaults();
  const promptDefaults = { ...sampleDefaults(), namespace: 'legacy' };
  const result = resolveSubagentDefaults({
    prompt: `${buildDefaultsPrefix(promptDefaults)}\nDo the work.`,
    env: {
      PI_SUBAGENT_DEFAULTS_BASE64: Buffer.from(JSON.stringify(runtimeDefaults), 'utf8').toString('base64')
    }
  });

  assert.equal(result.source, 'runtime');
  assert.equal(result.subAgentDefaults.namespace, 'demo');
  assert.equal(result.cleanedPrompt, 'Do the work.');
});

test('chooseExecutionMode selects headless for context-heavy single-stream work below delegation thresholds', () => {
  const result = chooseExecutionMode({
    task: 'Run one bounded audit with lots of context',
    estimatedSteps: 3,
    estimatedMinutes: 1,
    independentWorkUnits: 1,
    contextHeavy: true,
    subAgentDefaults: sampleDefaults()
  });

  assert.equal(result.recommendedAction, 'stay-local');
  assert.equal(result.selectedMode, 'headless');
  assert.equal(result.workerTimeout, '10m');
  assert.equal(result.defaultsSource, 'provided');
});

test('orchestrateSubagentExecution returns a planned headless decision without writing cluster state', async () => {
  const fake = createFakeKubectl();
  const result = await orchestrateSubagentExecution(
    {
      task: 'Run one bounded audit with lots of context',
      estimatedSteps: 3,
      estimatedMinutes: 1,
      independentWorkUnits: 1,
      contextHeavy: true,
      subAgentDefaults: sampleDefaults()
    },
    { kubectl: fake.kubectl }
  );

  assert.equal(result.status, 'planned');
  assert.equal(result.selectedMode, 'headless');
  assert.equal(fake.calls.length, 0);
});

test('orchestrateSubagentExecution reports missing delegation input when delegation is required', async () => {
  const result = await orchestrateSubagentExecution({
    task: 'Investigate, implement, and verify a multi-part production bug across separate areas',
    estimatedSteps: 9,
    estimatedMinutes: 12,
    independentWorkUnits: 3,
    subAgentDefaults: sampleDefaults()
  });

  assert.equal(result.status, 'needs-delegation-input');
  assert.equal(result.selectedMode, 'delegate');
  assert.match(result.reason, /delegation.nextStep/i);
});

test('orchestrateSubagentExecution delegates and hibernates when a worker split is supplied', async () => {
  const fake = createFakeKubectl();
  const result = await orchestrateSubagentExecution(
    {
      task: 'Investigate, implement, and verify a multi-part production bug across separate areas',
      estimatedSteps: 9,
      estimatedMinutes: 12,
      independentWorkUnits: 2,
      subAgentDefaults: sampleDefaults(),
      delegation: {
        originalPrompt: 'Ship it',
        cleanedPrompt: 'Ship it',
        nextStep: 'merge worker results',
        workers: [
          { index: 1, task: 'Analyze', expectedResult: 'summary', outputLocation: 'out/1.md' },
          { index: 2, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/2.md' }
        ],
        sessionId: 's-demo',
        round: 1
      }
    },
    { kubectl: fake.kubectl }
  );

  assert.equal(result.status, 'hibernated');
  assert.equal(result.selectedMode, 'delegate');
  assert.equal(result.decision.selectedMode, 'delegate');
  assert.equal(result.pendingSubagents, 2);
  assert.equal(fake.triggers.length, 2);
});

test('hibernateSession writes the session Secret first, then emits Secret-owned PiTriggers', async () => {
  const fake = createFakeKubectl();
  const result = await hibernateSession(
    {
      subAgentDefaults: sampleDefaults(),
      originalPrompt: 'Ship it',
      cleanedPrompt: 'Ship it',
      nextStep: 'merge worker results',
      workers: [
        { index: 1, task: 'Analyze', expectedResult: 'summary', outputLocation: 'out/1.md' },
        { index: 2, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/2.md' }
      ],
      sessionId: 's-demo',
      round: 1
    },
    { kubectl: fake.kubectl }
  );

  assert.equal(result.status, 'hibernated');
  assert.equal(result.pendingSubagents, 2);
  assert.equal(result.triggerManifests.length, 2);
  assert.deepEqual(
    result.operations.map(operation => operation.type),
    ['apply-secret', 'apply-secret-owned-context', 'apply-triggers']
  );
  assert.equal(fake.triggers.length, 2);
  assert.equal(fake.triggers[0].metadata.ownerReferences[0].kind, 'Secret');
  assert.equal(fake.secrets.get('demo/pi-session-s-demo').metadata.uid, 'secret-uid-1');
});

test('handleSessionWakeup fetches state, records the worker result, and replaces the Secret', async () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1,
    existingSecretJson: JSON.stringify({
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'pi-session-s-demo',
        namespace: 'demo',
        uid: 'secret-uid-1',
        resourceVersion: '7'
      },
      type: 'Opaque',
      data: {}
    })
  });
  const storedSecret = buildStoredSecret(prepared);
  const fake = createFakeKubectl({ 'demo/pi-session-s-demo': storedSecret });

  const result = await handleSessionWakeup(
    {
      prompt: buildWakeupPrompt({ jobName: 'worker-1' }),
      workerSummary: 'Patch applied.'
    },
    { kubectl: fake.kubectl }
  );

  assert.equal(result.action, 'merge');
  assert.equal(result.pendingCount, 0);
  assert.equal(result.write.type, 'replace-secret');
  assert.equal(result.result.outcome, 'succeeded');
  assert.equal(result.fetched.job, true);
  const storedResult = JSON.parse(
    Buffer.from(fake.secrets.get('demo/pi-session-s-demo').data['result-r1-w1.json'], 'base64').toString('utf8')
  );
  assert.equal(storedResult.outcome, 'succeeded');
});

test('handleSessionWakeup retries after Secret replace conflicts', async () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1,
    existingSecretJson: JSON.stringify({
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'pi-session-s-demo',
        namespace: 'demo',
        uid: 'secret-uid-1',
        resourceVersion: '7'
      },
      type: 'Opaque',
      data: {}
    })
  });
  const storedSecret = buildStoredSecret(prepared);
  const fake = createFakeKubectl({ 'demo/pi-session-s-demo': storedSecret }, { replaceConflicts: 1 });

  const result = await handleSessionWakeup(
    {
      prompt: buildWakeupPrompt({ jobName: 'worker-1' }),
      workerSummary: 'Patch applied.',
      maxAttempts: 3
    },
    { kubectl: fake.kubectl }
  );

  assert.equal(result.action, 'merge');
  assert.equal(result.attempts, 2);
  assert.equal(fake.calls.filter(call => call.command === 'replace -f -').length, 2);
  assert.ok(fake.calls.filter(call => /^get secret -l /.test(call.command)).length >= 2);
});

test('handleSessionWakeup timeout path skips Job and Event lookups', async () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1,
    existingSecretJson: JSON.stringify({
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'pi-session-s-demo',
        namespace: 'demo',
        uid: 'secret-uid-1',
        resourceVersion: '7'
      },
      type: 'Opaque',
      data: {}
    })
  });
  const storedSecret = buildStoredSecret(prepared);
  const fake = createFakeKubectl({ 'demo/pi-session-s-demo': storedSecret });

  const result = await handleSessionWakeup(
    {
      prompt: buildWakeupPrompt({ jobName: 'worker-1', timeout: true }),
      workerSummary: 'Timed out.'
    },
    { kubectl: fake.kubectl }
  );

  assert.equal(result.fetched.job, false);
  assert.equal(result.fetched.events, false);
  assert.equal(result.result.outcome, 'completed-with-timeouts');
  assert.equal(fake.calls.some(call => /^get job /.test(call.command)), false);
  assert.equal(fake.calls.some(call => /^get events /.test(call.command)), false);
});
