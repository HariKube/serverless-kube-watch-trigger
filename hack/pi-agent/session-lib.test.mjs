import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDefaultsPrefix,
  decideSubagentStrategy,
  extractSubAgentDefaults,
  prepareSessionHibernation,
  processSessionWakeup
} from './session-lib.mjs';

function sampleDefaults() {
  return {
    namespace: 'demo',
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
  return JSON.stringify({
    ...prepared.secretManifest,
    data: {
      ...(prepared.secretManifest.data || {}),
      'context.json': Buffer.from(JSON.stringify(prepared.context, null, 2), 'utf8').toString('base64'),
      ...extraData
    }
  });
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

test('extractSubAgentDefaults decodes and strips the prompt prefix', () => {
  const defaults = sampleDefaults();
  const prompt = `${buildDefaultsPrefix(defaults)}\nDo the work.`;
  const result = extractSubAgentDefaults(prompt, 'fallback');

  assert.equal(result.found, true);
  assert.equal(result.cleanedPrompt, 'Do the work.');
  assert.equal(result.subAgentDefaults.namespace, 'demo');
  assert.equal(result.subAgentDefaults.maxParallel, 3);
});

test('decideSubagentStrategy recommends staying local for short single-stream work', () => {
  const result = decideSubagentStrategy({
    task: 'Update one sentence in a markdown file',
    proposedAction: 'stay-local',
    estimatedSteps: 3,
    estimatedMinutes: 1,
    independentWorkUnits: 1,
    maxParallel: 4
  });

  assert.equal(result.recommendedAction, 'stay-local');
  assert.equal(result.approved, true);
  assert.equal(result.recommendedWorkers, 0);
  assert.equal(result.confidence, 'high');
  assert.equal(result.checks.at(-1)?.status, 'pass');
});

test('decideSubagentStrategy rejects keeping large parallel work local', () => {
  const result = decideSubagentStrategy({
    task: 'Investigate, implement, and verify a multi-part production bug across separate areas',
    proposedAction: 'stay-local',
    estimatedSteps: 9,
    estimatedMinutes: 12,
    independentWorkUnits: 3,
    maxParallel: 2
  });

  assert.equal(result.recommendedAction, 'delegate');
  assert.equal(result.approved, false);
  assert.equal(result.recommendedWorkers, 2);
  assert.match(result.reason, /delegate/i);
  assert.equal(result.checks.some(check => check.status === 'pass' && /parallel/i.test(check.message)), true);
});

test('prepareSessionHibernation builds context and manifests for pending workers', () => {
  const sourceOwnerReference = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    name: 'source-config',
    uid: 'source-uid-1'
  };

  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    workSoFar: 'planned',
    nextStep: 'merge worker results',
    workers: [
      { index: 1, task: 'Analyze', expectedResult: 'summary', outputLocation: 'out/1.md', completed: true, result: 'done' },
      { index: 2, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/2.md' }
    ],
    sessionId: 's-demo',
    round: 2,
    sourceOwnerReference
  });

  assert.equal(prepared.sessionId, 's-demo');
  assert.equal(prepared.round, 2);
  assert.equal(prepared.pendingSubagents, 1);
  assert.equal(prepared.secretManifest.metadata.labels['harikube.info/pending-subagents'], '1');
  assert.equal(prepared.leaseManifests.length, 0);
  assert.equal(prepared.triggerManifests.length, 1);
  assert.deepEqual(prepared.context.sourceOwnerReference, sourceOwnerReference);
  assert.match(prepared.workers[1].prompt, /Worker Index: 2/);
  assert.equal(prepared.triggerManifests[0].metadata.name, prepared.workers[1].triggerName);
  assert.deepEqual(prepared.triggerManifests[0].metadata.annotations, {
    'harikube.info/session-secret': 'pi-session-s-demo',
    'harikube.info/output-location': 'out/2.md'
  });
  assert.deepEqual(prepared.triggerManifests[0].spec.resource, { apiVersion: 'batch/v1', kind: 'Job' });
  assert.deepEqual(prepared.triggerManifests[0].spec.labelSelectors, [
    `triggers.harikube.info/pitrigger-name=${prepared.workers[1].triggerName}`
  ]);
  assert.deepEqual(prepared.triggerManifests[0].spec.eventTypes, ['ADDED', 'MODIFIED']);
  assert.match(prepared.triggerManifests[0].spec.eventFilter, /^or \.status\.completionTime/);
  assert.match(prepared.triggerManifests[0].spec.eventFilter, /"Complete"/);
  assert.match(prepared.triggerManifests[0].spec.eventFilter, /"Failed"/);
  assert.equal(prepared.triggerManifests[0].spec.timeout, '24h');
  assert.deepEqual(prepared.cleanup.workerTriggerNames, prepared.workers.map(worker => worker.triggerName));
  assert.deepEqual(prepared.context.cleanup, prepared.cleanup);
  assert.deepEqual(prepared.secretManifest.metadata.ownerReferences, [sourceOwnerReference]);
  assert.deepEqual(prepared.triggerManifests[0].metadata.ownerReferences, [sourceOwnerReference]);
});


test('prepareSessionHibernation updates an existing secret manifest when the session secret already exists', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 3,
    existingSecretJson: JSON.stringify({
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'pi-session-s-demo',
        namespace: 'demo',
        resourceVersion: '42',
        labels: {
          'custom-label': 'keep-me'
        }
      },
      type: 'Opaque',
      data: {
        'result-r2-w1.json': Buffer.from(JSON.stringify({ kept: true }), 'utf8').toString('base64')
      }
    })
  });

  assert.equal(prepared.secretManifest.metadata.resourceVersion, '42');
  assert.equal(prepared.secretManifest.metadata.labels['custom-label'], 'keep-me');
  assert.equal(prepared.secretManifest.metadata.labels['harikube.info/round'], '3');
  assert.equal(prepared.secretManifest.data['result-r2-w1.json'], Buffer.from(JSON.stringify({ kept: true }), 'utf8').toString('base64'));
  const storedContext = JSON.parse(Buffer.from(prepared.secretManifest.data['context.json'], 'base64').toString('utf8'));
  assert.equal(storedContext.id, prepared.context.id);
  assert.equal(storedContext.round, prepared.context.round);
  assert.equal(storedContext.status, prepared.context.status);
  assert.equal(storedContext.workers[0].triggerName, prepared.context.workers[0].triggerName);
  assert.deepEqual(storedContext.cleanup, prepared.context.cleanup);
});

test('processSessionWakeup returns secret-not-found when the session secret is gone', () => {
  const prompt = [
    'Session ID: s-demo',
    'Namespace: demo',
    'Session Secret Label: harikube.info/session=s-demo',
    'Round: 1',
    'Worker Index: 1'
  ].join('\n');

  const result = processSessionWakeup({
    prompt,
    secretJson: JSON.stringify({
      kind: 'Status',
      reason: 'NotFound',
      message: 'secrets "pi-session-s-demo" not found'
    })
  });

  assert.equal(result.action, 'secret-not-found');
  assert.match(result.reason, /not found/i);
  assert.match(result.exitReason, /goodbye/i);
});

test('processSessionWakeup records a finished worker, preserves cleanup state, and marks merge when last worker reports', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1
  });

  const secretJson = buildStoredSecret(prepared);
  const prompt = buildWakeupPrompt({ jobName: 'worker-1' });

  const result = processSessionWakeup({
    prompt,
    secretJson,
    workerSummary: 'Patch applied.',
    jobJson: JSON.stringify({
      status: {
        conditions: [{ type: 'Complete', status: 'True', message: 'done' }]
      }
    }),
    eventsJson: JSON.stringify({ items: [{ reason: 'Completed', message: 'Job finished.' }] })
  });

  assert.equal(result.action, 'merge');
  assert.equal(result.pendingCount, 0);
  assert.equal(result.result.outcome, 'succeeded');
  assert.equal(result.context.status, 'merging');
  assert.deepEqual(result.cleanup, prepared.cleanup);
  assert.deepEqual(result.context.cleanup, prepared.cleanup);
  assert.equal(result.context.workers[0].triggerName, prepared.context.workers[0].triggerName);
  assert.equal(result.replacementSecret.metadata.labels['harikube.info/pending-subagents'], '0');
  assert.match(result.replacementSecretJson, /result-r1-w1.json/);
});

test('extractSubAgentDefaults accepts the defauls typo in the prompt prefix', () => {
  const defaults = sampleDefaults();
  const prompt = `${buildDefaultsPrefix(defaults).replace('defaults', 'defauls')}\nDo the work.`;
  const result = extractSubAgentDefaults(prompt, 'fallback');

  assert.equal(result.found, true);
  assert.equal(result.cleanedPrompt, 'Do the work.');
  assert.equal(result.subAgentDefaults.namespace, 'demo');
});

test('prepareSessionHibernation fans out one PiTrigger per pending worker and watches Jobs by trigger label', () => {
  const prepared = prepareSessionHibernation({
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
  });

  assert.equal(prepared.pendingSubagents, 2);
  assert.equal(prepared.leaseManifests.length, 0);
  assert.equal(prepared.triggerManifests.length, 2);
  assert.notEqual(prepared.triggerManifests[0].metadata.name, prepared.triggerManifests[1].metadata.name);
  assert.deepEqual(
    prepared.triggerManifests.map(trigger => trigger.metadata.name),
    prepared.workers.map(worker => worker.triggerName)
  );
  assert.deepEqual(
    prepared.triggerManifests.map(trigger => trigger.spec.resource),
    prepared.workers.map(() => ({ apiVersion: 'batch/v1', kind: 'Job' }))
  );
  assert.deepEqual(
    prepared.triggerManifests.map(trigger => trigger.spec.maxJobs),
    [1, 1]
  );
  assert.deepEqual(
    prepared.triggerManifests.map(trigger => trigger.spec.timeout),
    ['24h', '24h']
  );
  assert.deepEqual(
    prepared.triggerManifests.map(trigger => trigger.spec.labelSelectors[0]),
    prepared.workers.map(worker => `triggers.harikube.info/pitrigger-name=${worker.triggerName}`)
  );
  assert.equal(prepared.triggerManifests.every(trigger => /\.status\.completionTime/.test(trigger.spec.eventFilter)), true);
  assert.deepEqual(prepared.cleanup.workerTriggerNames, prepared.workers.map(worker => worker.triggerName));
});

test('processSessionWakeup skips prompts without wake-up metadata', () => {
  const result = processSessionWakeup({ prompt: 'hello there' });

  assert.equal(result.action, 'skip');
  assert.match(result.reason, /wake-up/i);
});

test('processSessionWakeup returns not-ready while the worker job is still active', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1
  });

  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ jobName: 'worker-1' }),
    secretJson: buildStoredSecret(prepared),
    jobJson: JSON.stringify({ status: { active: 1 } }),
    eventsJson: JSON.stringify({ items: [] })
  });

  assert.equal(result.action, 'not-ready');
  assert.match(result.reason, /still active/i);
  assert.equal(result.context.status, 'hibernated');
  assert.deepEqual(result.cleanup, prepared.cleanup);
});

test('processSessionWakeup returns stale-round when prompt metadata does not match the stored context', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1
  });

  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ round: 2, jobName: 'worker-1' }),
    secretJson: buildStoredSecret(prepared)
  });

  assert.equal(result.action, 'stale-round');
  assert.match(result.reason, /does not match/i);
});

test('processSessionWakeup returns already-reported when the worker result key already exists', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1
  });

  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ jobName: 'worker-1' }),
    secretJson: buildStoredSecret(prepared, {
      'result-r1-w1.json': Buffer.from(JSON.stringify({ outcome: 'succeeded' }), 'utf8').toString('base64')
    }),
    jobJson: JSON.stringify({
      status: {
        conditions: [{ type: 'Complete', status: 'True', message: 'done' }]
      }
    }),
    eventsJson: JSON.stringify({ items: [{ reason: 'Completed', message: 'Job finished.' }] })
  });

  assert.equal(result.action, 'already-reported');
  assert.match(result.reason, /already reported/i);
  assert.deepEqual(result.cleanup, prepared.cleanup);
});

test('processSessionWakeup records one worker and waits when other workers are still pending', () => {
  const prepared = prepareSessionHibernation({
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
  });

  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ workerIndex: 1, jobName: 'worker-1' }),
    secretJson: buildStoredSecret(prepared),
    workerSummary: 'Analysis complete.',
    jobJson: JSON.stringify({
      status: {
        conditions: [{ type: 'Complete', status: 'True', message: 'done' }]
      }
    }),
    eventsJson: JSON.stringify({ items: [{ reason: 'Completed', message: 'Job finished.' }] })
  });

  assert.equal(result.action, 'wait');
  assert.equal(result.pendingCount, 1);
  assert.equal(result.context.status, 'hibernated');
  assert.equal(result.result.outcome, 'succeeded');
  assert.deepEqual(result.cleanup, prepared.cleanup);
  assert.equal(result.context.workers[0].triggerName, prepared.context.workers[0].triggerName);
  assert.match(result.exitReason, /1 pending/);
});

test('processSessionWakeup records timeout outcomes when the prompt indicates a timeout', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1
  });

  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ jobName: 'worker-1', timeout: true }),
    secretJson: buildStoredSecret(prepared)
  });

  assert.equal(result.action, 'merge');
  assert.equal(result.result.outcome, 'timeout');
  assert.equal(result.result.summary, 'Worker timed out.');
  assert.deepEqual(result.context.cleanup, prepared.cleanup);
});
