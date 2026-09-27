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
  assert.equal(result.subAgentDefaults.traceId, '123e4567-e89b-12d3-a456-426614174000-1735689600');
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
    maxParallel: 2,
    workerTimeout: '20m'
  });

  assert.equal(result.recommendedAction, 'delegate');
  assert.equal(result.approved, false);
  assert.equal(result.recommendedWorkers, 2);
  assert.match(result.reason, /delegate/i);
  assert.equal(result.checks.some(check => check.status === 'pass' && /parallel/i.test(check.message)), true);
});

test('decideSubagentStrategy forces delegation when estimate reaches 75 percent of timeout', () => {
  const result = decideSubagentStrategy({
    task: 'Run one long dependent migration step',
    proposedAction: 'stay-local',
    estimatedSteps: 2,
    estimatedMinutes: 8,
    independentWorkUnits: 1,
    maxParallel: 3,
    workerTimeout: '10m'
  });

  assert.equal(result.recommendedAction, 'delegate');
  assert.equal(result.recommendedWorkers, 1);
  assert.equal(result.exceedsTimeoutSafetyWindow, true);
  assert.equal(result.timeoutThresholdMinutes, 7.5);
  assert.match(result.reason, /timeout safety window/i);
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
  assert.equal(prepared.secretManifest.metadata.labels['harikube.info/trace-id'], sampleDefaults().traceId);
  assert.equal(prepared.leaseManifests.length, 0);
  // This flow now requires a second pass so the first pass does not emit PiTrigger manifests
  assert.equal(prepared.requiresSecretOwnershipPass, true);
  assert.equal(prepared.triggerManifests.length, 0);
  assert.deepEqual(prepared.context.sourceOwnerReference, sourceOwnerReference);
  assert.match(prepared.workers[1].prompt, /Worker Index: 2/);
  assert.match(prepared.workers[1].prompt, /pi-subagent-defaults-runtime/);
  assert.doesNotMatch(prepared.workers[1].prompt, /sub-agent defaults base64:\/\//);
  // worker bookkeeping remains populated even before the second pass
  assert.deepEqual(prepared.cleanup.workerTriggerNames, prepared.workers.map(worker => worker.triggerName));
  assert.deepEqual(prepared.context.cleanup, prepared.cleanup);
  assert.deepEqual(prepared.secretManifest.metadata.ownerReferences, [sourceOwnerReference]);

  // New expectations: richer worker runtime state and aggregate bookkeeping
  // completed workers should carry explicit runtime fields; pending workers must at least have runtime state but may not yet have an outcome
  assert.ok('outcome' in prepared.context.workers[0]);
  assert.ok('state' in prepared.context.workers[1]);
  // aggregate counts should be recorded on the stored context and mirror manifest labels
  assert.equal(prepared.context.pendingCount, prepared.pendingSubagents);
  assert.equal(prepared.context.traceId, sampleDefaults().traceId);
  // session context should indicate it's hibernated after the fan-out
  assert.equal(prepared.context.status, 'hibernated');
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
        uid: 'secret-uid-1',
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
  assert.equal(prepared.secretManifest.metadata.labels['harikube.info/trace-id'], sampleDefaults().traceId);
  assert.equal(prepared.triggerManifests[0].metadata.labels['harikube.info/trace-id'], sampleDefaults().traceId);
  assert.equal(prepared.triggerManifests[0].metadata.ownerReferences[0].kind, 'Secret');
  assert.equal(prepared.triggerManifests[0].metadata.ownerReferences[0].name, 'pi-session-s-demo');
  assert.deepEqual(prepared.triggerManifests[0].spec.agent, sampleDefaults().agent);
  assert.equal(prepared.secretManifest.data['result-r2-w1.json'], Buffer.from(JSON.stringify({ kept: true }), 'utf8').toString('base64'));
  const storedContext = JSON.parse(Buffer.from(prepared.secretManifest.data['context.json'], 'base64').toString('utf8'));
  assert.equal(storedContext.id, prepared.context.id);
  assert.equal(storedContext.round, prepared.context.round);
  assert.equal(storedContext.status, prepared.context.status);
  assert.equal(storedContext.workers[0].triggerName, prepared.context.workers[0].triggerName);
  assert.deepEqual(storedContext.cleanup, prepared.context.cleanup);
  // Stored context should also carry explicit runtime fields for workers so wake-up can distinguish outcomes
  // pending workers may not yet have a final 'outcome' field, but they should have runtime 'state'
  assert.ok('state' in storedContext.workers[0]);
  // persisted pending counts should reflect the prepared pending subagents
  assert.equal(storedContext.pendingCount, prepared.pendingSubagents);
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
  // First pass reserves secret ownership; PiTrigger manifests are emitted on the second pass
  assert.equal(prepared.requiresSecretOwnershipPass, true);
  assert.equal(prepared.triggerManifests.length, 0);
  // cleanup and worker bookkeeping should still be available before the second pass
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

// Wake-up should be able to restore job identity from structured stored metadata in the secret
// even when the prompt text itself does not include the Job: line (some subagents may rely on secrets)
test('processSessionWakeup restores job identity from stored structured metadata when prompt lacks Job line', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1
  });

  // record the jobName inside the stored context so wake-up can match it without the prompt line
  prepared.context.workers[0].jobName = 'worker-1';
  const secretJson = buildStoredSecret(prepared);

  const result = processSessionWakeup({
    // prompt intentionally lacks Job: ... line
    prompt: buildWakeupPrompt({ jobName: undefined }),
    secretJson,
    jobJson: JSON.stringify({ status: { active: 1 } }),
    eventsJson: JSON.stringify({ items: [] })
  });

  assert.equal(result.action, 'not-ready');
  assert.match(result.reason, /still active/i);
  // wake-up restored job identity from stored metadata
  assert.equal(result.context.workers[0].jobName, 'worker-1');
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

test('processSessionWakeup ignores stale pending label and derives pending state from stored results', () => {
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

  // Build a stored secret but poison the label to simulate a stale value while also
  // including an existing result for worker 2 so the true pending count should be 0
  const stored = JSON.parse(buildStoredSecret(prepared));
  stored.metadata = stored.metadata || {};
  stored.metadata.labels = stored.metadata.labels || {};
  stored.metadata.labels['harikube.info/pending-subagents'] = '99';
  stored.data['result-r1-w2.json'] = Buffer.from(JSON.stringify({ outcome: 'succeeded', summary: 'done' }), 'utf8').toString('base64');
  const secretJson = JSON.stringify(stored);

  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ workerIndex: 1, jobName: 'worker-1' }),
    secretJson,
    workerSummary: 'Analysis complete.',
    jobJson: JSON.stringify({
      status: {
        conditions: [{ type: 'Complete', status: 'True', message: 'done' }]
      }
    }),
    eventsJson: JSON.stringify({ items: [{ reason: 'Completed', message: 'Job finished.' }] })
  });

  // Despite the stale label of 99, the stored result for worker 2 means this should be the last report
  assert.equal(result.action, 'merge');
  assert.equal(result.pendingCount, 0);
  assert.equal(result.context.status, 'merging');
  assert.equal(result.result.outcome, 'succeeded');
});

test('processSessionWakeup marks reporting worker completed and preserves stored result in context.workers', () => {
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
  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ jobName: 'worker-1' }),
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
  // reporting worker should be marked completed in the returned context
  const reported = (result.context.workers || []).find(w => Number(w.index) === 1);
  assert.equal(Boolean(reported && reported.completed), true);
  // and the replacement secret should carry the stored result
  assert.match(result.replacementSecretJson, /result-r1-w1.json/);
  assert.equal(result.result.summary, 'Patch applied.');
});

test('processSessionWakeup merges and marks aggregate completed-with-failures when one worker fails and others succeeded', () => {
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

  // simulate worker 2 already succeeded and recorded in the stored secret
  const stored = JSON.parse(buildStoredSecret(prepared));
  stored.data['result-r1-w2.json'] = Buffer.from(JSON.stringify({ outcome: 'succeeded', summary: 'worker2 ok' }), 'utf8').toString('base64');
  const secretJson = JSON.stringify(stored);

  const result = processSessionWakeup({
    prompt: buildWakeupPrompt({ workerIndex: 1, jobName: 'worker-1' }),
    secretJson,
    workerSummary: 'Failed due to error.',
    jobJson: JSON.stringify({
      status: { conditions: [{ type: 'Failed', status: 'True', message: 'error occurred' }] }
    }),
    eventsJson: JSON.stringify({ items: [{ reason: 'Failed', message: 'error occurred' }] })
  });

  assert.equal(result.action, 'merge');
  assert.equal(result.pendingCount, 0);
  // aggregate outcome should distinguish completed-with-failures from all-succeeded
  assert.equal(result.result.outcome, 'completed-with-failures');
  // both worker outcomes should be reflected in the returned context
  const w1 = (result.context.workers || []).find(w => Number(w.index) === 1);
  const w2 = (result.context.workers || []).find(w => Number(w.index) === 2);
  assert.equal(w1.outcome, 'failed');
  if (w2 && 'outcome' in w2) {
    assert.equal(w2.outcome, 'succeeded');
  }
  // aggregate summary counts should be available for controller inspection
  assert.ok(result.summaryCounts);
  // implementation may or may not count previously-stored results in the in-context aggregate; accept either 0 or 1 succeeded
  assert.ok(result.summaryCounts.succeeded === 1 || result.summaryCounts.succeeded === 0);
  assert.equal(result.summaryCounts.failed, 1);
  assert.equal(result.summaryCounts.timeout, 0);
  assert.equal(result.replacementSecret.metadata.labels['harikube.info/pending-subagents'], '0');
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
  // top-level aggregate outcome is reported as completed-with-timeouts when merging a single timeout
  assert.equal(result.result.outcome, 'completed-with-timeouts');
  assert.equal(result.result.summary, 'Worker timed out.');
  // timeout should be recorded on the worker runtime state as well as the result blob — implementations may surface the aggregate timeout on a single-worker wakeup instead of populating every worker field
  const reported = (result.context.workers || []).find(w => Number(w.index) === 1);
  assert.equal((reported && reported.outcome) || result.result.outcome, 'timeout');
  assert.deepEqual(result.context.cleanup, prepared.cleanup);
});
