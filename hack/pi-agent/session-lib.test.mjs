import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDefaultsPrefix,
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

test('extractSubAgentDefaults decodes and strips the prompt prefix', () => {
  const defaults = sampleDefaults();
  const prompt = `${buildDefaultsPrefix(defaults)}\nDo the work.`;
  const result = extractSubAgentDefaults(prompt, 'fallback');

  assert.equal(result.found, true);
  assert.equal(result.cleanedPrompt, 'Do the work.');
  assert.equal(result.subAgentDefaults.namespace, 'demo');
  assert.equal(result.subAgentDefaults.maxParallel, 3);
});

test('prepareSessionHibernation builds context and manifests for pending workers', () => {
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
    round: 2
  });

  assert.equal(prepared.sessionId, 's-demo');
  assert.equal(prepared.round, 2);
  assert.equal(prepared.pendingSubagents, 1);
  assert.equal(prepared.secretManifest.metadata.labels['harikube.info/pending-subagents'], '1');
  assert.equal(prepared.leaseManifests.length, 1);
  assert.equal(prepared.triggerManifests.length, 1);
  assert.match(prepared.workers[1].prompt, /Worker Index: 2/);
  assert.match(prepared.triggerManifests[0].metadata.annotations['harikube.info/worker-prompt'], /Task:/);
});

test('processSessionWakeup records a finished worker and marks merge when last worker reports', () => {
  const prepared = prepareSessionHibernation({
    subAgentDefaults: sampleDefaults(),
    originalPrompt: 'Ship it',
    cleanedPrompt: 'Ship it',
    nextStep: 'merge worker results',
    workers: [{ index: 1, task: 'Implement', expectedResult: 'patch', outputLocation: 'out/1.md' }],
    sessionId: 's-demo',
    round: 1
  });

  const secretJson = JSON.stringify({
    ...prepared.secretManifest,
    data: {
      'context.json': Buffer.from(JSON.stringify(prepared.context, null, 2), 'utf8').toString('base64')
    }
  });

  const prompt = [
    'Session ID: s-demo',
    'Namespace: demo',
    'Session Secret Label: harikube.info/session=s-demo',
    'Round: 1',
    'Worker Index: 1',
    'Job: worker-1'
  ].join('\n');

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
  assert.match(result.replacementSecretJson, /result-r1-w1.json/);
});
