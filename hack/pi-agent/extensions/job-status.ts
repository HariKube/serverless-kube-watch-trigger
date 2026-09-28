import { Type } from 'typebox';
import { execKubectlCommand } from './kubectl-lib.mjs';

export default function registerJobStatus(pi) {
  pi.registerTool({
    name: 'job_status',
    label: 'job_status',
    description:
      'Fetch a Job, its related Events, and Pods (label job-name=<job>) and produce a compact diagnostics summary for timeouts/failures.',
    parameters: Type.Object({
      jobName: Type.String({ description: 'Name of the Job to inspect.' }),
      namespace: Type.Optional(Type.String({ description: 'Namespace to query. Defaults to the Pod serviceaccount namespace.' })),
      includeRawJob: Type.Optional(Type.Boolean({ description: 'Include the raw Job JSON payload in the result. Default: false.' })),
      includeRawEvents: Type.Optional(Type.Boolean({ description: 'Include raw Events JSON payload. Default: false.' })),
      includeRawPods: Type.Optional(Type.Boolean({ description: 'Include raw Pods JSON payload. Default: false.' }))
    }),

    async execute(_toolCallId, params) {
      const jobName = String(params.jobName || '').trim();
      const namespace = params.namespace;
      if (!jobName) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'error', message: 'jobName is required' }, null, 2) }],
          details: { status: 'error', message: 'jobName is required' }
        };
      }

      // Helpers to run kubectl reads and parse JSON safely
      async function safeGet(command) {
        try {
          const res = await execKubectlCommand({ command, namespace });
          return { ok: true, stdout: res.stdout, stderr: res.stderr, commandExecuted: res.commandExecuted };
        } catch (err) {
          return { ok: false, error: err };
        }
      }

      const results = {
        job: null,
        events: null,
        pods: null
      };

      // Fetch Job
      const jobResp = await safeGet(`get job ${jobName} -o json`);
      if (jobResp.ok) {
        try {
          results.job = JSON.parse(jobResp.stdout || '{}');
        } catch (e) {
          results.job = { parseError: e.message, raw: jobResp.stdout };
        }
      } else {
        results.job = { error: jobResp.error?.message || jobResp.error || 'failed to fetch job' };
      }

      // Fetch Events related to the Job (field-selector by involvedObject.name)
      const eventsResp = await safeGet(`get events -o json --field-selector involvedObject.name=${jobName},involvedObject.kind=Job`);
      if (eventsResp.ok) {
        try {
          results.events = JSON.parse(eventsResp.stdout || '{}');
        } catch (e) {
          results.events = { parseError: e.message, raw: eventsResp.stdout };
        }
      } else {
        results.events = { error: eventsResp.error?.message || eventsResp.error || 'failed to fetch events' };
      }

      // Fetch Pods selected by job-name=<jobName>
      const podsResp = await safeGet(`get pods -l job-name=${jobName} -o json`);
      if (podsResp.ok) {
        try {
          results.pods = JSON.parse(podsResp.stdout || '{}');
        } catch (e) {
          results.pods = { parseError: e.message, raw: podsResp.stdout };
        }
      } else {
        results.pods = { error: podsResp.error?.message || podsResp.error || 'failed to fetch pods' };
      }

      // Derived summary logic
      const derived = {
        jobFound: false,
        jobStatus: null,
        pods: [],
        events: [],
        timedOut: false,
        timedOutReason: null,
        failed: false,
        failureReason: null
      };

      // Analyze job
      if (results.job && !results.job.error && !results.job.parseError && results.job.metadata) {
        derived.jobFound = true;
        const js = results.job;
        const status = js.status || {};
        derived.jobStatus = {
          succeeded: status.succeeded || 0,
          failed: status.failed || 0,
          active: status.active || 0,
          conditions: Array.isArray(status.conditions)
            ? status.conditions.map(c => ({ type: c.type, status: c.status, reason: c.reason, message: c.message, lastTransitionTime: c.lastTransitionTime }))
            : []
        };

        // Check for common timeout/failure reasons on the Job
        if (Array.isArray(status.conditions)) {
          for (const c of status.conditions) {
            if (c.type === 'Failed' || /failed/i.test(c.type || '')) {
              derived.failed = true;
              derived.failureReason = c.reason || c.message || 'Job condition indicates failure';
            }
            if ((c.reason && /deadline|timeout|backoff/i.test(c.reason)) || (c.message && /deadline|timeout|backoff/i.test(c.message))) {
              derived.timedOut = true;
              derived.timedOutReason = c.reason || c.message;
            }
          }
        }

        // Also infer from status counts
        if ((status.failed || 0) > 0 && !derived.failed) {
          derived.failed = true;
          derived.failureReason = 'job has failed pod count > 0';
        }
      }

      // Analyze events
      if (results.events && results.events.items && Array.isArray(results.events.items)) {
        derived.events = results.events.items.map(ev => ({ reason: ev.reason, type: ev.type, message: ev.message, source: ev.source, count: ev.count, firstTimestamp: ev.firstTimestamp, lastTimestamp: ev.lastTimestamp }));
        for (const ev of results.events.items) {
          const msg = String(ev.message || '');
          const reason = String(ev.reason || '');
          if (/backofflimitexceeded|backoff limit exceeded|backofflimit/i.test(reason + ' ' + msg)) {
            derived.timedOut = true;
            derived.timedOutReason = derived.timedOutReason || `event:${reason} ${msg}`;
            derived.failed = derived.failed || true;
            derived.failureReason = derived.failureReason || `event:${reason}`;
          }
          if (/deadlineexceeded|deadline exceeded|deadline/i.test(reason + ' ' + msg)) {
            derived.timedOut = true;
            derived.timedOutReason = derived.timedOutReason || `event:${reason} ${msg}`;
          }
          if ((ev.type || '').toLowerCase() === 'warning' && !derived.failed && /failed|error|backoff|oom|oomkilled|evicted/i.test(msg + ' ' + reason)) {
            derived.failed = true;
            derived.failureReason = derived.failureReason || `event:${reason} ${msg}`;
          }
        }
      }

      // Analyze pods and their container statuses
      if (results.pods && results.pods.items && Array.isArray(results.pods.items)) {
        for (const pod of results.pods.items) {
          const podSummary = {
            name: pod.metadata?.name,
            phase: pod.status?.phase,
            containerStatuses: []
          };
          const cstatuses = pod.status?.containerStatuses || [];
          for (const cs of cstatuses) {
            const s = { name: cs.name, ready: cs.ready, restartCount: cs.restartCount };
            if (cs.state) {
              if (cs.state.terminated) {
                s.state = { terminated: { exitCode: cs.state.terminated.exitCode, reason: cs.state.terminated.reason, message: cs.state.terminated.message, startedAt: cs.state.terminated.startedAt, finishedAt: cs.state.terminated.finishedAt } };
                // Terminated with non-zero exit code -> failure
                if (typeof cs.state.terminated.exitCode === 'number' && cs.state.terminated.exitCode !== 0) {
                  derived.failed = true;
                  derived.failureReason = derived.failureReason || (`container ${cs.name} exitCode=${cs.state.terminated.exitCode} reason=${cs.state.terminated.reason || 'unknown'}`);
                }
                if (cs.state.terminated.reason && /deadlineexceeded|deadline exceeded|oomkilled|oom|evicted/i.test(cs.state.terminated.reason)) {
                  derived.timedOut = derived.timedOut || /deadlineexceeded|deadline exceeded/i.test(cs.state.terminated.reason);
                  derived.timedOutReason = derived.timedOutReason || cs.state.terminated.reason;
                }
              } else if (cs.state.waiting) {
                s.state = { waiting: { reason: cs.state.waiting.reason, message: cs.state.waiting.message } };
                if (cs.state.waiting.reason && /crashloopbackoff|errimagepull|imagepullbackoff|backoff/i.test(cs.state.waiting.reason)) {
                  derived.failed = true;
                  derived.failureReason = derived.failureReason || cs.state.waiting.reason;
                }
              } else if (cs.state.running) {
                s.state = { running: true };
              }
            }
            podSummary.containerStatuses.push(s);
          }

          derived.pods.push(podSummary);
        }
      }

      // Finalize a compact high-level verdict
      const verdict = {
        verdict: derived.timedOut ? 'timed_out' : derived.failed ? 'failed' : derived.jobFound ? 'ok' : 'not_found',
        timedOut: derived.timedOut,
        timedOutReason: derived.timedOutReason,
        failed: derived.failed,
        failureReason: derived.failureReason
      };

      const details = {
        jobName,
        namespace: namespace || null,
        verdict,
        jobStatus: derived.jobStatus,
        pods: derived.pods,
        events: derived.events
      };

      // Attach raw payloads on request
      const raw = {};
      if (params.includeRawJob) raw.job = results.job;
      if (params.includeRawEvents) raw.events = results.events;
      if (params.includeRawPods) raw.pods = results.pods;

      const output = {
        status: 'success',
        details,
        raw
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(output, null, 2)
          }
        ],
        details: output
      };
    }
  });
}
