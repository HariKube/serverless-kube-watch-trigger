import { Type } from 'typebox';
import { processSessionWakeup } from './session-lib.mjs';

export default function registerProcessSessionWakeup(pi) {
  pi.registerTool({
    name: 'process_session_wakeup',
    label: 'process_session_wakeup',
    description:
      'Validate wake-up metadata, inspect stored session state, and produce the Secret replacement needed to record a worker result.',
    parameters: Type.Object({
      prompt: Type.String({ description: 'The current prompt, including wake-up lines when present.' }),
      secretJson: Type.String({ description: 'JSON from kubectl get secret ... -o json or list response.' }),
      workerSummary: Type.Optional(Type.String({ description: 'Short worker summary to store with the result.' })),
      jobJson: Type.Optional(Type.String({ description: 'JSON from kubectl get job <name> -o json.' })),
      eventsJson: Type.Optional(Type.String({ description: 'JSON from kubectl get events ... -o json.' }))
    }),
    async execute(_toolCallId, params) {
      const result = processSessionWakeup(params);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        details: result
      };
    }
  });
}
