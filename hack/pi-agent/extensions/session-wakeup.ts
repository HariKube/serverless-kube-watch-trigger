import { Type } from 'typebox';
import { handleSessionWakeup } from './orchestration.mjs';

export default function registerSessionWakeup(pi) {
  pi.registerTool({
    name: 'handle_session_wakeup',
    label: 'handle_session_wakeup',
    description:
      'Fetch wake-up state from Kubernetes, evaluate the worker outcome, and persist the updated session Secret with conflict-aware retries.',
    parameters: Type.Object({
      prompt: Type.String({ description: 'The current prompt, including wake-up lines when present.' }),
      workerSummary: Type.Optional(Type.String({ description: 'Short worker summary to store with the result.' })),
      maxAttempts: Type.Optional(Type.Number({ description: 'Maximum Secret replace attempts on conflict. Default: 5.' }))
    }),
    async execute(_toolCallId, params) {
      const result = await handleSessionWakeup(params);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        details: result
      };
    }
  });
}
