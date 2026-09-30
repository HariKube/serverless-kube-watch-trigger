import { Type } from 'typebox';
import { handleSessionWakeup } from './orchestration.mjs';
import registerExtensionRuntime from './extension-runtime.mjs';

export default function registerSessionWakeup(pi) {
  // preserve the original tool contract as metadata and route registration through the shared runtime helper
  const toolMeta = {
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
  };

  // lightweight discovery snapshot for runtime skills (keeps the helper lifecycle happy)
  const discoverFn = async () => ({
    status: 'ok',
    fetchedAt: new Date().toISOString(),
    tool: { name: toolMeta.name }
  });

  // render a tiny runtime skill representation for tooling that expects a skill file
  const renderSkillFn = snapshot => `# runtime-snapshot for ${toolMeta.name}\n${JSON.stringify(snapshot, null, 2)}`;

  // register the tool and runtime lifecycle through the shared helper
  // do not await to avoid blocking startup; helper manages lifecycle and registration
  void registerExtensionRuntime(pi, toolMeta, discoverFn, renderSkillFn);
}
