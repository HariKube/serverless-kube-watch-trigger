import { Type } from 'typebox';
import registerExtensionRuntime from './extension-runtime.mjs';

export default function registerExitExtension(pi) {
  // preserve the original tool contract as metadata and route registration through the shared runtime helper
  const toolMeta = {
    name: 'exit_pi',
    label: 'exit_pi',
    description: 'Gracefully terminate the Pi process with an optional exit code (default 0) after all required work is safely persisted.',
    parameters: Type.Object({
      reason: Type.Optional(Type.String({ description: 'Short, non-sensitive exit reason for logs.' })),
      delayMs: Type.Optional(Type.Number({ description: 'Delay before exit so logs can flush. Default: 100.' })),
      exitCode: Type.Optional(Type.Number({ description: 'Optional exit code to use when terminating. Defaults to 0.' }))
    }),
    async execute(_toolCallId, params) {
      const reason = params.reason || 'Task completed successfully.';
      const delayMs = Math.max(0, Math.trunc(params.delayMs ?? 100));
      const exitCode = Math.max(0, Math.trunc(params.exitCode ?? 0));
      console.log(`[exit_pi] ${reason}`);

      setTimeout(() => {
        process.exit(exitCode);
      }, delayMs);

      return {
        content: [{ type: 'text', text: JSON.stringify({ status: 'exiting', reason, delayMs, exitCode }, null, 2) }],
        details: { status: 'exiting', reason, delayMs, exitCode }
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
