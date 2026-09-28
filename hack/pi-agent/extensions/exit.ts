import { Type } from 'typebox';

export default function registerExitExtension(pi) {
  pi.registerTool({
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
  });
}
