import { Type } from 'typebox';

export default function registerExitExtension(pi) {
  pi.registerTool({
    name: 'exit_pi',
    label: 'exit_pi',
    description: 'Gracefully terminate the Pi process with exit code 0 after all required work is safely persisted.',
    parameters: Type.Object({
      reason: Type.Optional(Type.String({ description: 'Short, non-sensitive exit reason for logs.' })),
      delayMs: Type.Optional(Type.Number({ description: 'Delay before exit so logs can flush. Default: 100.' }))
    }),
    async execute(_toolCallId, params) {
      const reason = params.reason || 'Task completed successfully.';
      const delayMs = Math.max(0, Math.trunc(params.delayMs ?? 100));
      console.log(`[exit_pi] ${reason}`);

      setTimeout(() => {
        process.exit(0);
      }, delayMs);

      return {
        content: [{ type: 'text', text: JSON.stringify({ status: 'exiting', reason, delayMs }, null, 2) }],
        details: { status: 'exiting', reason, delayMs }
      };
    }
  });
}
