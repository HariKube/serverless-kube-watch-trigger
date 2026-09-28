import { Type } from 'typebox';
import { execKubectlCommand, isConflict } from './kubectl-lib.mjs';

export default function registerExecKubectl(pi) {
  pi.registerTool({
    name: 'exec_kubectl',
    label: 'exec_kubectl',
    description:
      'Execute one non-interactive kubectl command against the in-cluster API using the Pod ServiceAccount.',
    parameters: Type.Object({
      command: Type.String({ description: 'Everything after kubectl.' }),
      namespace: Type.Optional(Type.String({ description: 'Namespace passed as -n <namespace>.' })),
      input: Type.Optional(Type.String({ description: 'STDIN content for apply -f - or replace -f -.' })),
      retryOnConflict: Type.Optional(Type.Boolean({ description: 'Retry replace/apply calls when the API returns Conflict.' })),
      maxAttempts: Type.Optional(Type.Number({ description: 'Retry limit when retryOnConflict=true. Default: 5.' }))
    }),
    async execute(_toolCallId, params) {
      const attempts = params.retryOnConflict ? Math.max(1, Math.trunc(params.maxAttempts || 5)) : 1;
      let lastError;
      let commandExecuted = '';

      for (let attempt = 1; attempt <= attempts; attempt += 1) {
        try {
          const result = await execKubectlCommand({
            command: params.command,
            namespace: params.namespace,
            input: params.input
          });
          commandExecuted = result.commandExecuted;
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    status: 'success',
                    attempts: attempt,
                    commandExecuted: result.commandExecuted,
                    stdout: result.stdout,
                    stderr: result.stderr
                  },
                  null,
                  2
                )
              }
            ],
            details: {
              status: 'success',
              attempts: attempt,
              commandExecuted: result.commandExecuted,
              stdout: result.stdout,
              stderr: result.stderr
            }
          };
        } catch (error) {
          lastError = error;
          if (!(params.retryOnConflict && attempt < attempts && isConflict(error.stderr))) {
            break;
          }
          await new Promise(resolve => setTimeout(resolve, attempt * 200));
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                status: 'error',
                attempts,
                commandExecuted,
                exitCode: lastError?.exitCode || 1,
                stdout: lastError?.stdout || '',
                stderr: lastError?.stderr || lastError?.message || ''
              },
              null,
              2
            )
          }
        ],
        details: {
          status: 'error',
          attempts,
          commandExecuted,
          exitCode: lastError?.exitCode || 1,
          stdout: lastError?.stdout || '',
          stderr: lastError?.stderr || lastError?.message || ''
        }
      };
    }
  });
}
