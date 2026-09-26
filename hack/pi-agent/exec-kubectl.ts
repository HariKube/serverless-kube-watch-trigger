import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { Type } from 'typebox';

const DEFAULT_NAMESPACE_PATH = process.env.NS_PATH || '/var/run/secrets/kubernetes.io/serviceaccount/namespace';
const TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token';
const CA_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt';
const MAX_BUFFER_BYTES = 10 * 1024 * 1024;

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function validateCommand(command) {
  const trimmed = String(command || '').trim();
  if (!trimmed) {
    throw new Error('command is required');
  }
  if (/^kubectl\b/.test(trimmed)) {
    throw new Error('omit the kubectl prefix; pass only the kubectl arguments');
  }
  if (/&&|\|\||;(?![^"']*["'])/.test(trimmed) || /\n/.test(trimmed)) {
    throw new Error('command must be a single non-interactive kubectl invocation');
  }
  return trimmed;
}

async function resolveNamespace(explicitNamespace) {
  if (explicitNamespace) {
    return explicitNamespace;
  }
  return (await readFile(DEFAULT_NAMESPACE_PATH, 'utf8')).trim();
}

async function buildScript(command, namespace) {
  const token = (await readFile(TOKEN_PATH, 'utf8')).trim();
  const serverHost = process.env.KUBERNETES_SERVICE_HOST;
  const serverPort = process.env.KUBERNETES_SERVICE_PORT_HTTPS || '443';
  if (!serverHost) {
    throw new Error('KUBERNETES_SERVICE_HOST is not set');
  }

  const args = [
    'kubectl',
    `--kubeconfig=/dev/null`,
    `--server=${shellQuote(`https://${serverHost}:${serverPort}`)}`,
    `--token=${shellQuote(token)}`,
    `--certificate-authority=${shellQuote(CA_PATH)}`
  ];

  if (namespace) {
    args.push(`-n ${shellQuote(namespace)}`);
  }
  args.push(command);

  return args.join(' ');
}

async function runScript(script, input, maxBufferBytes) {
  return await new Promise((resolve, reject) => {
    const child = spawn('bash', ['-lc', script], {
      env: { ...process.env, KUBECONFIG: '/dev/null' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject({
        ...error,
        stdout,
        stderr
      });
    };

    const append = (target, chunk) => {
      const value = chunk.toString();
      if (target === 'stdout') {
        stdout += value;
        if (Buffer.byteLength(stdout, 'utf8') > maxBufferBytes) {
          child.kill('SIGTERM');
          fail({ exitCode: 1, message: 'kubectl stdout exceeded the maximum buffer size' });
        }
      } else {
        stderr += value;
        if (Buffer.byteLength(stderr, 'utf8') > maxBufferBytes) {
          child.kill('SIGTERM');
          fail({ exitCode: 1, message: 'kubectl stderr exceeded the maximum buffer size' });
        }
      }
    };

    child.stdout.on('data', chunk => append('stdout', chunk));
    child.stderr.on('data', chunk => append('stderr', chunk));
    child.on('error', error => fail({ exitCode: 1, message: error.message }));
    child.on('close', code => {
      if (settled) return;
      if (code === 0) {
        settled = true;
        resolve({ stdout, stderr });
      } else {
        fail({ exitCode: code ?? 1, message: `kubectl exited with code ${code}` });
      }
    });

    child.stdin.end(input ?? undefined);
  });
}

function isConflict(stderr) {
  return /conflict|the object has been modified/i.test(stderr || '');
}

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
      const command = validateCommand(params.command);
      const namespace = await resolveNamespace(params.namespace);
      const attempts = params.retryOnConflict ? Math.max(1, Math.trunc(params.maxAttempts || 5)) : 1;
      let lastError;
      let commandExecuted = '';

      for (let attempt = 1; attempt <= attempts; attempt += 1) {
        try {
          const script = await buildScript(command, namespace);
          commandExecuted = script;
          const result = await runScript(script, params.input, MAX_BUFFER_BYTES);
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    status: 'success',
                    attempts: attempt,
                    commandExecuted: script,
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
              commandExecuted: script,
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
