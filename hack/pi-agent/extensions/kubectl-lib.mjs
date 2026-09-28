import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';

export const DEFAULT_NAMESPACE_PATH = process.env.NS_PATH || '/var/run/secrets/kubernetes.io/serviceaccount/namespace';
export const TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token';
export const CA_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt';
export const MAX_BUFFER_BYTES = 10 * 1024 * 1024;

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

export function validateCommand(command) {
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

export async function resolveNamespace(explicitNamespace) {
  if (explicitNamespace) {
    return explicitNamespace;
  }
  return (await readFile(DEFAULT_NAMESPACE_PATH, 'utf8')).trim();
}

export async function buildScript(command, namespace) {
  const token = (await readFile(TOKEN_PATH, 'utf8')).trim();
  const serverHost = process.env.KUBERNETES_SERVICE_HOST;
  const serverPort = process.env.KUBERNETES_SERVICE_PORT_HTTPS || '443';
  if (!serverHost) {
    throw new Error('KUBERNETES_SERVICE_HOST is not set');
  }

  const args = [
    'kubectl',
    '--kubeconfig=/dev/null',
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

export async function runScript(script, input, maxBufferBytes = MAX_BUFFER_BYTES) {
  return await new Promise((resolve, reject) => {
    const child = spawn('bash', ['-lc', script], {
      env: { ...process.env, KUBECONFIG: '/dev/null' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const fail = error => {
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

export async function execKubectlCommand({ command, namespace, input, maxBufferBytes = MAX_BUFFER_BYTES }) {
  const validatedCommand = validateCommand(command);
  const resolvedNamespace = await resolveNamespace(namespace);
  const script = await buildScript(validatedCommand, resolvedNamespace);
  const result = await runScript(script, input, maxBufferBytes);
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    commandExecuted: script,
    namespace: resolvedNamespace
  };
}

export function isConflict(stderr) {
  return /conflict|the object has been modified/i.test(stderr || '');
}
