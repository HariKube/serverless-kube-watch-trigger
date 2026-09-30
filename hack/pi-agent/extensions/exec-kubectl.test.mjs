import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

test('exec-kubectl.ts source-level assertions for helper-adoption migration guard', () => {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const srcPath = path.join(__dirname, 'exec-kubectl.ts');
  const src = fs.readFileSync(srcPath, 'utf8');

  // Pattern A: current shape — registers a native tool named `exec_kubectl`
  const registersExecKubectl = /name\s*:\s*['"]exec_kubectl['"]/.test(src);

  // Pattern B: migrated shape — imports the shared helper and routes runtime via it
  const importsRuntime = /\.\/extension-runtime(?:\.mjs)?/.test(src) || /extension-runtime(?:\.mjs)?/.test(src);
  const usesHelperApi = /registerExtensionRuntime|resources_discover/.test(src);

  // The file should either still directly register the `exec_kubectl` tool (pre-migration)
  // or have adopted the shared runtime helper (post-migration) — allow either so this
  // test can act as a regression gate before/after the upcoming refactor.
  assert.ok(
    registersExecKubectl || (importsRuntime && usesHelperApi),
    'exec-kubectl.ts must either register name: "exec_kubectl" (pre-migration) or import "./extension-runtime.mjs" and reference registerExtensionRuntime/resources_discover (post-migration)'
  );
});
