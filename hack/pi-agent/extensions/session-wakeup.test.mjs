import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), 'session-wakeup.ts');

test('session-wakeup registers native tool name handle_session_wakeup', async () => {
  const src = await readFile(SRC, 'utf8');
  // tolerant whitespace match for the tool name registration
  assert.match(src, /name\s*:\s*['"]handle_session_wakeup['"]/);
});

test('if migrated to extension-runtime helper, ensure helper import routes runtime export', async () => {
  const src = await readFile(SRC, 'utf8');

  // detect a migration that imports the shared helper runtime module
  const importsHelper = /import[\s\S]*["']\.\/extension-runtime(?:\.mjs)?["']/.test(src);

  // helper routing should reference either registerExtensionRuntime or resources_discover (indirect signal of helper adoption)
  const referencesHelperUsage = /(registerExtensionRuntime|resources_discover)/.test(src);

  // If the file imports the shared helper it must also route through it (lightweight source-level assertion).
  if (importsHelper) {
    assert.ok(
      referencesHelperUsage,
      'session-wakeup.ts imports ./extension-runtime.mjs but does not reference registerExtensionRuntime or resources_discover; migrated extension should route runtime skill export through the shared helper.'
    );
  } else {
    // No helper import present today — that's acceptable for pre-migration state. This test exists so that when the file is migrated
    // (and the import appears) the helper usage assertion above will enforce correct routing.
    assert.ok(!importsHelper || referencesHelperUsage);
  }
});
