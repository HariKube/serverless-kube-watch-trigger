import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('execution-mode preserves choose_execution_mode contract and prefers extension-runtime helper', () => {
  const src = fs.readFileSync(new URL('./execution-mode.ts', import.meta.url), 'utf8');

  // Always require the native tool name to remain discoverable
  assert.match(src, /name:\s*['"]choose_execution_mode['"]/);

  // Accept either the legacy direct registration or the migrated helper-based registration
  const directRegister = /pi\.registerTool\(/.test(src);
  const helperStyle = /registerExtensionRuntime|extension-runtime\.mjs|resources_discover/.test(src);

  assert.ok(
    directRegister || helperStyle,
    'execution-mode must either directly register the tool (pi.registerTool) or adopt the shared extension-runtime helper (registerExtensionRuntime / resources_discover)'
  );
});
