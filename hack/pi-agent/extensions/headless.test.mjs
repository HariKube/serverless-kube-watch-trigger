import { test } from 'node:test';
import { strict as assert } from 'assert';
import fs from 'fs';

test('headless launcher must not pass --no-extensions to pi subprocess', () => {
  // Read the source file adjacent to this test
  const src = fs.readFileSync(new URL('./headless.ts', import.meta.url), 'utf8');

  // Regression guard: ensure the python pty spawn command does not include the
  // --no-extensions flag (it disables runtime extensions unexpectedly).
  assert.ok(!src.includes('--no-extensions'), 'headless.ts contains "--no-extensions" in the spawned pi command; remove this flag to allow runtime extensions in headless workers');

  // Lightweight assertions to guard adoption of the shared extension runtime helper:
  // - ensure headless imports the shared helper (./extension-runtime or ./extension-runtime.mjs)
  // - ensure the file references resources_discover (which should be routed through the helper)
  // - ensure the tool still registers the "headless" native tool name
  const importsHelper = /(?:import\b[\s\S]*from\s+['"]\.\/extension-runtime(?:\.mjs)?['"])|(?:require\(['"]\.\/extension-runtime(?:\.mjs)?['"]\))/i;
  assert.ok(importsHelper.test(src), 'headless.ts should import the shared ./extension-runtime (or ./extension-runtime.mjs) helper to adopt the common runtime pattern');

  assert.ok(src.includes('resources_discover'), 'headless.ts should reference "resources_discover" (via the shared helper) rather than reimplementing discovery logic');

  assert.ok(/name:\s*['"]headless['"]/.test(src), 'headless.ts must still register the "headless" native tool name');
});
