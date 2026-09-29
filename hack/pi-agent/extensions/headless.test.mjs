import { test } from 'node:test';
import { strict as assert } from 'assert';
import fs from 'fs';

test('headless launcher must not pass --no-extensions to pi subprocess', () => {
  // Read the source file adjacent to this test
  const src = fs.readFileSync(new URL('./headless.ts', import.meta.url), 'utf8');

  // Regression guard: ensure the python pty spawn command does not include the
  // --no-extensions flag (it disables runtime extensions unexpectedly).
  assert.ok(!src.includes('--no-extensions'), 'headless.ts contains "--no-extensions" in the spawned pi command; remove this flag to allow runtime extensions in headless workers');
});
