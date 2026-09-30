import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';

// Migration/regression contract test for decision-maker.ts:
// - must preserve the native tool name `decision_maker`
// - should either continue to register the tool directly or adopt the
//   shared ./extension-runtime.mjs helper (registerExtensionRuntime / resources_discover)

test('decision-maker migration contract: preserves name and opts into extension-runtime or keeps direct registration', () => {
  const srcPath = new URL('./decision-maker.ts', import.meta.url);
  const src = fs.readFileSync(srcPath, 'utf8');

  // name must be preserved verbatim in the production source
  assert.ok(src.includes("name: 'decision_maker'") || src.includes('name: "decision_maker"'), 'expected name: "decision_maker" in decision-maker.ts');

  // Accept either the migrated helper shape or the existing direct registration.
  const usesRuntimeHelper = src.includes("./extension-runtime.mjs") || src.includes('registerExtensionRuntime') || src.includes('resources_discover');
  const registersDirectly = src.includes('registerTool(') || src.includes('pi.registerTool');

  assert.ok(usesRuntimeHelper || registersDirectly, 'decision-maker.ts must either import ./extension-runtime.mjs and reference the extension runtime helper (resources_discover/registerExtensionRuntime) or register the tool directly via registerTool');
});
