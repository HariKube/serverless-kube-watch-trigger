import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';

// Regression contract: subagent-orchestrator must preserve the native tool name
// 'orchestrate_subagent_execution' and may either register it directly or adopt
// the shared ./extension-runtime.mjs helper (but must still present the same name).

test('subagent-orchestrator migration: preserve native tool name and allow helper adoption', () => {
  const src = fs.readFileSync(new URL('./subagent-orchestrator.ts', import.meta.url), 'utf8');

  // Must mention the canonical tool name
  assert.ok(src.includes("name: 'orchestrate_subagent_execution'") || src.includes('name: "orchestrate_subagent_execution"'), 'file must expose the native tool name orchestrate_subagent_execution');

  // Either still registers the tool directly (registerTool) OR adopts the shared helper
  const usesRegisterTool = /registerTool\(/.test(src);
  const importsRuntime = src.includes("./extension-runtime.mjs") || src.includes('./extension-runtime.mjs');
  const referencesHelper = /registerExtensionRuntime\(|resources_discover/.test(src);

  assert.ok(usesRegisterTool || (importsRuntime && referencesHelper), 'file should either register the tool directly or import ./extension-runtime.mjs and use registerExtensionRuntime/resources_discover');
});
