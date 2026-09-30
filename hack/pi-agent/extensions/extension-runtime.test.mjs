import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import registerExtensionRuntime from './extension-runtime.mjs';

// This unit test defines the contract for a reusable, generic extension-runtime helper.
// The helper is expected to accept the PI runtime, explicit tool metadata, a discovery
// function (invoked once), and a skill-render function which returns the text to
// be written for the generated skill. The test provides local stubs including a
// discovery call counter so the helper itself does not need test-only introspection.

function makeFakePi() {
  const handlers = new Map();
  let registeredTool = null;

  return {
    on(event, handler) {
      handlers.set(event, handler);
    },
    async invoke(event, ...args) {
      const h = handlers.get(event);
      if (!h) throw new Error(`no handler for ${event}`);
      return await h(...args);
    },
    registerTool(tool) {
      registeredTool = tool;
    },
    getRegisteredTool() {
      return registeredTool;
    }
  };
}

function writeSkill(dir, name, text) {
  const skillDir = path.join(dir, name);
  fs.mkdirSync(skillDir, { recursive: true });
  // render a simple skill file that includes the provided text
  fs.writeFileSync(path.join(skillDir, 'skill.txt'), text, 'utf8');
  return skillDir;
}

// The helper under test should match this generic shape when implemented in
// ./extension-runtime.mjs: registerExtensionRuntime(pi, toolMeta, discoverFn, renderSkillFn)
// and return an object including at least { skillRoot } so tests can inspect and
// verify cleanup on shutdown. This test drives the expected behavior without
// assuming any demo-specific implementation details.

test('extension-runtime helper contract: discovery once, resources_discover exposes skill, tool metadata present, cleanup on shutdown', async (t) => {
  const pi = makeFakePi();

  // local test-owned discovery counter: the helper should call this at most once
  let discoveryCalls = 0;
  const fakeSnapshot = {
    status: 'success',
    fetchedAt: new Date().toISOString(),
    discoveredBy: 'unit-test',
  };

  async function discoverOnce() {
    discoveryCalls += 1;
    // simulate async discovery work
    return Object.assign({}, fakeSnapshot);
  }

  // tool metadata supplied explicitly by the test
  const toolMeta = {
    name: 'runtime_native_tool',
    label: 'runtime_native_tool',
    description: 'A runtime-native helper tool',
    // the helper/extension may augment with a `native` object when registering
  };

  // render function supplied by the test — intentionally returns content WITHOUT YAML frontmatter;
  // the helper is expected to normalize this into a named skill file (SKILL.md) using toolMeta
  function renderSkill(snapshot) {
    return `snapshot-status: ${snapshot.status}\ndiscoveredBy: ${snapshot.discoveredBy}\n\nThis runtime skill text lacks frontmatter and should be normalized by the helper.\n`;
  }

  // call the generic helper shape; production will implement this signature
  const impl = await registerExtensionRuntime(pi, toolMeta, discoverOnce, renderSkill);

  // Call resources_discover twice and assert discovery only captured once and same skill path returned.
  const first = await pi.invoke('resources_discover');
  assert.ok(first && Array.isArray(first.skillPaths) && first.skillPaths.length === 1, 'first resources_discover should return one skillPath');

  const second = await pi.invoke('resources_discover');
  assert.ok(second && Array.isArray(second.skillPaths) && second.skillPaths.length === 1, 'second resources_discover should return one skillPath');

  // discovery should have been performed only once (test-owned counter)
  assert.equal(discoveryCalls, 1, 'startup discovery should be captured once');

  const skillPath = first.skillPaths[0];
  // skill path should exist
  assert.ok(fs.existsSync(skillPath), 'skill path should exist on disk');

  // the helper contract now requires a named SKILL.md file rendered for the runtime skill
  const rendered = fs.readFileSync(path.join(skillPath, 'SKILL.md'), 'utf8');
  // helper contract: helper writes a named SKILL.md that includes generated YAML frontmatter
  assert.ok(rendered.startsWith('---'), 'rendered skill should include generated YAML frontmatter');
  assert.ok(rendered.includes(`name: ${toolMeta.name}`), 'rendered skill frontmatter should include tool name derived from toolMeta');
  assert.ok(rendered.includes(`description: ${toolMeta.description}`), 'rendered skill frontmatter should include tool description derived from toolMeta');
  // original rendered body should still include snapshot metadata content
  assert.ok(rendered.includes('snapshot-status: success'), 'rendered skill should include snapshot status');
  assert.ok(rendered.includes('discoveredBy'), 'rendered skill should include snapshot metadata');

  // ensure the registered tool contains at least the supplied metadata and may include native augmentation
  const registered = pi.getRegisteredTool();
  assert.ok(registered, 'tool should be registered');
  assert.equal(registered.name, toolMeta.name, 'registered tool should have expected name');
  assert.ok(registered.native && typeof registered.native === 'object', 'registered tool should include native metadata');

  // invoke shutdown and assert cleanup — helper must expose skillRoot so tests can confirm removal
  await pi.invoke('session_shutdown');
  assert.ok(!fs.existsSync(impl.skillRoot), 'skill root should be removed on session_shutdown');
});
