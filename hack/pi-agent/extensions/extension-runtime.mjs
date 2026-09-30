import fs from 'fs';
import os from 'os';
import path from 'path';

export default async function registerExtensionRuntime(pi, toolMeta, discoverFn, renderSkillFn) {
  // create a temp root for any runtime-generated skills
  const skillRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pi-extension-runtime-'));

  let snapshotPromise = null;
  let skillPathPromise = null;

  // register resources_discover to lazily perform discovery once and write a skill
  pi.on('resources_discover', async () => {
    if (!skillPathPromise) {
      if (!snapshotPromise) {
        snapshotPromise = (async () => {
          try {
            return await discoverFn();
          } catch (error) {
            return {
              status: 'error',
              fetchedAt: new Date().toISOString(),
              message: error?.message || String(error)
            };
          }
        })();
      }

      skillPathPromise = (async () => {
        const snapshot = await snapshotPromise;
        let rendered = renderSkillFn(snapshot);
        if (rendered == null) rendered = '';
        // normalize to string
        rendered = String(rendered);

        // If the rendered content doesn't start with YAML frontmatter ("---"),
        // prepend minimal frontmatter so the runtime-generated skill is a named SKILL.md.
        const startsWithFrontmatter = /^---\s*\r?\n/.test(rendered);
        if (!startsWithFrontmatter) {
          const name = toolMeta && toolMeta.name ? String(toolMeta.name) : '';
          const description = toolMeta && toolMeta.description ? String(toolMeta.description) : '';
          const front = `---\nname: ${name.replace(/`/g,'')}${description ? `\ndescription: ${description.replace(/`/g,'')}` : ''}\n---\n\n`;
          rendered = front + rendered;
        }

        const skillDir = path.join(skillRoot, 'runtime-snapshot-skill');
        fs.mkdirSync(skillDir, { recursive: true });
        fs.writeFileSync(path.join(skillDir, 'SKILL.md'), rendered, 'utf8');
        return skillDir;
      })();
    }

    return { skillPaths: [await skillPathPromise] };
  });

  // ensure native metadata object exists on the registered tool
  const tool = Object.assign({}, toolMeta);
  if (!tool.native || typeof tool.native !== 'object') {
    tool.native = {};
  }

  pi.registerTool(tool);

  // cleanup on shutdown
  pi.on('session_shutdown', async () => {
    try {
      fs.rmSync(skillRoot, { recursive: true, force: true });
    } catch (e) {
      // ignore cleanup errors
    }
  });

  return { skillRoot };
}
