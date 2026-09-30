import { Type } from 'typebox';
import { resolveSubagentDefaults } from './orchestration.mjs';
import registerExtensionRuntime from './extension-runtime.mjs';

export default function registerResolveSubagentDefaults(pi) {
  // preserve the original tool contract as metadata and route registration through the shared runtime helper
  const toolMeta = {
    name: 'resolve_subagent_defaults',
    label: 'resolve_subagent_defaults',
    description:
      'Resolve sub-agent defaults for the current session, preferring injected runtime defaults and falling back to the legacy prompt prefix only when needed.',
    parameters: Type.Object({
      prompt: Type.Optional(Type.String({ description: 'Prompt that may still contain the legacy sub-agent defaults prefix.' })),
      fallbackNamespace: Type.Optional(
        Type.String({ description: 'Namespace to use when decoded defaults omit a namespace. Default: default.' })
      ),
      subAgentDefaults: Type.Optional(Type.Any({ description: 'Optional explicit defaults object to normalize first.' }))
    }),
    async execute(_toolCallId, params) {
      const result = resolveSubagentDefaults(params);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        details: result
      };
    }
  };

  // lightweight discovery snapshot for runtime skills (keeps the helper lifecycle happy)
  const discoverFn = async () => ({
    status: 'ok',
    fetchedAt: new Date().toISOString(),
    tool: { name: toolMeta.name }
  });

  // render a tiny runtime skill representation for tooling that expects a skill file
  const renderSkillFn = snapshot => `# runtime-snapshot for ${toolMeta.name}\n${JSON.stringify(snapshot, null, 2)}`;

  // register the tool and runtime lifecycle through the shared helper
  // do not await to avoid blocking startup; helper manages lifecycle and registration
  void registerExtensionRuntime(pi, toolMeta, discoverFn, renderSkillFn);
}
