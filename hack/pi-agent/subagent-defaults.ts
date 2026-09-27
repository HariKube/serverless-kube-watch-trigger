import { Type } from 'typebox';
import { resolveSubagentDefaults } from './orchestration.mjs';

export default function registerResolveSubagentDefaults(pi) {
  pi.registerTool({
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
  });
}
