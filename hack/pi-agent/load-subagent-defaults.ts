import { Type } from 'typebox';
import { extractSubAgentDefaults } from './session-lib.mjs';

export default function registerLoadSubagentDefaults(pi) {
  pi.registerTool({
    name: 'load_subagent_defaults',
    label: 'load_subagent_defaults',
    description:
      'Parse the sub-agent defaults base64 prefix from a prompt, validate it, and return the cleaned prompt with normalized defaults.',
    parameters: Type.Object({
      prompt: Type.String({ description: 'The full prompt that may start with sub-agent defaults base64://...' }),
      fallbackNamespace: Type.Optional(
        Type.String({ description: 'Namespace to use when the decoded defaults omit namespace.' })
      )
    }),
    async execute(_toolCallId, params) {
      const result = extractSubAgentDefaults(params.prompt, params.fallbackNamespace || 'default');
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        details: result
      };
    }
  });
}
