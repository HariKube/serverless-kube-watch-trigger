import { Type } from 'typebox';
import { decideSubagentStrategy } from './session-lib.mjs';

const ProposedAction = Type.Union([Type.Literal('stay-local'), Type.Literal('delegate')]);

export default function registerDecisionMaker(pi) {
  pi.registerTool({
    name: 'decide_subagent_strategy',
    label: 'decide_subagent_strategy',
    description:
      'Validate whether work should stay local or be delegated to sub-agents using the shared delegation guidelines.',
    parameters: Type.Object({
      task: Type.String({ description: 'Short summary of the work being evaluated.' }),
      proposedAction: Type.Optional(ProposedAction),
      estimatedSteps: Type.Optional(Type.Number({ description: 'Estimated number of meaningful execution steps.' })),
      estimatedMinutes: Type.Optional(Type.Number({ description: 'Estimated number of minutes to finish the work.' })),
      independentWorkUnits: Type.Optional(
        Type.Number({ description: 'How many independent work streams can proceed in parallel.' })
      ),
      maxParallel: Type.Optional(Type.Number({ description: 'Maximum number of sub-agents allowed for the session.' }))
    }),
    async execute(_toolCallId, params) {
      const result = decideSubagentStrategy(params);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        details: result
      };
    }
  });
}
