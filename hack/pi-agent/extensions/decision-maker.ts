import { Type } from 'typebox';
import { decideSubagentStrategy } from './session-lib.mjs';
import registerExtensionRuntime from './extension-runtime.mjs';

const ProposedAction = Type.Union([Type.Literal('stay-local'), Type.Literal('delegate')]);

export default function registerDecisionMaker(pi) {
  // preserve the original tool contract as metadata and route registration through the shared runtime helper
  const toolMeta = {
    name: 'decision_maker',
    label: 'decision_maker',
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
      maxParallel: Type.Optional(Type.Number({ description: 'Maximum number of sub-agents allowed for the session.' })),
      workerTimeout: Type.Optional(
        Type.String({ description: 'PiAgentSpec.timeout duration (for example 10m or 1h30m) used for timeout-safety delegation decisions.' })
      )
    }),
    async execute(_toolCallId, params) {
      const result = decideSubagentStrategy(params);
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
