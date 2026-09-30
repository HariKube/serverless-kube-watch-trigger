import { Type } from 'typebox';
import { chooseExecutionMode } from './orchestration.mjs';
import registerExtensionRuntime from './extension-runtime.mjs';

const ProposedAction = Type.Union([Type.Literal('stay-local'), Type.Literal('delegate')]);

export default function registerChooseExecutionMode(pi) {
  // preserve the original tool contract as metadata and route registration through the shared runtime helper
  const toolMeta = {
    name: 'choose_execution_mode',
    label: 'choose_execution_mode',
    description:
      'Choose stay-local, headless, or delegated execution using shared timeout and parallelism rules, automatically reusing resolved sub-agent defaults when available.',
    parameters: Type.Object({
      task: Type.String({ description: 'Short summary of the work being evaluated.' }),
      proposedAction: Type.Optional(ProposedAction),
      estimatedSteps: Type.Optional(Type.Number({ description: 'Estimated number of meaningful execution steps.' })),
      estimatedMinutes: Type.Optional(Type.Number({ description: 'Estimated number of minutes to finish the work.' })),
      independentWorkUnits: Type.Optional(
        Type.Number({ description: 'How many independent work streams can proceed in parallel.' })
      ),
      maxParallel: Type.Optional(Type.Number({ description: 'Maximum number of sub-agents allowed for the session.' })),
      workerTimeout: Type.Optional(Type.String({ description: 'Timeout used for timeout-safety decisions.' })),
      contextHeavy: Type.Optional(Type.Boolean({ description: 'Mark true when the work is a single stream but would bloat parent context.' })),
      preferHeadless: Type.Optional(Type.Boolean({ description: 'Allow headless mode for context-heavy single-stream work. Default: true.' })),
      prompt: Type.Optional(Type.String({ description: 'Optional prompt used only for legacy defaults-prefix cleanup.' })),
      fallbackNamespace: Type.Optional(Type.String()),
      subAgentDefaults: Type.Optional(Type.Any({ description: 'Optional explicit defaults object to normalize first.' }))
    }),
    async execute(_toolCallId, params) {
      const result = chooseExecutionMode(params);
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
  const renderSkillFn = (snapshot: any) => `# runtime-snapshot for ${toolMeta.name}\n${JSON.stringify(snapshot, null, 2)}`;

  // register the tool and runtime lifecycle through the shared helper
  // do not await to avoid blocking startup; helper manages lifecycle and registration
  void registerExtensionRuntime(pi, toolMeta, discoverFn, renderSkillFn);
}
