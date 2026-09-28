import { Type } from 'typebox';
import { chooseExecutionMode } from './orchestration.mjs';

const ProposedAction = Type.Union([Type.Literal('stay-local'), Type.Literal('delegate')]);

export default function registerChooseExecutionMode(pi) {
  pi.registerTool({
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
  });
}
