import { Type } from 'typebox';
import { orchestrateSubagentExecution } from './orchestration.mjs';
import registerExtensionRuntime from './extension-runtime.mjs';

const ProposedAction = Type.Union([Type.Literal('stay-local'), Type.Literal('delegate')]);

const Worker = Type.Object({
  index: Type.Number({ description: '1-based worker index' }),
  task: Type.String({ description: 'Complete instructions for this worker' }),
  expectedResult: Type.Optional(Type.String()),
  outputLocation: Type.Optional(Type.String()),
  completed: Type.Optional(Type.Boolean()),
  result: Type.Optional(Type.String())
});

const OwnerReference = Type.Object({
  apiVersion: Type.String({ description: 'API version of the original triggering resource.' }),
  kind: Type.String({ description: 'Kind of the original triggering resource.' }),
  name: Type.String({ description: 'Name of the original triggering resource.' }),
  uid: Type.String({ description: 'UID of the original triggering resource.' })
});

export default function registerSubagentOrchestrator(pi) {
  // preserve the original tool contract as metadata and route registration through the shared runtime helper
  const toolMeta = {
    name: 'orchestrate_subagent_execution',
    label: 'orchestrate_subagent_execution',
    description:
      'Choose stay-local, headless, or delegated execution and, when delegation input is supplied, persist the hibernated parent session plus worker PiTriggers in one step.',
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
      prompt: Type.Optional(Type.String({ description: 'Optional prompt used for legacy defaults-prefix cleanup and parent context.' })),
      fallbackNamespace: Type.Optional(Type.String()),
      subAgentDefaults: Type.Optional(Type.Any({ description: 'Optional explicit defaults object to normalize first.' })),
      delegation: Type.Optional(
        Type.Object({
          originalPrompt: Type.Optional(Type.String({ description: 'The original parent task prompt.' })),
          cleanedPrompt: Type.Optional(Type.String()),
          workSoFar: Type.Optional(Type.String()),
          nextStep: Type.String({ description: 'What the parent should do after workers report back.' }),
          workers: Type.Array(Worker, { minItems: 1 }),
          sessionId: Type.Optional(Type.String()),
          secretName: Type.Optional(Type.String()),
          round: Type.Optional(Type.Number()),
          previousContext: Type.Optional(Type.Any()),
          sourceOwnerReference: Type.Optional(OwnerReference)
        })
      )
    }),
    async execute(_toolCallId, params) {
      const result = await orchestrateSubagentExecution(params);
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
