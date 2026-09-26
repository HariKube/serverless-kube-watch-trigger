import { Type } from 'typebox';
import { prepareSessionHibernation } from './session-lib.mjs';

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

export default function registerPrepareSessionHibernation(pi) {
  pi.registerTool({
    name: 'prepare_session_hibernation',
    label: 'prepare_session_hibernation',
    description:
      'Normalize session state for a parent agent, generate Secret/Lease/PiTrigger manifests, and prepare worker prompts for hibernation.',
    parameters: Type.Object({
      subAgentDefaults: Type.Any({ description: 'Decoded sub-agent defaults object.' }),
      originalPrompt: Type.String({ description: 'The original parent task prompt.' }),
      cleanedPrompt: Type.Optional(Type.String()),
      workSoFar: Type.Optional(Type.String()),
      nextStep: Type.String({ description: 'What the parent should do after workers report back.' }),
      workers: Type.Array(Worker, { minItems: 1 }),
      sessionId: Type.Optional(Type.String()),
      secretName: Type.Optional(Type.String()),
      round: Type.Optional(Type.Number()),
      previousContext: Type.Optional(Type.Any()),
      existingSecretJson: Type.Optional(
        Type.String({ description: 'Existing Secret JSON from kubectl get secret ... -o json when updating an existing session Secret.' })
      ),
      sourceOwnerReference: Type.Optional(OwnerReference)
    }),
    async execute(_toolCallId, params) {
      const result = prepareSessionHibernation(params);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        details: result
      };
    }
  });
}
