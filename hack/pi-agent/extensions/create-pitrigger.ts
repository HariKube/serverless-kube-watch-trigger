import { Type } from 'typebox';
import { createPiTrigger } from './orchestration.mjs';

const EventType = Type.Union([Type.Literal('ADDED'), Type.Literal('MODIFIED'), Type.Literal('DELETED')]);

export default function registerCreatePiTrigger(pi) {
  pi.registerTool({
    name: 'create_pitrigger',
    label: 'create_pitrigger',
    description:
      'Create or prepare a PiTrigger manifest, optionally reusing runtime sub-agent defaults for namespace and agent settings.',
    parameters: Type.Object({
      prompt: Type.Optional(Type.String({ description: 'Original prompt, only needed for legacy defaults-prefix cleanup.' })),
      fallbackNamespace: Type.Optional(Type.String({ description: 'Namespace used when neither namespace nor sub-agent defaults provide one.' })),
      subAgentDefaults: Type.Optional(Type.Any({ description: 'Decoded sub-agent defaults object used as a fallback source for namespace and agent.' })),
      name: Type.String({ description: 'Metadata.name for the PiTrigger.' }),
      namespace: Type.Optional(Type.String({ description: 'Metadata.namespace for the PiTrigger. Defaults to subAgentDefaults.namespace or fallbackNamespace.' })),
      labels: Type.Optional(Type.Any({ description: 'Optional metadata.labels map.' })),
      annotations: Type.Optional(Type.Any({ description: 'Optional metadata.annotations map.' })),
      ownerReferences: Type.Optional(Type.Array(Type.Any(), { description: 'Optional metadata.ownerReferences array.' })),
      resource: Type.Any({ description: 'Required watched resource object with apiVersion and kind.' }),
      namespaces: Type.Optional(Type.Array(Type.String(), { description: 'Namespaces to watch. Defaults to [namespace].' })),
      labelSelectors: Type.Optional(
        Type.Array(Type.String(), {
          minItems: 1,
          description: 'Custom spec.labelSelectors entries supplied by the agent, for example ["app=my-app", "tier=backend"].'
        })
      ),
      fieldSelectors: Type.Optional(Type.Array(Type.String(), { description: 'Optional spec.fieldSelectors entries.' })),
      eventTypes: Type.Optional(
        Type.Array(EventType, {
          minItems: 1,
          description: 'Custom spec.eventTypes entries supplied by the agent. Allowed values: ADDED, MODIFIED, DELETED.'
        })
      ),
      eventFilter: Type.Optional(Type.String({ description: 'Optional spec.eventFilter template expression.' })),
      sendInitialEvents: Type.Optional(Type.Boolean({ description: 'Whether to emit initial object state events.' })),
      maxJobs: Type.Optional(Type.Number({ description: 'Optional maxJobs limit.' })),
      timeout: Type.Optional(Type.String({ description: 'Optional PiTrigger watcher timeout duration such as 10m or 1h.' })),
      provider: Type.Optional(Type.String({ description: 'Optional override for agent.provider while inheriting the rest of subAgentDefaults.agent.' })),
      model: Type.Optional(Type.String({ description: 'Optional override for agent.model while inheriting the rest of subAgentDefaults.agent.' })),
      serviceAccountName: Type.Optional(
        Type.String({
          description: 'Optional override for agent.serviceAccountName. When omitted, create_pitrigger inherits subAgentDefaults.agent.serviceAccountName by default.'
        })
      ),
      agent: Type.Optional(
        Type.Any({
          description:
            'Optional partial or full PiAgentSpec overrides. When subAgentDefaults.agent is available, this object is merged on top of it rather than replacing it wholesale.'
        })
      ),
      apply: Type.Optional(Type.Boolean({ description: 'When true (default), apply the manifest to the cluster. When false, only return the manifest.' }))
    }),
    async execute(_toolCallId, params) {
      const result = await createPiTrigger(params);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        details: result
      };
    }
  });
}
