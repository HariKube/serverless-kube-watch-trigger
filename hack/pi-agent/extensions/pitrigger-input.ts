import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const PI_TRIGGER_INPUT_ENV = 'PI_TRIGGER_INPUT_BASE64';
const PI_SUBAGENT_DEFAULTS_ENV = 'PI_SUBAGENT_DEFAULTS_BASE64';
const PI_TRIGGER_RUNTIME_SKILL = 'pi-trigger-runtime-input';
const PI_SUBAGENT_DEFAULTS_RUNTIME_SKILL = 'pi-subagent-defaults-runtime';

function decodeBase64Object(envName: string, requiredKeys: string[]) {
  const encoded = process.env[envName]?.trim();
  if (!encoded) {
    throw new Error(`${envName} is required for the PiTrigger runtime extension`);
  }

  let parsed: any;
  try {
    parsed = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  } catch (error: any) {
    throw new Error(`${envName} must contain base64-encoded JSON: ${error.message}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${envName} must decode to an object`);
  }

  for (const key of requiredKeys) {
    if (!parsed[key] || typeof parsed[key] !== 'object' || Array.isArray(parsed[key])) {
      throw new Error(`${envName}.${key} must be an object`);
    }
  }

  return parsed;
}

function renderRuntimeInputSkill(input: any) {
  return `---
name: ${PI_TRIGGER_RUNTIME_SKILL}
description: Provides the current PiTrigger triggering object payload and trigger metadata decoded from the injected runtime environment. Use when handling a PiTrigger-triggered worker job or when you need trigger, session, or job identity for the current execution.
---

# PiTrigger runtime input

The runtime extension decoded \`${PI_TRIGGER_INPUT_ENV}\` once at startup.
Treat the structured data below as the source of truth for this execution.

## Rules

- Do not look for mounted \`payload.json\` or \`metadata.json\` files; this runtime injects PiTrigger input through the environment instead.
- Use the decoded metadata below for job/session identity, output-location routing, and wake-up/restore decisions, especially with higher-level tools like \`handle_session_wakeup\`.
- Treat the environment variable itself as an implementation detail; rely on this decoded skill content instead of re-decoding it.
- Strongly separate the triggering object payload (the raw resource/object captured by the watch) from the trigger/session/job metadata below; do not conflate fields from \`payload\` with \`metadata\`.
- Do not wait for user clarification or prompt for interactive input; if the worker is blocked or uncertain it must call the \`decision_maker\` tool, then continue executing according to that decision and keep working autonomously until the task is solved or the job reaches \`TIMED_OUT\`.

## Trigger metadata

\`\`\`json
${JSON.stringify(input.metadata, null, 2)}
\`\`\`

## Trigger payload

\`\`\`json
${JSON.stringify(input.payload, null, 2)}
\`\`\`
`;
}

function renderSubAgentDefaultsSkill(defaults: any) {
  return `---
name: ${PI_SUBAGENT_DEFAULTS_RUNTIME_SKILL}
description: Provides the current PiTrigger sub-agent defaults decoded from injected runtime environment state. Use when a PiTrigger worker may create, hibernate, wake, or otherwise configure sub-agent PiTriggers or Jobs.
---

# PiTrigger sub-agent defaults

The runtime extension decoded \`${PI_SUBAGENT_DEFAULTS_ENV}\` once at startup.
Treat the structured JSON below as the canonical starting \`subAgentDefaults\` object for this execution.

## Rules

- When this skill is available, do not rely on a prompt-prefixed \`sub-agent defaults base64://...\` payload.
- Pass the decoded object below as \`subAgentDefaults\` to higher-level tools like \`resolve_subagent_defaults\`, \`choose_execution_mode\`, \`orchestrate_subagent_execution\`, or \`hibernate_session\`.
- If you need to tune fields such as \`piTriggerTimeout\`, copy the object below and add or adjust only the specific top-level fields needed for the current delegation round.
- Do not rewrite \`agent\` by hand unless the task explicitly requires changing worker runtime settings.
- Prefer the higher-level orchestration tools over low-level helpers such as \`prepare_session_hibernation\` unless you are debugging the hibernation planner itself.
- Treat the environment variable itself as an implementation detail; rely on this decoded skill content instead of re-decoding it.
- Do not wait for user clarification or prompt for interactive input; if the worker is blocked or uncertain it must call the `decision_maker` tool, then continue executing according to that decision and keep working autonomously until the task is solved or the job reaches `TIMED_OUT`.

## Canonical sub-agent defaults

\`\`\`json
${JSON.stringify(defaults, null, 2)}
\`\`\`

## PiAgentSpec

The embedded \`agent\` field above is the current PiTrigger worker's PiAgentSpec and should be reused for delegated worker PiTriggers unless the task explicitly requires a runtime change.
`;
}

function writeSkill(rootDir: string, skillName: string, content: string) {
  const skillDir = path.join(rootDir, skillName);
  fs.mkdirSync(skillDir, { recursive: true });
  fs.writeFileSync(path.join(skillDir, 'SKILL.md'), content, 'utf8');
  return skillDir;
}

export default function registerPiTriggerInput(pi: any) {
  const input = decodeBase64Object(PI_TRIGGER_INPUT_ENV, ['payload', 'metadata']);
  const subAgentDefaults = decodeBase64Object(PI_SUBAGENT_DEFAULTS_ENV, ['agent']);

  if (typeof subAgentDefaults.namespace !== 'string' || !subAgentDefaults.namespace.trim()) {
    throw new Error(`${PI_SUBAGENT_DEFAULTS_ENV}.namespace must be a non-empty string`);
  }

  const skillRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pi-trigger-runtime-skills-'));
  const runtimeInputSkillDir = writeSkill(skillRoot, PI_TRIGGER_RUNTIME_SKILL, renderRuntimeInputSkill(input));
  const subAgentDefaultsSkillDir = writeSkill(
    skillRoot,
    PI_SUBAGENT_DEFAULTS_RUNTIME_SKILL,
    renderSubAgentDefaultsSkill(subAgentDefaults)
  );

  pi.on('resources_discover', async () => ({
    skillPaths: [runtimeInputSkillDir, subAgentDefaultsSkillDir]
  }));

  pi.on('session_shutdown', async () => {
    fs.rmSync(skillRoot, { recursive: true, force: true });
  });
}
