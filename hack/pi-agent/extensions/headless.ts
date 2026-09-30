import { spawn } from "child_process";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import * as crypto from "crypto";
import * as headlessOutput from "./headless_output.cjs";
import registerExtensionRuntime from "./extension-runtime.mjs";

export default function (pi: any) {
  // Preserve the original headless tool metadata and behavior but route lifecycle through the shared runtime helper
  const toolMeta = {
    name: "headless",
    description: "Executes a task in a headless sub-process using pi with TTY allocation.",
    parameters: {
      type: "object",
      properties: {
        prompt: {
          type: "string",
          description: "Task instruction or command for the worker"
        },
        cwd: {
          type: "string",
          description: "Working directory for the worker process (defaults to current process CWD)"
        },
        provider: {
          type: "string",
          description: "Provider to use for the headless pi subprocess"
        },
        model: {
          type: "string",
          description: "Model to use for the headless pi subprocess"
        }
      },
      required: ["prompt"]
    },
    execute: async (args: any, context: any) => {
      const isToolParamsObject = (value: any): value is Record<string, unknown> => {
        if (!value || typeof value !== "object") return false;

        return ["prompt", "command", "task", "instruction", "text", "cwd", "provider", "model"]
          .some((key) => key in value);
      };

      const toolParams = isToolParamsObject(args)
        ? args
        : isToolParamsObject(context?.args)
          ? context.args
          : isToolParamsObject(context)
            ? context
            : null;

      const extractPrompt = (rawArgs: any, ctx: any): string => {
        if (!rawArgs) return "";

        if (typeof rawArgs === "object" && rawArgs !== null) {
          for (const key of ["prompt", "command", "task", "instruction", "text"]) {
            if (rawArgs[key] && typeof rawArgs[key] === "string") {
              return rawArgs[key];
            }
          }
        }

        if (typeof rawArgs === "string" && !rawArgs.startsWith("call_")) {
          return rawArgs;
        }

        if (ctx && typeof ctx === "object") {
          if (ctx.prompt && typeof ctx.prompt === "string") return ctx.prompt;
          if (ctx.args && typeof ctx.args === "object" && ctx.args.prompt) return ctx.args.prompt;
        }

        return "";
      };

      let cleanPrompt = extractPrompt(toolParams ?? args, context).trim();

      if (!cleanPrompt && typeof args === "string" && args.startsWith("call_")) {
        cleanPrompt = "";
      }

      if (!cleanPrompt) {
        return {
          content: [
            {
              type: "text",
              text: `Error: Could not extract valid prompt from arguments: ${JSON.stringify(args)}`
            }
          ],
          isError: true
        };
      }

      const targetCwd = toolParams && typeof toolParams.cwd === "string"
        ? path.resolve(toolParams.cwd)
        : process.cwd();

      // Ensure global ~/.pi/agent/.headless directory exists
      const headlessDir = path.join(os.homedir(), ".pi", "agent", ".headless");
      if (!fs.existsSync(headlessDir)) {
        fs.mkdirSync(headlessDir, { recursive: true });
      }

      const runId = `${new Date().toISOString().replace(/[:.]/g, "-")}_${crypto.randomBytes(3).toString("hex")}`;
      const logPath = path.join(headlessDir, `${runId}.log`);

      const provider = toolParams && typeof toolParams.provider === "string"
        ? String(toolParams.provider)
        : "github-copilot";
      const model = toolParams && typeof toolParams.model === "string"
        ? String(toolParams.model)
        : "gpt-5-mini";

      const formattedPrompt = `You are a headless Pi worker running without a human; you must never wait for or request user clarification or input. If you become blocked or uncertain, call the 'decision_maker' tool immediately to choose the next action, then continue executing that decision; do not treat clarification as terminal. Keep working to complete the task until you either succeed (produce a final actionable answer) or are explicitly terminated with TIMED_OUT; do not exit early for clarification-like messages. Execute the necessary tool or shell commands to complete the request below.\n\nPrompt: ${cleanPrompt}`;

      const extractLastOutputLines = (rawOutput: string): string => headlessOutput
        .stripAnsi(String(rawOutput || ""))
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n")
        .split("\n")
        .map((line: string) => line.trimEnd())
        .filter((line: string) => line.trim())
        .slice(-2)
        .join("\n");

      const looksLikeClarificationRequest = (text: string): boolean => {
        const normalized = String(text || "").trim().toLowerCase();
        if (!normalized) return false;

        const clarificationPattern = /\b(i need\b.*\b(detail|details|info|information|clarification)\b|but i[’']ll need\b|need a bit more detail|please provide|could you clarify|can you clarify|what path|what filename|which path|which file|which filename)\b/i;
        if (clarificationPattern.test(normalized)) return true;

        return normalized.endsWith("?") && /^(what|which|where|who|could you|can you|please provide)\b/i.test(normalized);
      };

      return new Promise((resolve) => {
        // Stream raw execution output directly to disk
        const logStream = fs.createWriteStream(logPath, { flags: "a", encoding: "utf-8" });

        const initialHeader = `METADATA: ${JSON.stringify({
          runId,
          cwd: targetCwd,
          provider,
          model
        }, null, 2)}\n\nPROMPT: ${cleanPrompt}\n\n--- RAW OUTPUT START ---\n`;

        logStream.write(initialHeader);

        let isSettled = false;
        let timer: ReturnType<typeof setTimeout> | null = null;

        const finalizeLogAndResolve = (
          errorMessage: string | null,
          metadata: Record<string, unknown> = {},
          finalAnswer: string = "",
          outputTail: string = ""
        ) => {
          if (isSettled) return;
          isSettled = true;

          if (timer) {
            clearTimeout(timer);
            timer = null;
          }

          const finalMetadata: Record<string, unknown> = {
            runId,
            logPath,
            status: errorMessage ? "error" : "success",
            errorMessage,
            taskCompleted: !errorMessage,
            ...metadata
          };

          if (finalAnswer) {
            finalMetadata.finalAnswer = finalAnswer;
          }

          if (outputTail) {
            finalMetadata.lastOutputLines = outputTail;
          }

          if (errorMessage) {
            finalMetadata.displayMessage = [
              errorMessage,
              outputTail ? `Last output lines:\n${outputTail}` : "",
              `Full response logged to: ${logPath}`
            ].filter(Boolean).join("\n\n");
          }

          const footer = `\n--- RAW OUTPUT END ---\n\nFINAL METADATA: ${JSON.stringify(finalMetadata, null, 2)}\n`;

          logStream.write(footer);
          logStream.end();

          resolve({
            content: [
              {
                type: "text",
                text: JSON.stringify(finalMetadata, null, 2)
              }
            ],
            isError: finalMetadata.status !== "success"
          });
        };

        const pythonPtyCmd = `import pty, os, sys; pty.spawn(['pi', '--mode', 'json', '--no-session', '--provider', sys.argv[2], '--model', sys.argv[3], '-p', sys.argv[1]])`;

        const child = spawn("python3", ["-c", pythonPtyCmd, formattedPrompt, provider, model], {
          cwd: targetCwd,
          env: {
            ...process.env,
            CI: "true",
            PYTHONUNBUFFERED: "1",
            TERM: "xterm-256color"
          },
          stdio: ["pipe", "pipe", "pipe"]
        });

        let accumulatedOutput = "";

        child.stdin.end();

        const TIMEOUT_MS = 10 * 60 * 1000;
        timer = setTimeout(() => {
          child.kill("SIGKILL");
          finalizeLogAndResolve(
            "Execution timed out after 10 minutes.",
            { timeoutMs: TIMEOUT_MS },
            "",
            extractLastOutputLines(accumulatedOutput)
          );
        }, TIMEOUT_MS);

        const handleData = (chunk: Buffer) => {
          const str = chunk.toString();
          accumulatedOutput += str;
          logStream.write(str);
        };

        child.stdout.on("data", handleData);
        child.stderr.on("data", handleData);

        child.on("close", (code) => {
          const cleanText = headlessOutput.stripAnsi(accumulatedOutput);
          const outputTail = extractLastOutputLines(cleanText);

          const errors = [...cleanText.matchAll(new RegExp(/reflections allowed, stopping/i, "g"))];
          if (errors.length !== 0) {
            return finalizeLogAndResolve("Error: Max reflections allowed, stopping.", { exitCode: code }, "", outputTail);
          }

          // Parse NDJSON lines from worker output
          const lines = cleanText.split(/\r?\n/);
          let finalAnswer = "";
          let responseErrorMessage = "";
          let responseStopReason = "";
          let toolExecutionCount = 0;

          const captureAssistantMessage = (assistantMsg: any) => {
            if (!assistantMsg || assistantMsg.role !== "assistant") return;

            if (typeof assistantMsg.errorMessage === "string" && assistantMsg.errorMessage.trim()) {
              responseErrorMessage = assistantMsg.errorMessage.trim();
            }

            if (typeof assistantMsg.stopReason === "string" && assistantMsg.stopReason.trim()) {
              responseStopReason = assistantMsg.stopReason.trim();
            }

            if (Array.isArray(assistantMsg.content)) {
              const textBlocks = assistantMsg.content
                .filter((c: any) => c.type === "text" && typeof c.text === "string")
                .map((c: any) => c.text)
                .filter(Boolean);

              if (textBlocks.length > 0) {
                finalAnswer = textBlocks.join("\n").trim();
              }
            }
          };

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed.startsWith("{")) continue;

            try {
              const event = JSON.parse(trimmed);

              if (event.type === "message_end" && event.message?.role === "assistant") {
                captureAssistantMessage(event.message);
              }

              if (event.type === "tool_execution_end") {
                toolExecutionCount += 1;
              }

              if (event.type === "agent_end" && Array.isArray(event.messages)) {
                const assistantMsg = event.messages
                  .slice()
                  .reverse()
                  .find((m: any) => m.role === "assistant");

                captureAssistantMessage(assistantMsg);
              }
            } catch (e) {
              // Ignore invalid JSON lines
            }
          }

          if (!finalAnswer) {
            finalAnswer = headlessOutput.extractHeadlessFinalAnswer(cleanText);
          }

          const responseFailure = responseErrorMessage
            || ((responseStopReason === "error" || responseStopReason === "aborted")
              ? `Worker reported stopReason "${responseStopReason}" without an errorMessage.`
              : "");

          if (responseFailure) {
            return finalizeLogAndResolve(responseFailure, { exitCode: code, stopReason: responseStopReason, toolExecutionCount }, "", outputTail);
          }

          // Note: Clarification-style outputs are no longer treated as a terminal "needs_input" condition for headless workers; the worker prompt is hardened to never wait for user input and to call decision_maker when uncertain, so continue to normal handling below.

          if (code !== 0 || !finalAnswer) {
            const errReason = code !== 0
              ? `Worker process exited with code ${code}.`
              : "Worker completed, but no valid answer could be extracted from JSON output.";
            return finalizeLogAndResolve(`Error: ${errReason}`, { exitCode: code, stopReason: responseStopReason, toolExecutionCount }, "", outputTail);
          }

          finalizeLogAndResolve(null, { exitCode: code, stopReason: responseStopReason, toolExecutionCount, taskCompleted: true }, finalAnswer);
        });

        child.on("error", (err) => {
          finalizeLogAndResolve(`Failed to spawn worker process: ${err.message}`, {
            spawnError: err.message
          }, "", extractLastOutputLines(accumulatedOutput));
        });
      });
    }
  };

  // Lightweight discovery snapshot for runtime skills (local/runtime-oriented)
  const discoverFn = async () => {
    try {
      return {
        status: "ok",
        fetchedAt: new Date().toISOString(),
        runtime: {
          platform: process.platform,
          nodeVersion: process.version,
          cwd: process.cwd()
        },
        tools: [{ name: toolMeta.name, description: toolMeta.description }]
      };
    } catch (err: any) {
      return {
        status: "error",
        fetchedAt: new Date().toISOString(),
        message: err?.message || String(err)
      };
    }
  };

  const renderSkillFn = (snapshot: any) => {
    return `Headless Runtime Snapshot\n\nTool: ${toolMeta.name}\nDescription: ${toolMeta.description}\nFetchedAt: ${snapshot?.fetchedAt}\nRuntime: ${JSON.stringify(snapshot?.runtime || {}, null, 2)}\n`;
  };

  // Route registration and resources_discover lifecycle through the shared helper
  // Note: we intentionally do not await the async helper so the export remains synchronous in shape
  registerExtensionRuntime(pi, toolMeta, discoverFn, renderSkillFn);
}