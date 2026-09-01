import { describe, expect, it } from "vitest";
import { buildCodexArgs, parseCodexEventLine } from "../codex-runner.js";

describe("Codex runner protocol", () => {
  it("builds a new-session invocation", () => {
    const args = buildCodexArgs(
      {
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "build a calculator",
        threadId: null,
      },
      "workspace-write",
    );
    expect(args).toEqual([
      "exec",
      "--json",
      "--sandbox",
      "workspace-write",
      "--skip-git-repo-check",
      "-C",
      "/tmp/workspace",
      "build a calculator",
    ]);
  });

  it("resumes a stored Codex thread", () => {
    const args = buildCodexArgs(
      {
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "add tests",
        threadId: "thread-123",
      },
      "workspace-write",
    );
    expect(args.slice(-3)).toEqual(["resume", "thread-123", "add tests"]);
  });

  it("extracts the session, final message, usage, and progress events", () => {
    const parsed = {
      messages: [] as string[],
      threadId: null as string | null,
      usage: null as {
        inputTokens?: number;
        cachedInputTokens?: number;
        outputTokens?: number;
      } | null,
      errors: [] as string[],
      events: [] as Array<{ type: string; label: string; summary: string; detail?: string }>,
    };
    parseCodexEventLine(
      JSON.stringify({ type: "thread.started", thread_id: "thread-123" }),
      parsed,
    );
    parseCodexEventLine(
      JSON.stringify({
        type: "item.completed",
        item: {
          type: "file_edit_call",
          path: "/workspace/Main.java",
          summary: "Created a hello world Java class.",
        },
      }),
      parsed,
    );
    parseCodexEventLine(
      JSON.stringify({
        type: "item.completed",
        item: { type: "agent_message", text: "Done." },
      }),
      parsed,
    );
    parseCodexEventLine(
      JSON.stringify({
        type: "turn.completed",
        usage: { input_tokens: 10, output_tokens: 4 },
      }),
      parsed,
    );
    expect(parsed.threadId).toBe("thread-123");
    expect(parsed.messages).toEqual(["Done."]);
    expect(parsed.usage).toEqual({ inputTokens: 10, outputTokens: 4 });
    expect(parsed.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "file_edit_call",
          label: "File edit",
          summary: "Created a hello world Java class.",
          detail: "/workspace/Main.java",
        }),
      ]),
    );
  });

  it("formats command activity without repeating the command and redacts token values", () => {
    const parsed = {
      messages: [] as string[],
      threadId: null as string | null,
      usage: null as {
        inputTokens?: number;
        cachedInputTokens?: number;
        outputTokens?: number;
      } | null,
      errors: [] as string[],
      events: [] as Array<{ type: string; label: string; summary: string; detail?: string }>,
    };
    parseCodexEventLine(
      JSON.stringify({
        type: "item.completed",
        item: {
          type: "command_execution",
          command: "curl --token=secret-value https://example.test",
          output: "ok",
        },
      }),
      parsed,
    );

    expect(parsed.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "command_execution",
          label: "Command",
          summary: "Ran command",
          detail: "Command: curl --token=[redacted] https://example.test\nOutput: ok",
        }),
      ]),
    );
  });
});
