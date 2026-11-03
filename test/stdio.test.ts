import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));

// Uses raw JSON-RPC so that any non-protocol byte on stdout fails the test. No network is needed.
test("built server speaks clean JSON-RPC on stdout and logs to stderr", async () => {
  const child = spawn(process.execPath, [entry], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));

  const responses = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out; stdout=${stdout} stderr=${stderr}`)), 10_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.includes('"id":2')) {
        clearTimeout(timer);
        resolve();
      }
    });
  });

  const send = (message: object) => child.stdin.write(`${JSON.stringify(message)}\n`);
  send({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "raw-test", version: "0" } },
  });
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list" });

  try {
    await responses;
  } finally {
    child.kill();
  }

  const messages = stdout.trim().split("\n").map((line) => JSON.parse(line));
  assert.ok(messages.every((m) => m.jsonrpc === "2.0"));
  assert.equal(messages[0].result.serverInfo.name, "zero-wire-mcp");
  assert.equal(messages[1].result.tools.length, 4);
  assert.match(stderr, /running on stdio/);
});
