#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { FeedClient } from "./feed.js";
import { createServer } from "./server.js";

// stdout carries MCP protocol messages only. All diagnostics go to stderr.
try {
  await createServer(new FeedClient()).connect(new StdioServerTransport());
  console.error("[zero-wire-mcp] running on stdio");
} catch (error) {
  console.error("[zero-wire-mcp] failed to start:", error);
  process.exit(1);
}
