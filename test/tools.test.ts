import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { FeedClient } from "../src/feed.js";
import { createServer } from "../src/server.js";

const xml = readFileSync(new URL("./fixtures/synthetic-feed.xml", import.meta.url), "utf8");

async function connect(fetchImpl: typeof fetch) {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0.0.0" });
  const feed = new FeedClient({ fetchImpl, maxRetries: 0, minIntervalMs: 0 });
  await Promise.all([createServer(feed).connect(serverSide), client.connect(clientSide)]);
  return client;
}

let client: Client;
before(async () => {
  client = await connect((async () =>
    new Response(xml, { status: 200, headers: { "content-type": "application/rss+xml" } })) as unknown as typeof fetch);
});

async function call(name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content as { type: string; text: string }[])[0]?.text ?? "";
  return { isError: result.isError === true, text, data: result.isError ? undefined : JSON.parse(text) };
}
const ids = (data: { briefings: { id: string }[] }) => data.briefings.map((b) => b.id);

test("discovers exactly the four read-only tools", async () => {
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ["get_assessment_prompt", "get_vulnerability", "list_vulnerabilities", "search_vulnerabilities"]);
  for (const tool of tools) assert.equal(tool.annotations?.readOnlyHint, true, tool.name);
});

test("list_vulnerabilities returns the required fields", async () => {
  const { data } = await call("list_vulnerabilities");
  assert.equal(data.count, 3);
  assert.deepEqual(data.briefings[1], {
    id: "gizmo2shell",
    title: "gizmo2shell",
    cveIds: ["CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"],
    status: "Assess your exposure",
    category: "Needs attention",
    lastChecked: "2099-01-01",
    summary: "Three gizmo flaws, no agent prompt.",
    tags: ["mTLS"],
    hasAssessmentPrompt: false,
    sourceUrl: "https://radar.cloudflare.com/security/zero-wire/gizmo2shell",
  });
  assert.match(data.notice, /not a comprehensive CVE database/);
  assert.match(data.source.feedUrl, /zero-wire\/rss$/);
});

test("get_vulnerability returns structured details", async () => {
  const { data } = await call("get_vulnerability", { id: "widget-server-takeover" });
  assert.equal(data.overview, "A widget server flaw & its neighbor can't be trusted.");
  assert.deepEqual(data.affectedTechnologies, { tags: ["Kernel", "Memory corruption"], whoShouldInvestigate: "Anyone running widget servers." });
  assert.deepEqual(data.exploitationEvidence.map((g: { heading: string }) => g.heading), ["Exploit evidence"]);
  assert.deepEqual(data.vendorAdvisories.map((g: { heading: string }) => g.heading), ["Vendor advisory"]);
  assert.deepEqual(data.cloudflareMitigation[1], { heading: "Service status", text: ["Cloudflare was not impacted."], links: [] });
  assert.equal(data.chronology.length, 2);
  assert.equal(data.lastChecked, "2099-01-03");
  assert.equal(data.sourceUrl, "https://radar.cloudflare.com/security/zero-wire/widget-server-takeover");
  assert.equal(data.prompt, undefined);
  assert.equal(data.searchText, undefined);
});

test("get_vulnerability accepts every identifier form", async () => {
  for (const id of [
    "CVE-2099-0001",
    "cve-2099-0001",
    "  CVE-2099-0001 ",
    "2099-0001",
    "CVE‐2099‐0001",
    "WIDGET-server-takeover",
    "widget-server-takeover@2099-01-02",
    "Widget Server Takeover",
    "https://radar.cloudflare.com/security/zero-wire/widget-server-takeover/",
  ]) {
    const { data, isError } = await call("get_vulnerability", { id });
    assert.equal(isError, false, id);
    assert.equal(data.id, "widget-server-takeover", id);
  }
});

test("every CVE in a multi-CVE briefing resolves to it", async () => {
  for (const id of ["CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"]) {
    const { data } = await call("get_vulnerability", { id });
    assert.equal(data.id, "gizmo2shell");
    assert.equal(data.cveIds.length, 3);
  }
});

test("an unknown CVE is an error that explains the feed is curated", async () => {
  const { isError, text } = await call("get_vulnerability", { id: "CVE-2099-9999" });
  assert.equal(isError, true);
  assert.match(text, /curated/);
  assert.match(text, /says nothing about whether a CVE exists/);
});

test("absent fields stay empty in tool output", async () => {
  const { data } = await call("get_vulnerability", { id: "certificate-compromise" });
  assert.deepEqual(data.cveIds, []);
  assert.equal(data.whyItMatters, null);
  assert.deepEqual(data.exploitationEvidence, []);
  assert.deepEqual(data.vendorAdvisories, []);
});

test("search matches CVE IDs case-insensitively and exactly", async () => {
  assert.deepEqual(ids((await call("search_vulnerabilities", { cve: "cve-2099-0003" })).data), ["gizmo2shell"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { cve: "2099-0001" })).data), ["widget-server-takeover"]);
  // "CVE-2099-00011" contains no fixture ID, and must not partially match CVE-2099-0001.
  assert.equal((await call("search_vulnerabilities", { cve: "CVE-2099-00011" })).data.count, 0);
  assert.equal((await call("search_vulnerabilities", { cve: "nonsense" })).isError, true);
  assert.equal((await call("search_vulnerabilities", { cve: "CVE-2099-000" })).isError, true);
});

test("search matches keywords across briefing text, with all terms required", async () => {
  assert.deepEqual(ids((await call("search_vulnerabilities", { keyword: "GIZMO" })).data), ["widget-server-takeover", "gizmo2shell"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { keyword: "server gizmo parsing" })).data), ["widget-server-takeover"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { keyword: "cve-2099-0004" })).data), ["gizmo2shell"]);
  const none = await call("search_vulnerabilities", { keyword: "no-such-term" });
  assert.equal(none.data.count, 0);
  assert.match(none.data.notice, /curated/);
});

test("search matches tags by whole word", async () => {
  assert.deepEqual(ids((await call("search_vulnerabilities", { tag: "kernel" })).data), ["widget-server-takeover"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { tag: "memory" })).data), ["widget-server-takeover"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { tag: "memory-corruption" })).data), ["widget-server-takeover"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { tag: "TLS" })).data), ["certificate-compromise"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { tag: "mtls" })).data), ["gizmo2shell"]);
});

test("search matches feed statuses, site status labels and categories", async () => {
  assert.deepEqual(ids((await call("search_vulnerabilities", { status: "Patch" })).data), ["widget-server-takeover"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { status: "assess exposure" })).data), ["gizmo2shell"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { status: "review settings" })).data), ["certificate-compromise"]);
  assert.deepEqual(ids((await call("search_vulnerabilities", { status: "reference" })).data), ["certificate-compromise"]);
  assert.equal((await call("search_vulnerabilities", { status: "needs attention" })).data.count, 2);
});

test("search combines filters with AND and requires one", async () => {
  assert.deepEqual(ids((await call("search_vulnerabilities", { keyword: "gizmo", status: "patch" })).data), ["widget-server-takeover"]);
  assert.equal((await call("search_vulnerabilities", { keyword: "gizmo", tag: "TLS" })).data.count, 0);
  const empty = await call("search_vulnerabilities");
  assert.equal(empty.isError, true);
  assert.match(empty.text, /at least one/);
});

test("get_assessment_prompt returns the original text with provenance", async () => {
  const { data } = await call("get_assessment_prompt", { id: "cve-2099-0001" });
  assert.equal(data.available, true);
  assert.ok(data.prompt.startsWith("  Assess CVE-2099-0001 & don't change anything.\n\n1. Run"));
  assert.match(data.provenance, /Verbatim/);
  assert.match(data.handling, /not executed/);
});

test("get_assessment_prompt reports absence without a substitute", async () => {
  const { data, isError } = await call("get_assessment_prompt", { id: "gizmo2shell" });
  assert.equal(isError, false);
  assert.equal(data.available, false);
  assert.equal(data.prompt, null);
  assert.match(data.message, /No substitute/);
});

test("feed outages surface as readable tool errors on every tool", async () => {
  const down = await connect((async () => new Response("", { status: 503 })) as unknown as typeof fetch);
  for (const [name, args] of [
    ["list_vulnerabilities", {}],
    ["get_vulnerability", { id: "x" }],
    ["search_vulnerabilities", { keyword: "x" }],
    ["get_assessment_prompt", { id: "x" }],
  ] as const) {
    const result = await down.callTool({ name, arguments: args });
    assert.equal(result.isError, true, name);
    assert.match((result.content as { text: string }[])[0]?.text ?? "", /currently unavailable \(HTTP 503\)/);
  }
});
