import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// Runs the built server over real stdio against the live Cloudflare feed (npm run test:live).
// Specific CVEs asserted here may eventually leave the feed; update them if that happens.
const entry = fileURLToPath(new URL("../../dist/index.js", import.meta.url));
const client = new Client({ name: "zero-wire-live-test", version: "0.0.0" });

before(async () => {
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry] }));
});
after(async () => {
  await client.close();
});

async function call(name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content as { text: string }[])[0]?.text ?? "";
  assert.notEqual(result.isError, true, text);
  return JSON.parse(text);
}

test("lists live briefings with their required fields", async () => {
  const data = await call("list_vulnerabilities");
  assert.ok(data.count > 0);
  for (const b of data.briefings) {
    assert.ok(b.title, b.id);
    assert.ok(b.status, `${b.id} status`);
    assert.ok(["Needs attention", "Reference"].includes(b.category), `${b.id} category: ${b.category}`);
    assert.match(b.lastChecked, /^\d{4}-\d{2}-\d{2}$/, b.id);
    assert.ok(b.summary, `${b.id} summary`);
    assert.ok(b.sourceUrl.startsWith("https://radar.cloudflare.com/security/zero-wire/"), b.id);
  }
});

test("retrieves CVE-2026-98432 with full details", async () => {
  const b = await call("get_vulnerability", { id: "cve-2026-98432" });
  assert.equal(b.id, "linux-ipv4-tcp-use-after-free");
  assert.deepEqual(b.cveIds, ["CVE-2026-98432"]);
  assert.ok(b.overview);
  assert.ok(b.whatHappened.length > 0);
  assert.ok(b.affectedTechnologies.tags.includes("Kernel"));
  assert.ok(b.affectedTechnologies.whoShouldInvestigate);
  assert.ok(b.exploitationEvidence.length > 0);
  assert.ok(b.recommendedActions.steps.length > 0);
  assert.ok(b.vendorAdvisories.flatMap((g: { links: unknown[] }) => g.links).length > 0);
  assert.ok(b.cloudflareMitigation.length > 0);
  assert.ok(b.chronology.length > 0);
});

test("resolves every CVE of a multi-CVE briefing", async () => {
  const { briefings } = await call("list_vulnerabilities");
  const multi = briefings.filter((b: { cveIds: string[] }) => b.cveIds.length > 1);
  assert.ok(multi.length > 0, "expected at least one multi-CVE briefing");
  for (const expected of multi) {
    for (const id of expected.cveIds) {
      assert.equal((await call("get_vulnerability", { id })).id, expected.id, id);
    }
  }
});

test("handles a briefing without any CVE", async () => {
  const { briefings } = await call("list_vulnerabilities");
  const noCve = briefings.find((b: { cveIds: string[] }) => b.cveIds.length === 0);
  assert.ok(noCve, "expected at least one briefing without a CVE");
  assert.equal((await call("get_vulnerability", { id: noCve.id })).id, noCve.id);
});

test("searches live data on each dimension", async () => {
  const ids = (data: { briefings: { id: string }[] }) => data.briefings.map((b) => b.id);
  assert.ok(ids(await call("search_vulnerabilities", { cve: "CVE-2026-98432" })).includes("linux-ipv4-tcp-use-after-free"));
  assert.ok(ids(await call("search_vulnerabilities", { keyword: "mptcp" })).includes("linux-ipv4-tcp-use-after-free"));
  assert.ok(ids(await call("search_vulnerabilities", { tag: "kernel" })).includes("linux-ipv4-tcp-use-after-free"));
  assert.ok(ids(await call("search_vulnerabilities", { status: "patch" })).includes("linux-ipv4-tcp-use-after-free"));
  assert.ok((await call("search_vulnerabilities", { status: "needs attention" })).count > 0);
});

test("returns published prompts and reports missing ones", async () => {
  const { briefings } = await call("list_vulnerabilities");
  for (const b of briefings) {
    const data = await call("get_assessment_prompt", { id: b.id });
    assert.equal(data.available, b.hasAssessmentPrompt, b.id);
    if (data.available) {
      assert.match(data.prompt, /read-only/i, b.id);
      assert.ok(data.prompt.includes(b.sourceUrl), b.id);
    } else {
      assert.equal(data.prompt, null, b.id);
    }
  }
  const prompt = await call("get_assessment_prompt", { id: "CVE-2026-98432" });
  assert.equal(prompt.available, true);
  assert.ok(prompt.prompt.startsWith("Assess whether the infrastructure available to you is affected by CVE-2026-98432"));
});
