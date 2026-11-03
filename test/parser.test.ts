import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { FeedError } from "../src/feed.js";
import { parseFeed } from "../src/parser.js";

const xml = readFileSync(new URL("./fixtures/synthetic-feed.xml", import.meta.url), "utf8");
const feed = parseFeed(xml);
const byId = (id: string) => {
  const briefing = feed.briefings.find((b) => b.id === id);
  assert.ok(briefing, `missing ${id}`);
  return briefing;
};

test("keeps valid items and counts rejected ones", () => {
  assert.deepEqual(
    feed.briefings.map((b) => b.id),
    ["widget-server-takeover", "gizmo2shell", "certificate-compromise"],
  );
  assert.equal(feed.skippedItems, 2);
  assert.equal(feed.lastBuildDate, "2099-01-02");
});

test("extracts metadata, status and categories", () => {
  const b = byId("widget-server-takeover");
  assert.equal(b.title, "Widget server takeover");
  assert.equal(b.status, "Prioritize patching");
  assert.equal(b.category, "Needs attention");
  assert.equal(b.lastChecked, "2099-01-03");
  assert.equal(b.lastUpdated, "2099-01-02");
  assert.equal(b.author, "Test Author");
  assert.deepEqual(b.cveIds, ["CVE-2099-0001"]);
  assert.deepEqual(b.tags, ["Kernel", "Memory corruption"]);
  assert.equal(b.sourceUrl, "https://radar.cloudflare.com/security/zero-wire/widget-server-takeover");
});

test("decodes HTML entities in prose", () => {
  assert.equal(byId("widget-server-takeover").overview, "A widget server flaw & its neighbor can't be trusted.");
});

test("parses each section without mixing content between them", () => {
  const b = byId("widget-server-takeover");
  assert.deepEqual(b.whatHappened, ["First fact about the widget server.", "Second fact about gizmo parsing."]);
  assert.equal(b.whyItMatters, "Attackers can reach it before login.");
  assert.equal(b.whoShouldInvestigate, "Anyone running widget servers.");
  assert.deepEqual(b.recommendedActions, {
    summary: "Update the widget server.",
    steps: ["Inventory widget servers.", "Apply the vendor fix."],
  });
  assert.deepEqual(b.chronology, [
    { date: "2099-01-01", text: "The vendor published an advisory." },
    { date: "2099-01-02", text: "A: research exploit appeared." },
  ]);
});

test("keeps same-named subsections under their own parent", () => {
  const b = byId("widget-server-takeover");
  assert.deepEqual(b.cloudflareCoverage.map((g) => g.heading), ["Product coverage", "Service status"]);
  assert.deepEqual(b.cloudflareCoverage[0]?.text, ["WAF rules reduce exposure."]);
  assert.deepEqual(b.evidence.map((g) => g.heading), ["Vendor advisory", "Exploit evidence", "Product coverage"]);
  assert.deepEqual(b.evidence[2]?.text, ["Evidence for coverage."]);
});

test("drops unsafe links and the closing self-link", () => {
  const urls = byId("widget-server-takeover").evidence.flatMap((g) => g.links.map((l) => l.url));
  assert.deepEqual(urls, ["https://vendor.example/advisory", "https://research.example/post", "https://docs.example/waf"]);
});

test("preserves the assessment prompt verbatim", () => {
  assert.equal(
    byId("widget-server-takeover").assessmentPrompt,
    "  Assess CVE-2099-0001 & don't change anything.\n\n1. Run  checks: uname -r\n   keep this indentation\n\nFind more at https://radar.cloudflare.com/security/zero-wire/widget-server-takeover\n",
  );
});

test("handles multiple CVEs and normalises their case", () => {
  assert.deepEqual(byId("gizmo2shell").cveIds, ["CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"]);
});

test("leaves absent fields empty instead of inventing them", () => {
  const b = byId("certificate-compromise");
  assert.deepEqual(b.cveIds, []);
  assert.equal(b.category, "Reference");
  assert.equal(b.whyItMatters, null);
  assert.equal(b.whoShouldInvestigate, null);
  assert.equal(b.assessmentPrompt, null);
  assert.equal(b.author, null);
  assert.deepEqual(b.whatHappened, []);
  assert.deepEqual(b.recommendedActions, { summary: null, steps: [] });
  assert.deepEqual(b.chronology, []);
  assert.deepEqual(b.evidence, []);
  assert.equal(byId("gizmo2shell").assessmentPrompt, null);
});

test("rejects content that is not a Zero Wire feed", () => {
  for (const body of ["<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><br></body></html>", "not xml", "<rss></rss>", ""]) {
    assert.throws(() => parseFeed(body), FeedError, body);
  }
});

test("rejects a feed in which every item is invalid", () => {
  const body = `<rss><channel><item><title>x</title><link>https://evil.example/</link></item></channel></rss>`;
  assert.throws(() => parseFeed(body), FeedError);
});
