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

const hostile = (items: string, prolog = "") =>
  `<?xml version="1.0"?>${prolog}<rss xmlns:content="c"><channel>${items}</channel></rss>`;
const hostileItem = (html: string, link = "https://radar.cloudflare.com/security/zero-wire/ok") =>
  `<item><title>T</title><link>${link}</link><content:encoded><![CDATA[${html}]]></content:encoded></item>`;

test("reports external entities and prototype pollution attempts as invalid feeds", () => {
  const external = hostile(hostileItem("<p>x</p>"), `<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`);
  const pollution = hostile(`${hostileItem("<p>x</p>")}<__proto__ polluted="yes"/>`);
  for (const body of [external, pollution]) {
    assert.throws(() => parseFeed(body), (error: FeedError) => error instanceof FeedError && error.kind === "invalid");
  }
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test("skips oversized items and links without stalling", () => {
  const good = hostileItem("<p>x</p>");
  const started = Date.now();
  const result = parseFeed(
    hostile(
      good +
        hostileItem("<a>".repeat(400_000)) +
        hostileItem("<p>x</p>", `https://radar.cloudflare.com/security/zero-wire/${"/".repeat(400_000)}a`),
    ),
  );
  assert.equal(result.briefings.length, 1);
  assert.equal(result.skippedItems, 2);
  assert.ok(Date.now() - started < 5000);
});

test("loses only the affected item when markup overflows the stack", () => {
  const result = parseFeed(hostile(hostileItem("<p>x</p>") + hostileItem(`${"<div>".repeat(50_000)}x`)));
  assert.equal(result.briefings.length, 1);
  assert.equal(result.skippedItems, 1);
});

test("treats active markup as inert text and keeps only web links", () => {
  const html = `<p>intro</p><h2>Evidence and sources</h2><h3>E</h3><ul><li><a href="javascript:alert(1)">a</a></li><li><a href="file:///etc/passwd">b</a></li><li><a href="data:text/html,x">c</a></li><li><a href="https://ok.example/">d</a></li></ul><script>globalThis.ZERO_WIRE_PWNED = true</script>`;
  const [briefing] = parseFeed(hostile(hostileItem(html))).briefings;
  assert.deepEqual(briefing?.evidence[0]?.links, [{ text: "d", url: "https://ok.example/" }]);
  assert.equal((globalThis as Record<string, unknown>).ZERO_WIRE_PWNED, undefined);
});

test("rejects a feed in which every item is invalid", () => {
  const body = `<rss><channel><item><title>x</title><link>https://evil.example/</link></item></channel></rss>`;
  assert.throws(() => parseFeed(body), FeedError);
});
