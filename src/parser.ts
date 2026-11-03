import * as cheerio from "cheerio";
import { XMLParser, XMLValidator } from "fast-xml-parser";
import { z } from "zod";
import { FeedError } from "./errors.js";

const BRIEFING_PREFIX = "https://radar.cloudflare.com/security/zero-wire/";
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
// Far above real items (largest about 13 KB), low enough that hostile markup can't stall the HTML parser.
const MAX_ITEM_CHARS = 256 * 1024;
const MAX_LINK_CHARS = 2048;

export interface Link {
  text: string;
  url: string;
}

export interface Group {
  heading: string;
  text: string[];
  links: Link[];
}

export interface ChronologyEntry {
  date: string | null;
  text: string;
}

/** Every field comes from the feed. A field the feed lacks is null or empty, never inferred. */
export interface Briefing {
  id: string;
  title: string;
  sourceUrl: string;
  cveIds: string[];
  category: string | null;
  status: string | null;
  lastChecked: string | null;
  lastUpdated: string | null;
  author: string | null;
  tags: string[];
  summary: string | null;
  overview: string | null;
  whatHappened: string[];
  whyItMatters: string | null;
  whoShouldInvestigate: string | null;
  recommendedActions: { summary: string | null; steps: string[] };
  cloudflareCoverage: Group[];
  evidence: Group[];
  chronology: ChronologyEntry[];
  otherSections: Group[];
  assessmentPrompt: string | null;
  searchText: string;
}

export interface Feed {
  title: string | null;
  lastBuildDate: string | null;
  briefings: Briefing[];
  skippedItems: number;
}

const textNode = z.union([z.string(), z.object({ "#text": z.string().optional() }).passthrough()]);

const CategorySchema = z.union([
  z.string(),
  z.object({ "#text": z.string().optional(), "@_domain": z.string().optional() }).passthrough(),
]);

const ItemSchema = z
  .object({
    title: z.string().min(1),
    link: z.string().max(MAX_LINK_CHARS).startsWith(BRIEFING_PREFIX),
    pubDate: z.string().optional(),
    description: z.string().optional(),
    "dc:creator": z.string().optional(),
    "content:encoded": z.string().min(1).max(MAX_ITEM_CHARS),
    category: z.array(CategorySchema).default([]),
  })
  .passthrough();

const FeedSchema = z.object({
  rss: z.object({
    channel: z
      .object({
        title: textNode.optional(),
        lastBuildDate: z.string().optional(),
        item: z.array(z.unknown()).default([]),
      })
      .passthrough(),
  }),
});

const xml = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  parseTagValue: false,
  isArray: (name) => name === "item" || name === "category",
});

export function parseFeed(body: string): Feed {
  const invalid = () =>
    new FeedError("invalid", "The Zero Wire feed could not be parsed. Its format may have changed; no data was returned.");

  // The XML parser throws on external entities, reserved names and excessive nesting. Treat all of those as invalid.
  let document: unknown;
  try {
    if (XMLValidator.validate(body) !== true) throw invalid();
    document = xml.parse(body);
  } catch {
    throw invalid();
  }
  const parsed = FeedSchema.safeParse(document);
  if (!parsed.success) throw invalid();

  const channel = parsed.data.rss.channel;
  const briefings: Briefing[] = [];
  let skippedItems = 0;
  for (const raw of channel.item) {
    const item = ItemSchema.safeParse(raw);
    let briefing: Briefing | null = null;
    try {
      briefing = item.success ? parseItem(item.data) : null;
    } catch {
      // Pathological markup, such as nesting deep enough to overflow the stack, costs one item rather than the feed.
    }
    if (briefing) briefings.push(briefing);
    else skippedItems++;
  }
  if (channel.item.length > 0 && briefings.length === 0) throw invalid();

  return {
    title: typeof channel.title === "string" ? channel.title : null,
    lastBuildDate: toIsoDate(channel.lastBuildDate),
    briefings,
    skippedItems,
  };
}

function parseItem(item: z.infer<typeof ItemSchema>): Briefing | null {
  const sourceUrl = item.link.replace(/\/+$/, "");
  const id = sourceUrl.slice(BRIEFING_PREFIX.length);
  if (!/^[a-z0-9][a-z0-9-]*$/i.test(id)) return null;

  const cveIds: string[] = [];
  const tags: string[] = [];
  let category: string | null = null;
  for (const entry of item.category) {
    const value = (typeof entry === "string" ? entry : (entry["#text"] ?? "")).trim();
    if (!value) continue;
    if (CVE_PATTERN.test(value)) cveIds.push(value.toUpperCase());
    else if (typeof entry !== "string" && entry["@_domain"]) tags.push(value);
    else category ??= value;
  }

  const body = parseBody(item["content:encoded"], sourceUrl);
  const section = (pattern: RegExp) => body.sections.find((s) => pattern.test(s.heading));
  const firstText = (s: Section | undefined) => s?.paragraphs.join(" ") || null;

  const actions = section(/^what to do/i);
  const chronology = section(/^update chronology/i);
  const known = /^(update chronology|what happened|why |who should|what to do|cloudflare coverage|evidence and sources)/i;

  return {
    id,
    title: item.title,
    sourceUrl,
    cveIds: [...new Set(cveIds)],
    category,
    status: body.status,
    lastChecked: body.lastChecked,
    lastUpdated: toIsoDate(item.pubDate),
    author: item["dc:creator"] ?? null,
    tags,
    summary: body.overview ?? item.description ?? null,
    overview: body.overview,
    whatHappened: blockText(section(/^what happened/i)),
    whyItMatters: firstText(section(/^why /i)),
    whoShouldInvestigate: firstText(section(/^who should/i)),
    recommendedActions: { summary: firstText(actions), steps: actions?.items ?? [] },
    cloudflareCoverage: section(/^cloudflare coverage/i)?.subsections.map(toGroup) ?? [],
    evidence: section(/^evidence and sources/i)?.subsections.map(toGroup) ?? [],
    chronology: chronology?.chronology ?? [],
    otherSections: body.sections.filter((s) => !known.test(s.heading)).map(toGroup),
    assessmentPrompt: body.assessmentPrompt,
    searchText: normalise([item.title, cveIds.join(" "), tags.join(" "), category, body.status, body.text].join(" ")),
  };
}

interface Section {
  heading: string;
  paragraphs: string[];
  items: string[];
  links: Link[];
  chronology: ChronologyEntry[];
  pre: string | null;
  subsections: Section[];
}

interface Body {
  status: string | null;
  lastChecked: string | null;
  overview: string | null;
  sections: Section[];
  assessmentPrompt: string | null;
  text: string;
}

function parseBody(html: string, sourceUrl: string): Body {
  const $ = cheerio.load(html, null, false);
  const body: Body = { status: null, lastChecked: null, overview: null, sections: [], assessmentPrompt: null, text: clean($.root().text()) };

  let h2: Section | undefined;
  let current: Section | undefined;

  const collectLinks = (scope: ReturnType<typeof $>, into: Link[]) => {
    scope.find("a").each((_, a) => {
      const url = safeUrl($(a).attr("href"), sourceUrl);
      if (url) into.push({ text: clean($(a).text()), url });
    });
  };

  for (const el of $.root().children().toArray()) {
    const node = $(el);
    const tag = node.prop("tagName")?.toLowerCase();

    if (tag === "h2" || tag === "h3") {
      const section: Section = { heading: clean(node.text()), paragraphs: [], items: [], links: [], chronology: [], pre: null, subsections: [] };
      if (tag === "h2") {
        h2 = section;
        body.sections.push(section);
      } else if (h2) {
        h2.subsections.push(section);
      }
      current = section;
    } else if (tag === "p") {
      // Status line: <strong>status</strong> · Last checked <time>...</time>
      if (!current && !body.status && node.children("strong").length > 0 && node.find("time").length > 0) {
        body.status = clean(node.children("strong").first().text()) || null;
        body.lastChecked = node.find("time").first().attr("datetime") ?? null;
        continue;
      }
      if (!current) {
        body.overview ??= clean(node.text()) || null;
        continue;
      }
      // The feed closes each item with a self-link to the briefing; it is not evidence.
      const anchor = node.children("a").first();
      if (anchor.length > 0 && clean(anchor.text()) === clean(node.text()) && safeUrl(anchor.attr("href"), sourceUrl) === sourceUrl) continue;

      const text = clean(node.text());
      if (text) current.paragraphs.push(text);
      collectLinks(node, current.links);
    } else if (tag === "ul" || tag === "ol") {
      if (!current) continue;
      for (const li of node.children("li").toArray()) {
        const item = $(li);
        const time = item.find("time").first();
        if (time.length > 0 && /^update chronology/i.test(current.heading)) {
          const date = time.attr("datetime") ?? null;
          time.remove();
          current.chronology.push({ date, text: clean(item.text()).replace(/^:\s*/, "") });
        } else {
          const anchors = item.children("a");
          // Bullets that are only a link are represented by `links`.
          const linkOnly = anchors.length === 1 && clean(anchors.text()) === clean(item.text());
          if (!linkOnly) current.items.push(clean(item.text()));
        }
        collectLinks(item, current.links);
      }
    } else if (tag === "pre" && current) {
      // Kept exactly as published: no trimming or whitespace normalisation.
      current.pre = node.text();
      if (/assess your exposure/i.test(current.heading)) body.assessmentPrompt ??= current.pre;
    }
  }
  return body;
}

function blockText(section: Section | undefined): string[] {
  return section ? [...section.paragraphs, ...section.items] : [];
}

function toGroup(section: Section): Group {
  return { heading: section.heading, text: blockText(section), links: section.links };
}

function safeUrl(href: string | undefined, base: string): string | null {
  if (!href) return null;
  try {
    const url = new URL(href, base);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

function toIsoDate(value: string | undefined): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 10);
}

function clean(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

export function normalise(text: string): string {
  return clean(text).toLowerCase();
}
