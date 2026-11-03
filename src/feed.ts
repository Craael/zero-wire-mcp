import { FeedError } from "./errors.js";
import { parseFeed, type Feed } from "./parser.js";

export { FeedError };

export const FEED_URL = "https://radar.cloudflare.com/security/zero-wire/rss";
const USER_AGENT = "zero-wire-mcp/0.1.0 (unofficial community MCP server)";
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_RETRY_AFTER_MS = 20_000;

export interface FeedClientOptions {
  url?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxRetries?: number;
  ttlMs?: number;
  minIntervalMs?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export interface FeedResult {
  feed: Feed;
  fetchedAt: string;
}

/** Fetches the public Zero Wire RSS feed with timeouts, retries and a short in-memory cache. */
export class FeedClient {
  private readonly url: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly ttlMs: number;
  private readonly minIntervalMs: number;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private cached?: { result: FeedResult; expiresAt: number };
  private inFlight?: Promise<FeedResult>;
  private lastRequestAt = Number.NEGATIVE_INFINITY;

  constructor(options: FeedClientOptions = {}) {
    this.url = options.url ?? FEED_URL;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxRetries = options.maxRetries ?? 1;
    // Matches the feed's own Cache-Control: max-age=300.
    this.ttlMs = options.ttlMs ?? 5 * 60_000;
    // Matches Crawl-delay: 10 in radar.cloudflare.com/robots.txt, and also spaces out retries.
    this.minIntervalMs = options.minIntervalMs ?? 10_000;
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  async get(): Promise<FeedResult> {
    if (this.cached && this.now() < this.cached.expiresAt) return this.cached.result;
    if (this.inFlight) return this.inFlight;

    this.inFlight = this.fetchWithRetries()
      .then((result) => {
        this.cached = { result, expiresAt: this.now() + this.ttlMs };
        return result;
      })
      .finally(() => {
        this.inFlight = undefined;
      });
    return this.inFlight;
  }

  private async fetchWithRetries(): Promise<FeedResult> {
    let lastFailure = "unknown error";
    let retryAfterMs = 0;
    for (let attempt = 0; ; attempt++) {
      const waitMs = Math.max(this.lastRequestAt + this.minIntervalMs - this.now(), retryAfterMs);
      if (waitMs > 0) await this.sleep(waitMs);
      this.lastRequestAt = this.now();

      try {
        const response = await this.fetchImpl(this.url, {
          headers: {
            "User-Agent": USER_AGENT,
            Accept: "application/rss+xml, application/xml;q=0.9",
          },
          signal: AbortSignal.timeout(this.timeoutMs),
        });

        if (response.ok) return await this.readFeed(response);

        // A block is a decision by the site, not a transient fault: report it, never work around it.
        if (response.status === 401 || response.status === 403 || response.headers.has("cf-mitigated")) {
          throw new FeedError(
            "blocked",
            `Cloudflare refused access to the Zero Wire feed (HTTP ${response.status}). ` +
              `This server does not attempt to bypass access controls. Check ${this.url} in a browser.`,
          );
        }
        lastFailure = `HTTP ${response.status}`;
        if (response.status !== 429 && response.status < 500) break;

        retryAfterMs = (Number(response.headers.get("retry-after")) || 0) * 1000;
        if (retryAfterMs > MAX_RETRY_AFTER_MS) break;
      } catch (error) {
        if (error instanceof FeedError) throw error;
        const name = error instanceof Error ? error.name : "";
        lastFailure =
          name === "TimeoutError" || name === "AbortError"
            ? `timed out after ${this.timeoutMs} ms`
            : error instanceof Error
              ? error.message
              : String(error);
      }

      if (attempt >= this.maxRetries) break;
      console.error(`[zero-wire-mcp] feed request failed (${lastFailure}); retrying`);
    }
    throw new FeedError(
      "unavailable",
      `Cloudflare Zero Wire is currently unavailable (${lastFailure}). No briefing data was returned. Source: ${this.url}`,
    );
  }

  private async readFeed(response: Response): Promise<FeedResult> {
    const contentType = response.headers.get("content-type") ?? "";
    if (!/xml/i.test(contentType)) {
      throw new FeedError("invalid", `Expected an RSS feed from ${this.url} but received "${contentType || "no content type"}".`);
    }
    if (Number(response.headers.get("content-length")) > MAX_BYTES) {
      throw new FeedError("invalid", `The feed at ${this.url} exceeds the ${MAX_BYTES} byte limit.`);
    }
    const body = await response.text();
    if (Buffer.byteLength(body) > MAX_BYTES) {
      throw new FeedError("invalid", `The feed at ${this.url} exceeds the ${MAX_BYTES} byte limit.`);
    }

    const feed = parseFeed(body);
    if (feed.skippedItems > 0) {
      console.error(`[zero-wire-mcp] skipped ${feed.skippedItems} feed item(s) that failed validation`);
    }
    return { feed, fetchedAt: new Date(this.now()).toISOString() };
  }
}
