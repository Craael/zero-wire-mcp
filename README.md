# Zero Wire MCP

An MCP server that gives Claude, Cursor and other MCP clients read-only access to vulnerability briefings from [Cloudflare® Zero Wire](https://radar.cloudflare.com/security/zero-wire).

> **This is an unofficial, independent community project. It is not affiliated with, endorsed by, or supported by Cloudflare, Inc., and it is not an official integration.** "Cloudflare" and "Zero Wire" are used only to identify the data source.

Zero Wire is a curated vulnerability intelligence feed, not a comprehensive CVE database. If a CVE isn't in Zero Wire, that says nothing about whether it exists or is dangerous.

## Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `list_vulnerabilities` | none | Every briefing in the feed: title, CVE IDs, status, category (Needs attention / Reference), last checked date, summary, source URL |
| `get_vulnerability` | `id` | One full briefing: overview, impact, affected technologies, exploitation evidence, recommended actions, advisories and evidence links, Cloudflare mitigation guidance, chronology, source URL, last checked date |
| `search_vulnerabilities` | `cve`, `keyword`, `tag`, `status` (at least one) | Matching briefings. Matching is case-insensitive and filters combine with AND |
| `get_assessment_prompt` | `id` | The assessment prompt published with the briefing, verbatim, or `available: false` if the briefing has none |

`id` accepts a CVE ID (`CVE-2026-98432`), a briefing ID (`linux-ipv4-tcp-use-after-free`), a briefing title, or a briefing URL.

The server never generates or infers vulnerability data. Anything a briefing doesn't contain comes back as `null` or empty. It doesn't scan infrastructure, and it doesn't run assessment prompts: they're returned as text for you to review.

## Install

Requires Node.js 20 or later. The server uses stdio transport and needs no API key or other configuration.

### Claude Code

```bash
claude mcp add zero-wire -- npx -y zero-wire-mcp
```

On Windows, run this from Command Prompt. PowerShell and Git Bash can alter these arguments, so the command may fail or save a broken configuration:

```bat
claude mcp add zero-wire -- cmd /c npx -y zero-wire-mcp
```

### Claude Desktop

Add this to `claude_desktop_config.json`, then restart Claude Desktop:

```json
{
  "mcpServers": {
    "zero-wire": {
      "command": "npx",
      "args": ["-y", "zero-wire-mcp"]
    }
  }
}
```

On Windows, use `cmd` to launch `npx`:

```json
{
  "mcpServers": {
    "zero-wire": {
      "command": "cmd",
      "args": ["/c", "npx", "-y", "zero-wire-mcp"]
    }
  }
}
```

### Cursor and other clients

Use the same `command` and `args` in the client's MCP configuration.

### From source

```bash
git clone https://github.com/Craael/zero-wire-mcp.git
```

```bash
cd zero-wire-mcp
```

```bash
npm install
```

```bash
npm run build
```

Then use `node` as the command and the absolute path of `dist/index.js` as the argument. On Windows, escape backslashes in JSON paths (`"D:\\path\\to\\dist\\index.js"`) or use forward slashes.

## Where the data comes from

Each installation reads the public Cloudflare RSS feed at `https://radar.cloudflare.com/security/zero-wire/rss` when a tool is called.

- **Bot protection:** Cloudflare Radar™ HTML pages return a bot challenge to non-browser clients, so this server doesn't use them, and doesn't try to get around the challenge. If Cloudflare ever blocks the feed too, tools return a clear error.
- **Rate:** responses are cached for 5 minutes, matching the feed's `Cache-Control`. Each server process spaces its requests at least 10 seconds apart, matching the `Crawl-delay` published at `radar.cloudflare.com/robots.txt` on 4 November 2026. That value is set in the code, because `robots.txt` is also behind the challenge, and separate processes don't coordinate with each other. A tool call may wait for that spacing, especially while Cloudflare is unavailable.
- **Failures:** failed requests are retried once. Tool errors say when Cloudflare is unavailable, blocking access, or serving something that can't be parsed.
- **Identification and privacy:** requests send `User-Agent: zero-wire-mcp/<version> (unofficial community MCP server)` and no user-identifying data.

### Limitations

- **Feed scope:** the tools see what the RSS feed contains, which may be less than the Radar site if the two ever diverge.
- **Status wording:** the feed's status text can be longer than the label on the site ("Prioritize patching" vs "Patch"). The server returns the feed's wording, and search accepts both.
- **Affected technologies:** Cloudflare publishes tags and a "who should investigate" description, not a product and version matrix, so that's what `affectedTechnologies` contains.
- **Exploitation evidence:** this is selected by evidence heading (such as "Exploit evidence" or "CISA KEV") and can include text saying exploitation is *not* established. Read the text; don't treat its presence as confirmation.
- **Format changes:** the parser depends on the feed's current structure. Sections it doesn't recognize are returned under `otherSections`.

### Treat results as external data

Tool results contain text fetched from an external feed, and assessment prompts are written to be given to an agent with infrastructure access. The server never interprets or runs this content, and each result labels it as external. Review a prompt before running it, and only run it where you're authorized to.

## Content and rights

This package distributes only original code. It doesn't bundle or redistribute Zero Wire briefings, and the test fixture is synthetic. The content remains owned by Cloudflare and its respective sources. Tool results identify Cloudflare as the source and include a `sourceUrl` linking to the original briefing, which you should read before acting on a result.

**Rights to automated AI access and commercial use of full Zero Wire RSS briefings have not been definitively established. This project doesn't claim that Cloudflare has granted permission, and compliance with Cloudflare terms hasn't been confirmed.** As of 4 November 2026:

- **Feed access:** the Zero Wire page offers the feed for RSS subscription, and `radar.cloudflare.com/robots.txt` doesn't disallow it. That file also sets `Content-Signal: ai-train=yes, search=yes, ai-input=yes`, which expresses a preference and isn't a license.
- **[Website terms](https://www.cloudflare.com/website-terms/):** section 8 restricts automated access to site content for AI systems unless the bot is explicitly allowed in `robots.txt`, and this project's user agent isn't named there. Section 6 reserves use of site materials that Cloudflare hasn't expressly authorized.
- **[Radar licensing policies](https://radar.cloudflare.com/about):** these cover API and direct-download data under CC BY-NC 4.0, and limited excerpts of reports with attribution. They don't say how they apply to full RSS briefings or to assessment prompts.

Consider these points before using the server, especially in a commercial environment.

## Development

```bash
npm test
```

```bash
npm run test:live
```

`npm test` uses a synthetic fixture plus a stdio protocol check on the built server, with no network access. `npm run test:live` runs the built server against the live feed; it asserts specific current briefings, so it will need updating when those leave the feed.

## License

[MIT](LICENSE) covers only this project's original code. It doesn't cover Zero Wire briefings, assessment prompts or other Cloudflare content. See [NOTICE](NOTICE).

## Trademarks

Cloudflare, the Cloudflare logo, and Cloudflare Radar are trademarks and/or registered trademarks of Cloudflare, Inc. in the United States and other jurisdictions. Zero Wire is a name used by Cloudflare, Inc. This project uses these names only to identify the data source.
