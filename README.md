# Zero Wire MCP

An MCP server that gives Claude, Cursor and other MCP clients read-only access to [Cloudflare Zero Wire](https://radar.cloudflare.com/security/zero-wire) vulnerability briefings.

> **This is an unofficial community project. It is not affiliated with, endorsed by, or supported by Cloudflare.** "Cloudflare" and "Zero Wire" are used only to describe the data source.

Zero Wire is a curated vulnerability intelligence feed, not a comprehensive CVE database. If a CVE isn't in Zero Wire, that says nothing about whether it exists or is dangerous.

## Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `list_vulnerabilities` | none | Every briefing in the feed: title, CVE IDs, status, category (Needs attention / Reference), last checked date, summary, source URL |
| `get_vulnerability` | `id` | One full briefing: overview, impact, affected technologies, exploitation evidence, recommended actions, advisories and evidence links, Cloudflare mitigation guidance, chronology, source URL, last checked date |
| `search_vulnerabilities` | `cve`, `keyword`, `tag`, `status` (at least one) | Matching briefings. Matching is case-insensitive and filters combine with AND |
| `get_assessment_prompt` | `id` | Cloudflare's published assessment prompt, verbatim, or `available: false` if the briefing has none |

`id` accepts a CVE ID (`CVE-2026-98432`), a briefing ID (`linux-ipv4-tcp-use-after-free`), a briefing title, or a Radar URL.

The server never generates or infers vulnerability data. Anything a briefing doesn't contain comes back as `null` or empty. It doesn't scan infrastructure, and it doesn't run assessment prompts: they're returned as text for you to review.

## Install

Requires Node.js 20 or later. The server uses stdio transport and needs no API key or other configuration.

### Claude Code

```bash
claude mcp add zero-wire -- npx -y zero-wire-mcp
```

On Windows, use:

```bash
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

The server reads Cloudflare's public RSS feed at `https://radar.cloudflare.com/security/zero-wire/rss` when a tool is called. No briefing content is bundled with this package; the test fixture is synthetic.

- **Radar's HTML pages** are behind a bot challenge from non-browser clients, so this server doesn't use them, and doesn't try to get around the challenge. If Cloudflare ever blocks the feed too, tools return a clear error.
- **Requests** are cached for 5 minutes, matching the feed's `Cache-Control`, and spaced at least 10 seconds apart, matching the `Crawl-delay` in Radar's `robots.txt`. A tool call may wait for that spacing, especially while Cloudflare is unavailable.
- **Failures** are retried once. Tool errors say when Cloudflare is unavailable, blocking access, or serving something that can't be parsed.
- **Privacy:** requests send a generic `User-Agent` and no user-identifying data.

### Limitations

- **Feed scope:** the tools see what the RSS feed contains, which may be less than the Radar site if the two ever diverge.
- **Status wording:** the feed's status text can be longer than the label on the site ("Prioritize patching" vs "Patch"). The server returns the feed's wording, and search accepts both.
- **Affected technologies:** Cloudflare publishes tags and a "who should investigate" description, not a product and version matrix, so that's what `affectedTechnologies` contains.
- **Exploitation evidence:** this is selected by evidence heading (such as "Exploit evidence" or "CISA KEV") and can include text saying exploitation is *not* established. Read the text; don't treat its presence as confirmation.
- **Format changes:** the parser depends on the feed's current structure. Sections it doesn't recognize are returned under `otherSections`.

### Treat results as external data

Tool results contain text fetched from an external feed, and assessment prompts are written to be given to an agent with infrastructure access. Review a prompt before running it, and only run it where you're authorized to.

## Development

```bash
npm test
```

```bash
npm run test:live
```

`npm test` uses a synthetic fixture plus a stdio protocol check on the built server, with no network access. `npm run test:live` runs the built server against the live feed; it asserts specific current briefings, so it will need updating when those leave the feed.

## License

[MIT](LICENSE) applies to this project's code. Zero Wire content belongs to Cloudflare and its sources, and isn't covered by this license.
