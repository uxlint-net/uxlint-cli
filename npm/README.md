# @uxlint-net/uxlint

Audit any website's UX the way a design-literate reviewer would — contrast, tap targets, type scale,
colour discipline, copy clarity, scan patterns, resilience — and get a concrete fix for every finding.

Built to sit in a coding agent's loop: an agent writes UI it cannot see, and this is how it looks.

```sh
npx @uxlint-net/uxlint audit --base http://localhost:5173     # audit a running site
npx @uxlint-net/uxlint mcp                                    # run the MCP server (stdio)
```

## Use it from an agent

Add it as an MCP server. In Claude Code:

```sh
claude mcp add uxlint -- npx -y @uxlint-net/uxlint mcp
```

Or in any client that reads a JSON config:

```json
{
  "mcpServers": {
    "uxlint": { "command": "npx", "args": ["-y", "@uxlint-net/uxlint", "mcp"] }
  }
}
```

The agent gets `audit_url` (audit and get findings with fixes), `verify_fix` (re-check one rule on one
page in ~2s), `ux_guidance` (the idiomatic pattern for an area, before you change UI) and `get_shot`
(the annotated screenshot of a finding).

## What this package is

A launcher, not the tool. uxlint is a single compiled Rust binary; this package downloads the build for
your platform from the matching GitHub release, verifies the checksum published beside it, caches it
under `~/.cache/uxlint`, and hands over. The version you install is the version you get —
`npx @uxlint-net/uxlint@0.1.26` runs exactly that binary.

It drives a Chrome or Chromium you already have (no browser download, no Node runtime for the audit
itself). macOS and Linux, x64 and arm64. `CHROME=/path/to/chrome` if yours lives somewhere unusual.

## Privacy

The capture script is compiled into the binary and the source is public, so what runs in your pages is
fixed by the version you installed and can't be changed at run time. `uxlint audit --dry-run <dir>`
writes the exact payload to a folder so you can read it before anything is uploaded. See
[Privacy & trust](https://github.com/uxlint-net/uxlint-cli#privacy--trust).

- Docs: <https://uxlint.net/docs>
- Source: <https://github.com/uxlint-net/uxlint-cli>
