# Getting uxlint in front of agents

Where an MCP server can be listed, what each venue actually requires, and what is left to do. Written
because "submit it everywhere" is a dozen different submission formats, and the differences are the
whole job.

The pitch, in the order that matters: **an agent writes UI it cannot see.** uxlint looks at what it
built and hands back the exact change to make. That sentence is the listing copy for every venue
below; the rest is packaging.

---

## The distribution problem, stated once

Nearly every MCP venue assumes `npx` or `uvx` — a one-line command that fetches and runs the server
with no prior install. uxlint is a compiled Rust binary that drives your own Chrome, so it has no such
one-liner. Everything below is a way of working with that, and the ranked options are:

1. **An npm wrapper package** — `npx -y uxlint mcp`. BUILT, in `npm/`: it downloads the release build
   for your platform, verifies the checksum published beside it, caches it under `~/.cache/uxlint` and
   hands over. Progress goes to stderr, because under `uxlint mcp` stdout is the JSON-RPC channel.
   Tested end to end against the real v0.1.26 release. This is what unlocks the registry's npm path,
   the editor one-liners, Smithery and most directory forms — they all assume `npx`.
   **Publishing is CI's job**, not a laptop's: the release workflow publishes both names on every
   `v*` tag, signed with npm provenance (a verifiable link from the tarball back to the workflow run
   and commit that built it — which for a launcher that downloads a binary is the whole trust story).
   Provenance needs an OIDC token, so it only works in CI; `just npm-publish` from a laptop still
   works as break-glass, unsigned, and says so.

   **Left to do, both one-time and neither of them a publish:** create the npm org (`npm org create
   uxlint-net`) and add the token (`gh secret set NPM_TOKEN`). After that the first publish is a tag —
   or a `workflow_dispatch` of the release workflow against the existing v0.1.26 tag, which republishes
   nothing else.

   **Names: both.** `just npm-publish <version>` publishes the same launcher as `uxlint` (the documented
   one-liner — the shortest command is the one every directory and blog post prints, so it has to be
   ours) and as `@uxlint-net/uxlint` (our own scope, since `@uxlint` belongs to a different product).
   A name you don't hold is a name someone else can take. See "The other uxlint" below.
2. **MCPB bundle** — a prebuilt binary attached to a GitHub release. The official registry supports
   this natively (`registryType: mcpb`), and it is the honest shape for a compiled tool. Needs a pack
   step in the release workflow (below).
3. **`install.sh` first, then configure the server** — what the docs already tell people. Works, but
   it is two steps, and a two-step install loses people in a directory listing.

Deliberately NOT pursued: **OCI/Docker** distribution. The registry supports it and we already publish
`ghcr.io/uxlint-net/uxlint-cli`, but the MCP server drives the user's local Chrome and reads their
project directory. In a container it can do neither, so listing it that way would advertise an
experience that doesn't work.

---

## 1. Claude Code plugin marketplace — READY

Highest-intent audience: people already using an agent to write UI. No submission, no review queue —
a marketplace is just a repo.

Shipped in this repo:

- `.claude-plugin/marketplace.json` — the catalogue
- `plugin/.claude-plugin/plugin.json` — the plugin, declaring the MCP server
- `plugin/bin/uxlint-mcp` — the launcher: uses the `uxlint` already on PATH, and otherwise installs it
  once into the plugin's data directory with the same checksum-verifying installer the website
  documents. That is what makes this a one-click install rather than "install the CLI first".

Users run:

```
/plugin marketplace add uxlint-net/uxlint-cli
/plugin install uxlint@uxlint
```

Both manifests pass `claude plugin validate`. **To do:** announce it — the command above is the whole
onboarding, so it belongs in the README, the docs site, and any launch post.

## 2. Official MCP Registry (modelcontextprotocol/registry) — ONE STEP LEFT

The canonical index; other directories aggregate from it. Metadata only — it points at an artifact
hosted elsewhere.

`server.json` is written and committed (namespace `io.github.uxlint-net/uxlint`, which GitHub auth
proves ownership of). What remains is the artifact it points at:

1. **Build the `.mcpb` bundle in the release workflow.** A zip containing a `manifest.json`
   (`manifest_version`, `name`, `version`, `description`, `author`, `server`) plus the platform
   binaries we already build. `npm install -g @anthropic-ai/mcpb && mcpb pack`.
2. **Fill `fileSha256`** in `server.json` from the packed artifact (`openssl dgst -sha256`), and set
   `version` and the release URL to the tag being published.
3. **Publish**: `mcp-publisher login github-oidc && mcp-publisher publish` from a workflow with
   `id-token: write`.

`.github/workflows/publish-mcp.yml` does all three, and is deliberately **manual (`workflow_dispatch`)
rather than tag-triggered**: the first publish claims a namespace, and that should be a decision
someone makes on purpose, not a side effect of tagging a patch release. Flip it to `on: push: tags`
once a first run has been watched end to end.

## 3. Directory listings — COPY READY, SUBMIT MANUALLY

Each wants a form or a PR, and each takes minutes once the repo has a description, topics and a
working install line (all now true):

| Venue | How | Notes |
| --- | --- | --- |
| [Smithery](https://smithery.ai) | Connect the GitHub repo | Wants a runnable command; easiest after the npm wrapper |
| [Glama](https://glama.ai/mcp/servers) | Crawls GitHub + accepts submissions | Ranks on repo quality — description/topics/licence now in place |
| [PulseMCP](https://www.pulsemcp.com) | Submission form | Short description + categories |
| [mcp.so](https://mcp.so) | Submission form | Same copy |
| [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) | PR adding one line | Follow their category conventions |
| Cursor / VS Code / Windsurf docs | PR or form per editor | All assume a one-line command → npm wrapper first |

Listing copy to reuse verbatim:

> **uxlint** — Audit any website's UX the way a design-literate reviewer would: contrast, tap targets,
> type scale, colour discipline, copy clarity, scan patterns, resilience. Every finding comes back with
> the rule it broke, the source line, the selector, and the exact fix — so an agent can apply it and
> re-check until green. Runs against the Chrome you already have.

## 4. Before submitting anywhere

- [x] Repo description, homepage and topics (a directory's first impression, and ours was blank)
- [x] `LICENSE`, `README` with install + MCP sections, privacy/trust written up
- [x] Claude Code marketplace manifests, validated
- [x] `server.json` for the official registry
- [ ] `.mcpb` bundle attached to a release + `fileSha256` filled in
- [x] npm wrapper (`uxlint`) — built and tested; needs the first publish + `NPM_TOKEN`
- [ ] A 30-second demo GIF: agent writes UI → audit_url → findings → fixes → green. Every directory
      that allows an image converts better with one, and we don't have it.

---

## The other uxlint

**There is a live product with our name.** `uxlint.dev` — "UXLint — Just enter a URL. Find UX issues.
75 checks in under 60 seconds" — is a direct competitor in the same category, and it owns the `@uxlint`
npm **scope**: `@uxlint/cli` was published on 2026-03-11 by `goodwelchi <contact@goodwelchi.com>`,
pointing at `github.com/uxlint/cli`.

That is why this package is the unscoped `uxlint` (which was still free) rather than `@uxlint/mcp`.
Worth knowing before submitting anywhere, for three reasons:

1. **Directory confusion.** Both products will appear under the same name in MCP directories and search
   results. Whoever lists first, with the better description and image, owns the name in practice.
2. **The scope is a dead end.** Anything `@uxlint/*` on npm is theirs. Our npm identity is the bare
   name.
3. **It is a brand decision, not a packaging one** — trademark, domain, and whether the collision is
   worth contesting or worth differentiating away from. Flagged here rather than decided.
