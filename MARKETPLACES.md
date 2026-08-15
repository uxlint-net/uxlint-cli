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

1. **An npm wrapper package** — `npx -y @uxlint-net/uxlint mcp`. PUBLISHED, source in `npm/`: it
   downloads the release build for your platform, verifies the checksum published beside it, caches it
   under `~/.cache/uxlint` and hands over. Progress goes to stderr, because under `uxlint mcp` stdout
   is the JSON-RPC channel. Verified end to end from a cold cache against the real release. This is
   what unlocks the registry's npm path, the editor one-liners, Smithery and most directory forms —
   they all assume `npx`.
   **Publishing is CI's job, with no token anywhere.** The release workflow publishes both names on
   every `v*` tag using npm **trusted publishing**: GitHub mints an OIDC token, npm checks it came
   from this repo and this workflow file, and generates provenance automatically — a verifiable link
   from the tarball back to the run and commit that produced it, which for a launcher whose job is to
   download a binary is the whole trust story. There is no `NPM_TOKEN` to leak, and npm's own UI now
   warns against automation tokens for exactly that reason.

   **Bootstrap, once per package** (npm can only enable trust on a package that already exists):

   1. create the org at <https://www.npmjs.com/org/create> — name `uxlint-net`, free "unlimited public
      packages" plan (web-only; there is no `npm org create` command). Not needed for the unscoped
      `uxlint`, only for the scoped twin.
   2. `npm login` then `just npm-publish 0.1.26` — the only manual publish there will ever be.
   3. on npmjs.com, for EACH package → Settings → Trusted Publishing → GitHub Actions:
      repository `uxlint-net/uxlint-cli`, workflow `release.yml`.
   4. from then on a tag publishes both, signed, with nothing to steal.

   **Name: `@uxlint-net/uxlint`**, scoped, because neither unscoped option was available. `@uxlint`
   belongs to a different product with the same name (see below), and npm REFUSED the bare `uxlint`:
   "Package name too similar to existing package ux-lint" — an abandoned 2017 linter that still holds
   the normalized name. Our own org is the namespace we actually control.
2. ~~**MCPB bundle**~~ — a prebuilt binary attached to a release. This was the plan while there was no
   npm package; now that there is one, `server.json` points at npm instead. An artifact you don't have
   to build can't be built wrong.
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

Both manifests pass `claude plugin validate`, and the whole path is exercised: install from the real
marketplace, `/plugin update` across three versions, each fetching its matching CLI. The command is in
the README and on /docs/mcp. **To do:** a launch post.

## 2. Official MCP Registry (modelcontextprotocol/registry) — LIVE

Listed since 2026-08-15 as **`io.github.uxlint-net/uxlint`** (status `active`, first published at
v0.1.29). The canonical index; other directories aggregate from it. Metadata only — it points at the
npm package, and the registry proves we own the namespace by matching `mcpName` inside that package
against the server name. No bundle to build: the `.mcpb` route this section used to describe was
dropped once there was an npm package, because an artifact you don't have to build can't be built
wrong.

`.github/workflows/publish-mcp.yml` publishes it — deliberately **manual (`workflow_dispatch`, given a
tag already on npm) rather than tag-triggered**: the first publish claims a namespace, which should be
a decision someone makes on purpose. Now that a run has been watched end to end, flipping it to
`on: push: tags` is a live option.

Two things that run will teach you the hard way:

- It publishes **`main`'s `server.json`**, whatever tag you pass — the tag only sets the version. So
  the description and package identifier it announces are main's, not the tag's.
- The registry validates **at publish time**, i.e. after the release is already public. Our first
  attempt died on `422 expected length <= 100` for `description` (ours was 270). `tests/registry_manifest.rs`
  now pins that limit — in chars AND bytes, since an em dash is one char but three — along with the
  `name` ↔ `mcpName` and identifier ↔ npm-name pairings that are the ownership proof.

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
- [x] ~~`.mcpb` bundle~~ — dropped: the registry points at the npm package instead
- [x] npm wrapper — published as `@uxlint-net/uxlint`, with SLSA provenance via npm Trusted
      Publishing (OIDC, no token anywhere)
- [x] Listed in the official MCP Registry
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
