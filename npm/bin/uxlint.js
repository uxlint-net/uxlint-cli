#!/usr/bin/env node
// `npx uxlint …` — the npm face of the uxlint CLI.
//
// uxlint is a compiled Rust binary, but nearly every MCP client, editor and directory assumes a
// one-line `npx` command with no prior install. This package is that line. It ships no binary of its
// own: it fetches the one published for this platform from the GitHub release matching its own
// version, verifies the checksum we publish beside it, caches it, and hands over.
//
// Two rules govern everything here:
//
//   1. NOTHING may be written to stdout. Under `uxlint mcp` stdout is the JSON-RPC channel, and one
//      stray line of progress makes the server look broken to its client. Every message goes to
//      stderr, which clients show as logs.
//   2. The version is pinned to this package's own version, so `npx uxlint@0.1.26` runs exactly the
//      0.1.26 binary. An npm install that silently drifted to a newer CLI would make the two version
//      numbers a lie, and /v1/me tells clients which CLI to run.
//
// No dependencies, on purpose: a launcher that fetches a signed artifact should not itself pull a
// tree of packages. `tar` is invoked from PATH (present on macOS and Linux, the platforms we build).
'use strict';

const { spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { version } = require('../package.json');
const REPO = 'uxlint-net/uxlint-cli';

const log = (msg) => process.stderr.write(`uxlint: ${msg}\n`);

/** The release asset for this machine, or null if we don't publish one for it. */
function assetName() {
  const arch = { x64: 'x64', arm64: 'arm64' }[process.arch];
  const plat = { linux: 'linux', darwin: 'macos' }[process.platform];
  return arch && plat ? `uxlint-${plat}-${arch}.tar.gz` : null;
}

/** Follows redirects — GitHub release downloads always redirect to object storage. */
async function fetchBuffer(url, redirects = 5) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

async function install(dir, asset) {
  const base = `https://github.com/${REPO}/releases/download/v${version}/${asset}`;
  log(`downloading ${asset} v${version} (once)`);
  const [tarball, shaFile] = await Promise.all([
    fetchBuffer(base),
    fetchBuffer(`${base}.sha256`).catch(() => null) // absent → we say so rather than pretend
  ]);

  // Verify against the checksum published beside the artifact. This is the same file the shell
  // installer checks; skipping it silently would make `npx` the weakest way to install uxlint.
  if (shaFile) {
    const want = shaFile.toString('utf8').trim().split(/\s+/)[0];
    const got = crypto.createHash('sha256').update(tarball).digest('hex');
    if (want !== got) {
      throw new Error(`checksum mismatch for ${asset}\n  published ${want}\n  downloaded ${got}`);
    }
  } else {
    log(`warning: no published checksum for ${asset} — proceeding unverified`);
  }

  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, asset);
  fs.writeFileSync(tmp, tarball);
  const untar = spawnSync('tar', ['xzf', tmp, '-C', dir], { stdio: ['ignore', 'ignore', 'inherit'] });
  fs.unlinkSync(tmp);
  if (untar.status !== 0) throw new Error('could not extract the release archive (is `tar` on PATH?)');
}

async function main() {
  const asset = assetName();
  if (!asset) {
    log(`no published build for ${process.platform}/${process.arch}.`);
    log('supported: macOS and Linux on x64 or arm64. See https://uxlint.net/docs/cli');
    process.exit(1);
  }

  // Versioned cache: a new package version fetches a new binary, and old ones stay put rather than
  // being overwritten under a running process.
  const cache = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  const dir = path.join(cache, 'uxlint', 'bin', version);
  const bin = path.join(dir, 'uxlint');

  if (!fs.existsSync(bin)) {
    try {
      await install(dir, asset);
      fs.chmodSync(bin, 0o755);
    } catch (err) {
      log(`install failed: ${err.message}`);
      log('you can install it directly instead: curl -fsSL https://uxlint.net/install.sh | sh');
      process.exit(1);
    }
  }

  // Hand over completely: same argv, same streams, same exit code. `npx uxlint mcp` is then
  // indistinguishable from running the binary, which is what an MCP client needs.
  const child = spawn(bin, process.argv.slice(2), { stdio: 'inherit' });
  child.on('error', (err) => {
    log(`could not run ${bin}: ${err.message}`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    else process.exit(code ?? 0);
  });
}

main().catch((err) => {
  log(String((err && err.message) || err));
  process.exit(1);
});
