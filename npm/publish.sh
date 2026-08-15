#!/usr/bin/env bash
# Publish the npm launcher under BOTH of uxlint's names, from one source directory.
#
#   ./npm/publish.sh 0.1.26          # publish that version
#   DRY_RUN=1 ./npm/publish.sh 0.1.26
#
# Two names, one package:
#
#   uxlint               the documented one-liner — `npx -y uxlint mcp`. The shortest command is the
#                        one every directory, editor snippet and blog post prints, so it is the name
#                        that has to be ours.
#   @uxlint-net/uxlint   the same launcher under our own scope. The `@uxlint` scope belongs to a
#                        different product with the same name (uxlint.dev, `@uxlint/cli` since March),
#                        so `@uxlint-net` is the namespace we can actually hold — worth owning both
#                        because a name you don't hold is a name someone else can take.
#
# Published from ONE directory with the name rewritten, rather than two copies of a launcher that
# would drift. Everything else — version, bin, files, README — is identical by construction.
set -euo pipefail

VERSION="${1:?usage: publish.sh <version>   (e.g. 0.1.26)}"
VERSION="${VERSION#v}"
SRC="$(cd "$(dirname "$0")" && pwd)"
NAMES=("uxlint" "@uxlint-net/uxlint")

# A prerelease must never become what `npx uxlint` hands the world.
case "$VERSION" in
	*-*) DIST_TAG=(--tag next) ;;
	*) DIST_TAG=() ;;
esac

for name in "${NAMES[@]}"; do
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	cp -R "$SRC"/. "$work"/
	rm -f "$work/publish.sh"
	# The only difference between the two publishes.
	node -e '
		const fs = require("fs"), p = process.argv[1], name = process.argv[2], version = process.argv[3];
		const j = JSON.parse(fs.readFileSync(p, "utf8"));
		j.name = name;
		j.version = version;
		fs.writeFileSync(p, JSON.stringify(j, null, "\t") + "\n");
	' "$work/package.json" "$name" "$VERSION"

	echo "→ publishing $name@$VERSION" >&2
	if [ -n "${DRY_RUN:-}" ]; then
		(cd "$work" && npm publish --dry-run --access public "${DIST_TAG[@]}")
	else
		(cd "$work" && npm publish --provenance --access public "${DIST_TAG[@]}")
	fi
	rm -rf "$work"
	trap - EXIT
done

echo "published ${NAMES[*]} at $VERSION" >&2
