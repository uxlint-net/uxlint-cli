# Run the uxlint MCP server in a container.
#
# The CLI is normally installed on the machine that has the browser — that is the point of it, since
# it drives the Chrome you already have. This image exists for the cases where that isn't true:
# directory listings whose checks introspect a containerised server, CI that would rather not install
# anything on the runner, and anyone who wants the audit sandboxed away from their desktop browser.
#
# It therefore ships its own Chromium, because a uxlint that can list tools but not audit a page is a
# demo of nothing. Note what a container CAN'T reach: `--base http://localhost:5173` means localhost
# INSIDE the container, so auditing an app on your own machine needs `--network host` (Linux) or
# `host.docker.internal`. Public URLs work as-is.
ARG UXLINT_VERSION=latest

FROM debian:bookworm-slim AS runtime
ARG UXLINT_VERSION

# chromium + the fonts it needs to render text at all (without fonts-liberation every screenshot is
# tofu, and the copy lints read a page of boxes). ca-certificates for TLS to the uxlint API; curl and
# tar only to fetch the release below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates chromium fonts-liberation curl tar \
    && rm -rf /var/lib/apt/lists/*

# The same published, checksum-verified release the docs hand everyone else — not a build from
# source, so the binary in here is byte-identical to the one on your laptop.
RUN curl -fsSL https://uxlint.net/install.sh \
    | env UXLINT_MANAGED=1 UXLINT_INSTALL_DIR=/usr/local/bin \
      ${UXLINT_VERSION:+UXLINT_VERSION=$([ "$UXLINT_VERSION" = latest ] || echo "$UXLINT_VERSION")} sh \
    && uxlint --version

# headless_chrome finds the browser through CHROME; Debian puts it at /usr/bin/chromium.
ENV CHROME=/usr/bin/chromium \
    UXLINT_SERVER=https://uxlint.net \
    # Chrome's own sandbox can't initialise in an unprivileged container — it dies before opening
    # its DevTools port, and every worker browser "fails to start". Dropping it is safe HERE and
    # only here, because the container is the boundary; the CLI deliberately never defaults this on,
    # so a `uxlint audit` on your laptop keeps the sandbox between Chrome and an untrusted page.
    UXLINT_CHROME_NO_SANDBOX=1

# Not root: nothing here needs it, and this process reads a credential.
RUN useradd -m -u 10001 uxlint
USER uxlint
WORKDIR /work

# stdio MCP: stdin/stdout are the JSON-RPC channel, so run it with `docker run -i --rm`.
ENTRYPOINT ["uxlint", "mcp"]
