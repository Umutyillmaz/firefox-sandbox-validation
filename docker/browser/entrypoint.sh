#!/bin/sh
# Browser container entrypoint. PID 1 is tini (compose `init: true`), which
# reaps orphaned processes such as Firefox's post-shutdown background tasks.
set -eu

# Logs and profiles: owner-only permissions.
umask 077

if [ "$(id -u)" = "0" ]; then
    echo "refusing to run as root" >&2
    exit 1
fi

mkdir -p "$HOME" "$XDG_CACHE_HOME" "$INVISIBLE_PLAYWRIGHT_CACHE_DIR"

# Seed the warm security state into tmpfs. The read-only seed was fetched at image build time.
if [ ! -e "$INVISIBLE_PLAYWRIGHT_CACHE_DIR/security-state" ]; then
    cp -R --preserve=mode,timestamps /opt/ffsbx/seed/security-state "$INVISIBLE_PLAYWRIGHT_CACHE_DIR/"
fi

exec "$@"
