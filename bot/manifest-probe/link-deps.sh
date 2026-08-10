#!/usr/bin/env bash
# Put the AstraPlugins checkout where Cargo.toml's path dependency expects it.
#
# The registry bot parses `plugin.toml` with `astra-plugin-manifest`, the crate
# the daemon parses it with. That crate lives in Astra, is vendored into
# AstraPlugins under a byte-equality check, and is NOT copied into this
# repository — see manifest-probe/README.md for why a third copy would be worse
# than a checkout.
#
# Two ways to satisfy that, and this script covers both:
#
#   - a working copy of AstraPlugins beside this one (the developer case), or
#     wherever $ASTRA_PLUGINS_DIR points;
#   - a clone at $ASTRA_PLUGINS_REF (CI passes the pinned commit SHA).
#
# It never fetches without being told to. `--clone` is opt-in precisely because
# "the build silently pulled some code from the internet" is not a property a
# registry bot should have.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="$here/_deps/AstraPlugins"
crate_rel="astra-plugin-cli/vendor/astra-plugin-manifest"

clone=0
[ "${1:-}" = "--clone" ] && clone=1

have_crate() { [ -f "$1/$crate_rel/Cargo.toml" ]; }

mkdir -p "$here/_deps"

# 1. An explicit pointer wins over everything.
if [ -n "${ASTRA_PLUGINS_DIR:-}" ]; then
  if ! have_crate "$ASTRA_PLUGINS_DIR"; then
    echo "ASTRA_PLUGINS_DIR=$ASTRA_PLUGINS_DIR has no $crate_rel" >&2
    exit 1
  fi
  ln -sfn "$(cd "$ASTRA_PLUGINS_DIR" && pwd)" "$dest"
  echo "manifest-probe: linked $dest -> $ASTRA_PLUGINS_DIR"
  exit 0
fi

# 2. Already there (CI checked it out, or a previous run linked it).
if have_crate "$dest"; then
  echo "manifest-probe: $dest is already in place"
  exit 0
fi

# 3. A sibling working copy — three levels up from bot/manifest-probe/.
sibling="$(cd "$here/../../.." && pwd)/AstraPlugins"
if have_crate "$sibling"; then
  ln -sfn "$sibling" "$dest"
  echo "manifest-probe: linked $dest -> $sibling"
  exit 0
fi

if [ "$clone" -eq 1 ]; then
  ref="${ASTRA_PLUGINS_REF:-}"
  if [ -z "$ref" ]; then
    echo "refusing to clone without ASTRA_PLUGINS_REF: the manifest rules this bot enforces" >&2
    echo "must come from a commit somebody chose, not from whatever HEAD happens to be." >&2
    exit 1
  fi
  rm -rf "$dest"
  git clone --quiet --no-checkout \
    "${ASTRA_PLUGINS_URL:-https://github.com/mihailinl/AstraPlugins.git}" "$dest"
  git -C "$dest" checkout --quiet "$ref"
  echo "manifest-probe: cloned AstraPlugins at $ref"
  exit 0
fi

cat >&2 <<EOF
manifest-probe: cannot find AstraPlugins.

This binary links astra-plugin-manifest — the crate the DAEMON parses
plugin.toml with — rather than reimplementing it. It needs a checkout.

  export ASTRA_PLUGINS_DIR=/path/to/AstraPlugins   # then rerun
  $0 --clone                                       # with ASTRA_PLUGINS_REF set

Looked at: \${ASTRA_PLUGINS_DIR:-<unset>}, $dest, $sibling
EOF
exit 1
