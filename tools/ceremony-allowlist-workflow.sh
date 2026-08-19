#!/usr/bin/env bash
#
# Add a release-workflow commit to the attestation allowlist, and re-sign
# trust.json with a ROOT key.
#
# ── what this is for ───────────────────────────────────────────────────────
#
# The registry believes a plugin's build because the attestation on it names
# `AstraPlugins/.github/workflows/plugin-release.yml` at a commit `trust.json`
# allows. That is what stops an author swapping in their own build. It also
# means the workflow cannot be edited without this: change one character and
# every build signed by the new file is signed by something nothing trusts.
#
# The allowlist takes SEVERAL commits, and this script keeps the old ones. So
# there is no flag day: releases pinned to the previous commit keep working
# while callers move over at their own pace, and the old entry is dropped in a
# later ceremony once nothing points at it.
#
# ── what it does NOT affect ────────────────────────────────────────────────
#
# Nothing already in the catalogue, and nothing already installed. The daemon
# does not read this list — its own source says so — and no plugin's listing is
# re-verified after the fact. Only a FUTURE ingest consults it.
#
# ── usage ──────────────────────────────────────────────────────────────────
#
#   tools/ceremony-allowlist-workflow.sh <root-key.pem> <new-40-hex-sha>
#
# Run it on the offline machine that holds the root key. It does no network
# I/O. Carry `registry/v1/trust.json` back out and commit it.

set -euo pipefail

die() { printf '\n  ✗ %s\n\n' "$*" >&2; exit 1; }

ROOT_KEY="${1:-}"
NEW_SHA="${2:-}"
[ -n "$ROOT_KEY" ] || die "usage: $0 <root-key.pem> <new-40-hex-sha>"
[ -n "$NEW_SHA" ]  || die "usage: $0 <root-key.pem> <new-40-hex-sha>"
[ -r "$ROOT_KEY" ] || die "cannot read $ROOT_KEY"
printf '%s' "$NEW_SHA" | grep -qE '^[0-9a-f]{40}$' \
  || die "'$NEW_SHA' is not a 40-character lowercase commit SHA.
    A tag will not do — a tag can be repointed, which is the whole reason
    this list holds commits."

cd "$(dirname "$0")/.."
TRUST=registry/v1/trust.json
[ -r "$TRUST" ] || die "no $TRUST here — run this from a checkout of astra-registry"

command -v node >/dev/null || die "node is required"

# The index key's PUBLIC half, rebuilt out of the document being replaced.
# `sign-trust.mjs` wants it as a file, and the file from the original keygen may
# be long gone — but this is public material, published in every catalogue, so
# reconstructing it costs nothing and finds nothing secret.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
node -e '
  const fs = require("fs");
  const t = JSON.parse(fs.readFileSync(process.argv[1], "utf8")).signed;
  const keys = t.index_keys ?? [];
  if (!keys.length) { console.error("trust.json delegates to no index key"); process.exit(1); }
  for (const k of keys) {
    fs.writeFileSync(`${process.argv[2]}/${k.key_id}.pub.json`, JSON.stringify({
      $comment: "PUBLIC half, reconstructed from the trust.json being replaced.",
      key_id: k.key_id, algorithm: k.algorithm ?? "ed25519", public_key: k.public_key,
    }, null, 2) + "\n");
  }
  console.log(`  carrying forward ${keys.length} index key(s): ${keys.map((k) => k.key_id).join(", ")}`);
' "$TRUST" "$WORK"

# Every commit already trusted, plus the new one, de-duplicated and in order.
mapfile -t OLD < <(node -e '
  const t = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).signed;
  for (const s of t.reusable_workflow_shas ?? []) console.log(s);
' "$TRUST")
SERIAL=$(node -e '
  console.log((JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).signed.serial ?? 0) + 1);
' "$TRUST")

ARGS=()
for s in "${OLD[@]}"; do
  [ "$s" = "$NEW_SHA" ] && continue
  ARGS+=(--workflow-sha "$s")
done
ARGS+=(--workflow-sha "$NEW_SHA")
for f in "$WORK"/*.pub.json; do ARGS+=(--index-key-file "$f"); done

printf '\n  keeping %d existing commit(s), adding 1, new serial %s\n\n' "${#OLD[@]}" "$SERIAL"

node tools/sign-trust.mjs --root-key "$ROOT_KEY" --serial "$SERIAL" --out "$TRUST" "${ARGS[@]}"

echo
node tools/sign-trust.mjs --verify "$TRUST"

cat <<EOF

  ── next, on a machine that is allowed online ────────────────────────────

   1. git add registry/v1/trust.json && git commit -m "trust: allowlist <sha>"
   2. git push
   3. Tell whoever is holding the release: callers can move to the new commit,
      and nothing has to move at once.

  The root key was read from $ROOT_KEY and nothing else touched it. It was
  never printed, never copied, and this script made no network call.

EOF
