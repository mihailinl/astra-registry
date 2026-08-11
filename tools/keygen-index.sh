#!/usr/bin/env sh
# Generate the index signing keypair.
#
# The index key is what actually signs `index.json` and `revocations.json`. It
# is DELEGATED: a root-signed `trust.json` names its public half, and that is
# the only reason a daemon believes it. So unlike a root key this one is
# recoverable — if it leaks, you sign a new `trust.json` naming a replacement and
# the old key stops being believed at the next refresh. That is the whole point
# of the delegation, and the reason this key is allowed to live in CI at all.
#
#   sh tools/keygen-index.sh --id astra-index-2026a
#
# It writes a directory, mode 0700, containing:
#
#   <id>.private.pem   the OpenSSL private key — keep it, it is your only copy
#   <id>.seed.b64      the same key as the base64 raw 32-byte seed, which is the
#                      value GitHub's secret takes. Mode 0600.
#   <id>.pub.json      the public half, ready to hand to sign-trust.mjs
#
# The seed is written to a FILE and never printed. A secret echoed to a terminal
# is a secret in that terminal's scrollback, in a screen recording, and in
# whatever logs the session. You copy it out of the file yourself.
#
# ── what to do with it ─────────────────────────────────────────────────────
#
#   1. Put the seed in the registry's `publish` environment, as the secret
#      ASTRA_INDEX_SIGNING_KEY, and the id as ASTRA_INDEX_SIGNING_KEY_ID:
#
#        gh secret set ASTRA_INDEX_SIGNING_KEY --env publish \
#          --repo mihailinl/astra-registry < <id>.seed.b64
#
#   2. Name the PUBLIC half in a root-signed trust.json:
#
#        node tools/sign-trust.mjs --root-key <root>.private.pem \
#          --index-key-file <id>.pub.json --workflow-sha <40-hex> \
#          --out registry/v1/trust.json
#
# ── this does NOT have to be an offline machine ────────────────────────────
#
# `keygen-root.sh` says the opposite, and means it: a root private key that ever
# touches a networked machine is a root private key you have to assume is gone,
# and replacing it means shipping a new daemon build to every user. This key has
# a cheaper failure: you re-sign a trust.json. Generate it wherever you will
# paste it from.

set -eu

die() { printf 'keygen-index: %s\n' "$*" >&2; exit 1; }

KEY_ID=""
OUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --id)  KEY_ID="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}";    shift 2 ;;
    -h|--help)
      sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$KEY_ID" ] || die "--id is required, e.g. --id astra-index-2026a"

# The id becomes a filename and travels in a signed document that a daemon reads.
# Keep it to the same shape as a plugin id: no separators, no surprises.
case "$KEY_ID" in
  *[!a-z0-9-]*) die "--id must be lowercase letters, digits and hyphens: '$KEY_ID'" ;;
  -*|*-)        die "--id must not start or end with a hyphen: '$KEY_ID'" ;;
esac

command -v openssl >/dev/null 2>&1 || die "openssl is required"
openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null \
  || die "this openssl does not support ed25519 (need OpenSSL 1.1.1+ / LibreSSL 3.7+)"

[ -n "$OUT" ] || OUT="$HOME/astra-index-key-$(date -u +%Y%m%dT%H%M%SZ)"
[ -e "$OUT" ] && die "$OUT already exists — refusing to overwrite a key directory"

umask 077
mkdir -p -- "$OUT"
chmod 700 -- "$OUT"

KEY="$OUT/$KEY_ID.private.pem"
openssl genpkey -algorithm ed25519 -out "$KEY"
chmod 600 -- "$KEY"

# Raw 32-byte Ed25519 public key, base64. `openssl pkey -pubout -outform DER`
# emits a 44-byte SPKI whose last 32 bytes are the key itself — the same shape
# `keygen-root.sh` publishes and `bot/lib/sign.mjs` parses.
PUB_B64="$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | openssl base64 -A)"
FINGERPRINT="$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | openssl dgst -sha256 -hex | awk '{print $NF}')"

# The private key as the base64 raw 32-byte SEED, which is the form
# ASTRA_INDEX_SIGNING_KEY takes (bot/lib/sign.mjs rebuilds the PKCS#8 around
# it). A PKCS#8 DER for Ed25519 is a fixed 16-byte prefix and then the seed, so
# the last 32 bytes are it.
openssl pkey -in "$KEY" -outform DER | tail -c 32 | openssl base64 -A > "$OUT/$KEY_ID.seed.b64"
chmod 600 -- "$OUT/$KEY_ID.seed.b64"

# Round-trip the key before anyone depends on it: sign 32 random bytes and
# verify. A keypair that cannot do that is better discovered now than at the
# first release, and it costs a millisecond.
openssl rand -out "$OUT/.selftest.bin" 32
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$OUT/.selftest.bin" -out "$OUT/.selftest.sig"
openssl pkey -in "$KEY" -pubout -out "$OUT/.selftest.pub.pem"
openssl pkeyutl -verify -pubin -inkey "$OUT/.selftest.pub.pem" -rawin \
  -in "$OUT/.selftest.bin" -sigfile "$OUT/.selftest.sig" >/dev/null \
  || die "the generated key failed its own sign/verify round trip — do not use it"
rm -f -- "$OUT/.selftest.bin" "$OUT/.selftest.sig" "$OUT/.selftest.pub.pem"

cat > "$OUT/$KEY_ID.pub.json" <<EOF
{
  "\$comment": "PUBLIC half of an Astra registry index signing key. Safe to publish. Name it in a root-signed trust.json with tools/sign-trust.mjs.",
  "key_id": "$KEY_ID",
  "algorithm": "ed25519",
  "public_key": "$PUB_B64",
  "fingerprint_sha256": "$FINGERPRINT",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
chmod 644 -- "$OUT/$KEY_ID.pub.json"

cat <<EOF

  Index signing key generated.

  key id       $KEY_ID
  public key   $PUB_B64
  fingerprint  $FINGERPRINT

  Written to $OUT:

    $KEY_ID.private.pem   your only copy of the private key
    $KEY_ID.seed.b64      the same key, in the form the GitHub secret takes
    $KEY_ID.pub.json      the public half, for sign-trust.mjs

  The seed was NOT printed above. Copy it from the file.

  Next, in order:

    1. gh secret set ASTRA_INDEX_SIGNING_KEY --env publish \\
         --repo mihailinl/astra-registry < "$OUT/$KEY_ID.seed.b64"
       gh secret set ASTRA_INDEX_SIGNING_KEY_ID --env publish \\
         --repo mihailinl/astra-registry --body "$KEY_ID"

    2. node tools/sign-trust.mjs --root-key <your-root>.private.pem \\
         --index-key-file "$OUT/$KEY_ID.pub.json" \\
         --workflow-sha <40-hex sha of plugin-release.yml> \\
         --out registry/v1/trust.json

  Until step 2 lands, this key signs nothing anybody believes: a daemon
  believes an index key because a root key vouched for it, and no root key
  has yet.

EOF
