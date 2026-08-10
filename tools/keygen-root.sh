#!/usr/bin/env bash
#
# astra-registry — root key ceremony.
#
# Generates the TWO Ed25519 root keys that anchor the whole plugin trust chain:
# one that will be used, and one reserve that is generated at the same time and
# then never touched until it is needed. Both public halves ship inside every
# Astra binary. Nothing else in Astra is trusted because of where it came from —
# it is trusted because one of these two keys signed `trust.json`, and
# `trust.json` says which key may sign the catalogue.
#
# ── Run this once, by hand, on a machine with no network. ─────────────────────
#
# It is not run by CI. It is not run by an agent. It is not run in a container
# you will `docker rm` afterwards. The private halves it writes are the only
# secret in this design that cannot be rotated by pressing a button, because
# rotating a root means shipping a new Astra binary to every user.
#
# It prints public keys and fingerprints. It never prints, echoes, base64s to a
# terminal, or copies to a clipboard anything derived from a private key.
#
# Usage:
#   tools/keygen-root.sh --i-am-offline [--out DIR] [--label 2026a]
#
# See SECURITY.md for the custody rules and docs/RUNBOOK.md for what to do when
# one of these keys is lost or suspected compromised.

set -euo pipefail

# ── Refuse to be helpful in the ways that would ruin the ceremony ─────────────

die() { printf '\n  ✗ %s\n\n' "$*" >&2; exit 1; }

OFFLINE=0
OUT=""
LABEL="$(date -u +%Y)a"

while [ $# -gt 0 ]; do
  case "$1" in
    --i-am-offline) OFFLINE=1; shift ;;
    --out)   OUT="${2:-}";   shift 2 ;;
    --label) LABEL="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [ "$OFFLINE" -ne 1 ]; then
  cat >&2 <<'EOF'

  This script will not run without --i-am-offline.

  Before you pass it:

    1. Disconnect the machine from every network. Turn off Wi-Fi in the OS, not
       just in your head. Unplug the cable.
    2. Close anything that syncs a directory: Dropbox, iCloud, OneDrive, Syncthing,
       a backup agent, an editor with remote-save.
    3. Make sure your shell is not logging commands to a synced history file, and
       that no terminal-sharing / screen-recording tool is running.

  Then rerun with --i-am-offline.

EOF
  exit 2
fi

command -v openssl >/dev/null 2>&1 || die "openssl is required"
openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null \
  || die "this openssl does not support ed25519 (need OpenSSL 1.1.1+ / LibreSSL 3.7+)"

# The one mistake this script can actually prevent: writing a root private key
# into a git working tree, where the next `git add -A` publishes it forever.
if [ -n "$OUT" ]; then
  probe_dir="$(dirname -- "$OUT")"
else
  probe_dir="$PWD"
fi
if git -C "$probe_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  die "refusing to write root keys inside a git working tree ($probe_dir).
    Pass --out with a path on removable media, e.g.
      tools/keygen-root.sh --i-am-offline --out /run/media/\$USER/ASTRA-ROOT/keys"
fi

[ -n "$OUT" ] || OUT="$HOME/astra-root-ceremony-$(date -u +%Y%m%dT%H%M%SZ)"
[ -e "$OUT" ] && die "$OUT already exists — refusing to overwrite a ceremony directory"

# Everything this script creates is owner-only, from the first byte. `umask`
# rather than a later `chmod` because a later chmod leaves a window in which the
# file exists and is group-readable.
umask 077
mkdir -p -- "$OUT"
chmod 700 -- "$OUT"

# ── Generate ─────────────────────────────────────────────────────────────────

ACTIVE_ID="astra-root-$LABEL"
RESERVE_ID="astra-root-$LABEL-reserve"

# Raw 32-byte Ed25519 public key, base64. `openssl pkey -pubout -outform DER`
# emits a 44-byte SPKI whose last 32 bytes are the key itself.
pub_b64() { openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | openssl base64 -A; }
fingerprint() { openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | openssl dgst -sha256 -hex | awk '{print $NF}'; }

generate() { # $1 = key_id
  local key="$OUT/$1.private.pem"
  openssl genpkey -algorithm ed25519 -out "$key"
  chmod 600 -- "$key"
  # Verified, not assumed: if the umask or the filesystem did not honour us,
  # the ceremony stops here rather than leaving a readable root key behind.
  local mode
  mode="$(stat -c '%a' -- "$key" 2>/dev/null || stat -f '%Lp' -- "$key")"
  [ "$mode" = "600" ] || die "$key has mode $mode, expected 600 — stopping"
}

selftest() { # $1 = key_id — proves the key signs and verifies before you rely on it
  local key="$OUT/$1.private.pem" msg="$OUT/.selftest.bin" sig="$OUT/.selftest.sig"
  head -c 64 /dev/urandom > "$msg"
  openssl pkeyutl -sign -inkey "$key" -rawin -in "$msg" -out "$sig"
  openssl pkey -in "$key" -pubout -out "$OUT/.selftest.pub.pem"
  openssl pkeyutl -verify -pubin -inkey "$OUT/.selftest.pub.pem" -rawin -in "$msg" -sigfile "$sig" >/dev/null \
    || die "$1 failed its own sign/verify self-test"
  rm -f -- "$msg" "$sig" "$OUT/.selftest.pub.pem"
}

generate "$ACTIVE_ID"
generate "$RESERVE_ID"
selftest "$ACTIVE_ID"
selftest "$RESERVE_ID"

ACTIVE_PUB="$(pub_b64 "$OUT/$ACTIVE_ID.private.pem")"
RESERVE_PUB="$(pub_b64 "$OUT/$RESERVE_ID.private.pem")"
ACTIVE_FP="$(fingerprint "$OUT/$ACTIVE_ID.private.pem")"
RESERVE_FP="$(fingerprint "$OUT/$RESERVE_ID.private.pem")"

[ "$ACTIVE_PUB" != "$RESERVE_PUB" ] || die "the two keys came out identical — stop and investigate"

# The public document, ready to commit. Written next to the private keys so you
# can copy exactly this one file back to the online machine.
cat > "$OUT/root.json" <<EOF
{
  "\$comment": "The Astra plugin trust roots. Public keys only. These same two keys are compiled into astra-daemon; this file exists so a third party can read them without disassembling a binary, and so a mismatch between the two is visible. Generated by tools/keygen-root.sh.",
  "schema": "astra.registry.root/1",
  "status": "provisioned",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "roots": [
    {
      "key_id": "$ACTIVE_ID",
      "role": "active",
      "algorithm": "ed25519",
      "public_key": "$ACTIVE_PUB",
      "fingerprint_sha256": "$ACTIVE_FP",
      "signs": "trust.json"
    },
    {
      "key_id": "$RESERVE_ID",
      "role": "reserve",
      "algorithm": "ed25519",
      "public_key": "$RESERVE_PUB",
      "fingerprint_sha256": "$RESERVE_FP",
      "signs": "trust.json"
    }
  ]
}
EOF
chmod 600 -- "$OUT/root.json"

# ── Report ───────────────────────────────────────────────────────────────────
#
# From here on, stdout carries public material only.

cat <<EOF

  ══════════════════════════════════════════════════════════════════════════
   Astra root keys generated.  PUBLIC halves below — safe to copy anywhere.
  ══════════════════════════════════════════════════════════════════════════

   ACTIVE   $ACTIVE_ID
     public       $ACTIVE_PUB
     fingerprint  $ACTIVE_FP

   RESERVE  $RESERVE_ID
     public       $RESERVE_PUB
     fingerprint  $RESERVE_FP

  ── Next steps, in this order ─────────────────────────────────────────────

   1. BACK UP THE PRIVATE KEYS BEFORE YOU DO ANYTHING ELSE. Two copies, per
      SECURITY.md — "one person, two copies":

        (a) Offline and physical. Print or stamp
              $OUT/$ACTIVE_ID.private.pem
              $OUT/$RESERVE_ID.private.pem
            onto paper or steel and put them somewhere a house fire and a
            burglary are different events. Paper in a safe is fine. A photo of
            the paper on your phone is not.

        (b) Encrypted, in your password manager, as a file attachment — not
            pasted into a note field, which most managers sync as plaintext to
            their search index.

      Verify (a) by transcribing it back on the offline machine and diffing.
      A backup you have never restored is not a backup.

   2. Copy ONLY these two files to the online machine — never the .pem files:

        $OUT/root.json

      Commit it as registry/v1/root.json, replacing the "unprovisioned" stub.

   3. Paste the two public keys into astra-daemon's compiled-in root set:

        astra-rs/astra-daemon/src/plugins/trust.rs
        → const PRODUCTION_ROOT_KEYS

        ("$ACTIVE_ID",  RootRole::Active,  "$ACTIVE_PUB"),
        ("$RESERVE_ID", RootRole::Reserve, "$RESERVE_PUB"),

      \`cargo test -p astra-daemon plugins::trust\` then proves they parse, are
      distinct, and are not the test roots. An Astra without them fails closed:
      no trust.json verifies, so no catalogue is trusted.

   4. Sign the first trust.json with the ACTIVE key, offline, and publish it.
      docs/RUNBOOK.md § "Signing trust.json" has the exact command.

   5. WIPE THIS MACHINE'S COPY once both backups are verified:

        shred -u $OUT/*.private.pem 2>/dev/null || rm -P $OUT/*.private.pem
        rm -rf $OUT

      On an SSD, shred is not a guarantee. If this was a general-purpose
      machine, treat the keys as having touched it and prefer a machine you can
      reformat.

   6. Turn on hardware 2FA (a physical security key, not TOTP, not SMS) for the
      GitHub account that owns astra-registry. At a one-person team that single
      control is worth more than everything above — SECURITY.md says so plainly
      rather than pretending otherwise.

  The private keys are at $OUT (mode 600, in a directory mode 700).
  They were never printed, and this script did not touch the network.

EOF
