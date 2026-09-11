#!/usr/bin/env node
// Sign the Astra update manifest with a production root key.
//
//   node tools/sign-update-manifest.mjs --root-key "$keydir/root.pem" \
//     --artifact <where it is>/Astra-Installer-0.2.6.exe \
//     --notes-en releases/0.2.6/notes.en.txt \
//     --notes-ru releases/0.2.6/notes.ru.txt \
//     --notes-uk releases/0.2.6/notes.uk.txt \
//     [--version 0.2.6] [--min-supported 0.2.4] [--expires-days 180] \
//     [--also-reserve "$keydir/reserve.pem"] [--out manifest.json]
//
//   node tools/sign-update-manifest.mjs --renew releases/0.2.5/manifest.json \
//     --root-key "$keydir/root.pem" [--expires-days 180] [--out manifest.json]
//
//   node tools/sign-update-manifest.mjs --withdraw-to releases/0.2.4/manifest.json \
//     --root-key "$keydir/root.pem" [--expires-days 180] [--out manifest.json]
//
//   node tools/sign-update-manifest.mjs --verify manifest.json
//
//   node tools/sign-update-manifest.mjs --check-notes releases/0.2.6           # a directory
//   node tools/sign-update-manifest.mjs --check-notes notes.en.txt notes.ru.txt  # or files
//
// Exit status: 0 when the mode did what it says, 1 for every refusal. A refusal writes nothing.
//
// **Every mode takes a CLOSED set of flags.** An unknown flag, a flag given twice, or a word that
// belongs to no flag is refused, never ignored: a typo'd `--expires-day 30` must not quietly sign
// for the default 180 days.
//
// ── where the key comes from: decrypt, check, sign, shred ──────────────────
//
// A root key is used ONLY by decrypting its symmetric `.pem.gpg` copy. Where those copies live is
// recorded in the astra-rs repository, docs/KEY_CEREMONY.md §5, and is deliberately not repeated
// here. Never point --root-key at a plaintext PEM, wherever one may still sit. In bash, not fish:
//
//   set -euo pipefail
//   root_gpg='<the ACTIVE root .pem.gpg that KEY_CEREMONY.md §5 names>'
//   reserve_gpg='<the RESERVE root .pem.gpg, only on a day both roots sign>'
//   : "${XDG_RUNTIME_DIR:?is unset: refusing to put a root key anywhere but tmpfs}"
//   GNUPGHOME="$(mktemp -d)"; export GNUPGHOME     # throwaway, never the archive key's home
//   keydir="$(mktemp -d -p "$XDG_RUNTIME_DIR")"   # tmpfs, mode 0700
//   cleanup() {
//     set +e                                       # every step runs, whatever failed before it
//     for f in "$keydir"/*.pem; do
//       if [ -e "$f" ]; then shred -u "$f" || rm -f "$f"; fi
//     done
//     rm -rf "$keydir"
//     gpgconf --kill gpg-agent 2>/dev/null
//     rm -rf "$GNUPGHOME"
//   }
//   trap cleanup EXIT
//   trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
//
//   if ! (umask 077; gpg --no-symkey-cache --decrypt --output "$keydir/root.pem" "$root_gpg"); then
//     echo "gpg could not decrypt the active root: nothing was signed" >&2
//     exit 1
//   fi
//   # Only on a day both roots sign (--also-reserve), and still BEFORE the signer runs:
//   if ! (umask 077; gpg --no-symkey-cache --decrypt --output "$keydir/reserve.pem" "$reserve_gpg"); then
//     echo "gpg could not decrypt the reserve root: nothing was signed" >&2
//     exit 1
//   fi
//
//   node tools/sign-update-manifest.mjs --root-key "$keydir/root.pem" ...    # or --renew ...
//   #   plus --also-reserve "$keydir/reserve.pem" when the reserve was decrypted
//   node tools/sign-update-manifest.mjs --verify manifest.json
//
// **Decrypt to a FILE, and check gpg's exit status BEFORE the signer runs.** Never hand this script
// a named FIFO whose writer may fail before it opens the FIFO, such as `mkfifo p; gpg --decrypt
// --output p …` where gpg dies on a wrong passphrase or a timed-out pinentry and never opens its
// output. Opening a FIFO for reading waits for a writer, so `readFileSync` below blocks in open()
// forever, with silence as the only symptom. That happened on 2026-09-11. Process substitution
// (`--root-key <(gpg …)`) does not hang, but it runs the signer without anybody having looked at
// gpg's status either.
//
// `--no-symkey-cache` because a symmetric decrypt otherwise leaves the passphrase in gpg-agent for
// ten minutes, during which any process running as you can decrypt the root key without a prompt.
// The throwaway GNUPGHOME keeps that agent, and anything it remembers, away from every other key.
//
// ── what this document is for ──────────────────────────────────────────────
//
// Every installed Astra asks `GET /api/updates/manifest` on a timer and believes
// what it finds only if this signature verifies against a root compiled into the
// binary. The server holds no key and cannot make one: it serves the file's bytes
// unchanged, which means a compromised API can withhold an update but can never
// ship one.
//
//     sig = Ed25519(root_priv, SHA-256( "astra.update.v1" ‖ 0x00 ‖ JCS(signed) ))
//
// Same construction, same canonicaliser and same envelope as `sign-trust.mjs`,
// with this document's own domain. That is not tidiness: the daemon has exactly
// one Ed25519 verification and one canonicaliser, and a second signer that agreed
// with it *nearly* would produce manifests that verify here and nowhere else.
//
// ── the root key is a PATH, and only ever a path ───────────────────────────
//
// A key on a command line is a key in the shell history and in `ps`. What is
// passed is the path to a file that exists, in tmpfs, for the seconds a signature
// takes. This script does no network I/O.
//
// ── the guards, and why each exists ────────────────────────────────────────
//
// **The key is proved to be a published root, in the role asked for, before
// anything is written.** A key from a test directory or last year's key writes a
// document that verifies against itself and against no shipped daemon. The
// primary `--root-key` must be the ACTIVE root: the reserve signs as the primary
// only when `--reserve` says so, so reaching for the reserve by accident is refused
// here rather than spent. `--also-reserve` must be the reserve.
//
// **The size and digest are computed from the artefact, never accepted as
// arguments.** A manifest naming a file that is not there is August's webhook
// failure with a different noun: every delivery fails, nothing notices. If the
// installer is not on this machine, put it on this machine. (`--renew` and
// `--withdraw-to` take them from a document a published root already signed,
// never from an argument; see below.)
//
// **The filename must be in the closed set the client already accepts**, with a
// version that is SemVer 2.0.0 (no leading zeros, no empty pre-release
// identifier; the client parses it with the `semver` crate and calls the whole
// manifest malformed otherwise). The name becomes a URL component and a path on
// disk over there. The client widens that set BEFORE this publishes a new shape,
// never after. Every artefact carries the four fields the client's `Artifact`
// requires, a 64-character lowercase sha256 and a whole number of bytes.
//
// **Release notes are refused if they carry a "<", "](", "http://" or
// "https://"**, which is the API server's rule exactly (minice
// api/crates/astra-server/src/updates.rs, `load`). The server refuses to serve a
// manifest whose notes contain any of them: the WHOLE manifest, as a 503, so every
// client stops learning about updates and nothing on their side says why. The
// client itself renders notes as plain text and refuses nothing about them. Two
// rules are this signer's own: notes may not be empty (omit the locale instead),
// and English must exist, because the client falls back to English and shows
// nothing when there is none. The rule is `notesProblems` below, written once:
// signing, `--check-notes` (release.sh's preflight), `--renew` and `--verify` all
// call it.
//
// **The signature is verified against the published roots before the file is
// written.** Signing and then not checking is how you find out from a user.
//
// **The desk clock is printed next to the newest signature this repository
// records**, with the difference, because signedAt comes from this machine's
// clock and a wrong clock is the one mistake nothing else here can see. A
// renewal more than a year after the signature it renews is refused as a wrong
// clock. The hard guard against a future date is on the box, whose clock is
// synchronised: `publish-release.sh --check-manifest`, below.
//
// **What nothing here checks: that clients can download the artefact.** The API
// server does not check it either; it serves the document and checks nothing
// about the file the document names. The box step that would, `publish-release.sh
// --stage` (the flip, with a probe that fetches the file through the origin and
// compares its sha256 with the signed one before installing the document), is
// PLANNED in minice M3 and does not exist yet. Until it does, the only reachability
// check is by hand: fetch the file through the CDN and hash the body.
//
// ── renewing: --renew, and withdrawing: --withdraw-to ──────────────────────
//
// `--renew <prev.json>` re-signs the CURRENT document with a fresh signedAt and
// expires and nothing else changed. It is what `release.sh --resign` calls, and it
// is why an expiry no longer means carrying the 88 MB installer back to the desk.
//
//   · The previous document must pass every check --verify makes except
//     freshness: an expired document is exactly what a renewal recovers.
//   · `latest`, and every other member except the two dates, is carried byte for
//     byte, including members this script does not model (a `repo`, say).
//   · The carried claims are re-checked against today's rules, because a renewal
//     publishes them again.
//   · The previous document must be the NEWEST release record. Every
//     releases/*/manifest.json is verified (one that fails refuses the run, since
//     it might be the newest), and the previous document must carry the latest
//     signedAt among them AND the highest latest.version. Without this, renewing
//     the superseded 0.2.4 record would re-offer, to the whole fleet, an installer
//     that answers 404.
//   · The new signedAt must be STRICTLY later than the previous one and than every
//     record's, at the seconds precision it is published with. A client refuses a
//     manifest signed before one it has seen, and two documents with one signedAt
//     and different contents cannot be ordered by anybody.
//
// `--withdraw-to <record.json>` is the only way to put an OLDER release back in
// front of the fleet, and it is its own flag so that nobody does it by accident.
// It makes the same checks except "the newest record", and its signedAt must still
// be strictly later than every record's: otherwise the clients that saw the newer
// document refuse the withdrawal as a rollback and keep the release being
// withdrawn. Renewing a withdrawal later needs --withdraw-to again.
//
// Neither knows what the server serves right now; the box does. `publish-release.sh
// --check-manifest <signed.json> [--withdraw]` (minice, since eb9e379) fetches the
// served document and refuses a candidate signed more than five minutes ahead of the
// box's NTP-synced clock and, unless --withdraw is given, one whose signedAt is at or
// before the served one or whose version is older. It checks that a signature is
// present, not that it verifies; that is --verify's job here. Run it on the box
// before installing any document by hand. It stays essential: the records rule here
// stops a wrong input on this desk, not a wrong file on the box. Its --withdraw
// waives the signedAt rule as well as the version rule, so the strictly-later rule
// for a withdrawal lives here, in --withdraw-to, and not there.
//
// ── --verify ───────────────────────────────────────────────────────────────
//
// `ok` means a shipped client would accept the document NOW: a signature from a
// published root, in canonical base64 (the client's decoder is stricter than
// Node's); the schema; no duplicate key in any object (the client parses strictly
// and refuses the whole document; JSON.parse would silently keep the last one);
// not expired; signedAt no more than 24 hours ahead of this clock (update.rs
// FUTURE_SKEW); and artefacts and notes that pass the rules above.
//
// ── signing with BOTH roots, and the one day it matters ────────────────────
//
// `--also-reserve` adds a second signature from the reserve key. The verifier
// tries every key against every signature, so a manifest carrying both is
// accepted by clients that have learned a new root and by clients that have not.
// That is what makes burning the active root a rotation rather than a day-X: on
// any other day one signature is enough and a second is noise.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  UPDATE_SCHEMA,
  addDays,
  publicKeyBase64,
  publicKeyFromBase64,
  rfc3339,
  signEnvelope,
  verifyEnvelope,
} from "../bot/lib/sign.mjs";
import { compareSemver, parseSemver } from "./lib/semver.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const ROOT_JSON = path.join(REPO, "registry", "v1", "root.json");
const RELEASES = path.join(REPO, "releases");
const DAY_MS = 86400 * 1000;

/**
 * How long the manifest claims to be current: 180 days, by the owner's decision of
 * 2026-09-11 (astra-rs UPDATES_0_2_6_PLAN.md, D16).
 *
 * The number is a trade rather than a preference. A signature proves we wrote a
 * document, never that we wrote it recently, so a cache or a middlebox can replay
 * one for ever and updates simply stop; `expires` is what bounds that freeze. But
 * the signing key is offline on purpose, so a short expiry becomes a standing
 * obligation to get the key out on a calendar. Forget it and every client refuses
 * the manifest at once, Linux clients included because expiry is checked before
 * the platform: auto-update stops silently and completely, and it looks like the
 * server is down.
 *
 * It was thirty days until 2026-09-11. Thirty made renewal a monthly errand that
 * needed the installer back on the desk, and an alarm at 30 days left would have
 * fired the moment a fresh document was installed. Now the alarm fires at 30 days
 * left (vmalert and astra-alarm), `--renew` re-signs without the artefact, and
 * every release re-signs anyway. The price is the replay window: a stale cache can
 * hold a client on an old version for up to 180 days instead of 30.
 */
export const DEFAULT_EXPIRY_DAYS = 180;

/** The longest `--expires-days` accepted. Unchanged by D16. */
export const MAX_EXPIRY_DAYS = 365;

/** How far ahead of the clock the client lets a signedAt be (astra-daemon update.rs FUTURE_SKEW). */
export const FUTURE_SKEW_MS = 24 * 3600 * 1000;

/** The locales a manifest carries notes in. English is required; the rest fall back to it. */
export const NOTE_LOCALES = ["en", "ru", "uk"];

/** The API server's markup rule, exactly: "<", "](", "http://", "https://". Case-sensitive, as there. */
const MARKUP = /<|\]\(|https?:\/\//;

/**
 * The artefact names the shipped client accepts. Widen THERE first, then here.
 *
 * `Astra-Installer-<semver>.exe` is the OUTER Slint launcher — the file a person downloads and
 * runs. The inner Inno setup is called `Astra-Setup-<semver>.exe`, is embedded in the launcher and
 * unpacked to %TEMP% for the seconds an install takes, and can never be on a CDN. This regex named
 * the inner one until 2026-09-02; it matched a file that does not exist.
 *
 * Windows only, by the owner's decision: a closed set should name what is actually published, and
 * today that is one file. The Linux shapes are in the contract for the day they ship. The captured
 * version must also parse as SemVer 2.0.0; see `artefactProblems`.
 */
const FILENAME = /^Astra-Installer-([0-9A-Za-z.-]+)\.exe$/;

const PLATFORMS = new Set(["windows-x64"]);

/** The fields the client's `Artifact` struct requires. Without one, it refuses the whole manifest. */
const ARTIFACT_FIELDS = ["platform", "filename", "sha256", "sizeBytes"];

const SHA256 = /^[0-9a-f]{64}$/;

/** The flags that describe WHAT is offered. `--renew` and `--withdraw-to` carry all of that over. */
export const CONTENT_FLAGS = [
  "--artifact",
  "--version",
  "--notes-en",
  "--notes-ru",
  "--notes-uk",
  "--min-supported",
  "--channel",
  "--released-at",
  "--platform",
  "--kind",
];

const SIGNING_FLAGS = {
  "--root-key": "value",
  "--also-reserve": "value",
  "--reserve": "bool",
  "--expires-days": "value",
  "--out": "value",
};

/** Each mode's closed set of flags, and what each flag takes. */
const MODES = {
  verify: { "--verify": "value" },
  "check-notes": { "--check-notes": "list" },
  renew: { "--renew": "value", ...SIGNING_FLAGS },
  withdraw: { "--withdraw-to": "value", ...SIGNING_FLAGS },
  sign: { ...SIGNING_FLAGS, ...Object.fromEntries(CONTENT_FLAGS.map((f) => [f, "value"])) },
};

const MODE_FLAGS = {
  "--verify": "verify",
  "--check-notes": "check-notes",
  "--renew": "renew",
  "--withdraw-to": "withdraw",
};

function die(message) {
  console.error(`sign-update-manifest: ${message}`);
  process.exit(1);
}

/**
 * The command line, against the chosen mode's closed set. Throws on anything else.
 *
 * @param {string[]} argv the arguments after the script
 * @returns {{mode: string, opts: Record<string, string | string[] | true>}}
 */
export function parseArgs(argv) {
  const given = Object.keys(MODE_FLAGS).filter((f) => argv.includes(f));
  if (given.length > 1) throw new Error(`${given.join(" and ")} are separate modes; give one`);
  const mode = given.length ? MODE_FLAGS[given[0]] : "sign";
  const spec = MODES[mode];
  const modeName = given.length ? given[0] : "signing";
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      throw new Error(`unexpected argument ${JSON.stringify(a)}: every value belongs to a flag`);
    }
    const kind = spec[a];
    if (!kind) {
      if ((mode === "renew" || mode === "withdraw") && CONTENT_FLAGS.includes(a)) {
        throw new Error(
          `${modeName} carries every claim of the previous document unchanged, so ${a} would describe a ` +
            "different release and is refused. To change what is offered, sign afresh with --artifact.",
        );
      }
      throw new Error(
        `${a} is not a flag ${modeName} accepts (${Object.keys(spec).join(" ")}). An unknown flag is ` +
          "refused, never ignored: a typo'd --expires-days would otherwise sign for the default.",
      );
    }
    if (a in opts) throw new Error(`${a} is given twice; which one was meant is not something to guess`);
    if (kind === "bool") {
      opts[a] = true;
    } else if (kind === "value") {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value`);
      opts[a] = v;
      i++;
    } else {
      const list = [];
      while (i + 1 < argv.length && !argv[i + 1].startsWith("--")) list.push(argv[++i]);
      opts[a] = list;
    }
  }
  return { mode, opts };
}

/**
 * The notes rule, and the only copy of it: signing applies it, `--check-notes` applies it, and
 * `--renew`, `--withdraw-to` and `--verify` apply it to the notes a document carries.
 *
 * Refused: a note that is not a string, a locale the manifest does not carry, the same locale
 * twice, notes that are empty after trimming, notes with the server's markup triggers, and a set
 * with no English.
 *
 * @param {{locale: string, where: string, text: unknown}[]} entries the raw text of each note
 * @returns {{notes: Record<string, string>, problems: string[]}} the trimmed notes that passed,
 *   and one sentence per problem; the set is acceptable only when `problems` is empty
 */
export function notesProblems(entries) {
  const notes = {};
  const problems = [];
  const seen = new Set();
  for (const { locale, where, text: raw } of entries) {
    if (typeof raw !== "string") {
      problems.push(`${where}: the ${locale} notes are ${JSON.stringify(raw)}, not a string; the client refuses the whole manifest`);
      continue;
    }
    if (!NOTE_LOCALES.includes(locale)) {
      problems.push(
        `${where}: ${JSON.stringify(locale)} is not a locale the manifest carries ` +
          `(${NOTE_LOCALES.join(", ")}), so no client would ever show it`,
      );
      continue;
    }
    if (seen.has(locale)) {
      problems.push(`${where}: a second set of ${locale} notes; one of them would be silently dropped`);
      continue;
    }
    seen.add(locale);
    const text = raw.trim();
    if (!text) {
      problems.push(
        `${where}: the ${locale} notes are empty. Omit that locale instead: a locale nobody wrote ` +
          "falls back to English",
      );
      continue;
    }
    if (MARKUP.test(text)) {
      problems.push(
        `${where}: the ${locale} notes carry markup or a link (a "<", "](", "http://" or "https://"). ` +
          "The API server refuses to serve a manifest whose notes contain one: the WHOLE manifest, as " +
          "a 503, so every client would stop learning about updates. (The client renders notes as plain " +
          "text and refuses nothing.)",
      );
      continue;
    }
    notes[locale] = text;
  }
  if (!entries.some((e) => e.locale === "en")) {
    problems.push(
      "there are no English notes, and they are required: the client falls back to English for a " +
        "locale nobody wrote, and shows nothing when there is no English",
    );
  }
  return { notes, problems };
}

/**
 * One artefact entry against the rules this signer enforces: the four fields the client requires,
 * the filename in the client's closed set with a SemVer 2.0.0 version equal to `version`, a
 * platform this signer publishes, a lowercase sha256 and a whole number of bytes.
 *
 * @param {unknown} a
 * @param {string} version the release's version
 * @param {string} where how to name this entry in a problem
 * @returns {string[]}
 */
export function artefactProblems(a, version, where = "the artefact") {
  if (!a || typeof a !== "object" || Array.isArray(a)) return [`${where} is not an object`];
  const missing = ARTIFACT_FIELDS.filter((f) => !(f in a));
  if (missing.length) {
    return [
      `${where} has no ${missing.join(", ")}. The client's Artifact requires platform, filename, ` +
        "sha256 and sizeBytes, and refuses the whole manifest without one",
    ];
  }
  const problems = [];
  const m = typeof a.filename === "string" ? FILENAME.exec(a.filename) : null;
  if (!m || !parseSemver(m[1])) {
    problems.push(
      `${where} is named ${JSON.stringify(a.filename)}, which is outside the set the shipped client ` +
        "accepts: Astra-Installer-<version>.exe, where the version is SemVer 2.0.0 (no leading zeros, " +
        "no empty pre-release identifier). That name becomes a URL component AND a path on disk over " +
        "there. Rename it, or widen the set in the CLIENT first and ship that before publishing a new " +
        "shape here.",
    );
  } else if (m[1] !== version) {
    problems.push(`${where}: version ${version} disagrees with the filename's ${m[1]}; one of them is wrong`);
  }
  if (!PLATFORMS.has(a.platform)) {
    problems.push(`${where}: platform ${JSON.stringify(a.platform)} is not one this signer publishes (${[...PLATFORMS].join(", ")})`);
  }
  if (typeof a.sha256 !== "string" || !SHA256.test(a.sha256)) {
    problems.push(`${where}: sha256 ${JSON.stringify(a.sha256)} is not 64 lowercase hex characters`);
  }
  if (!Number.isSafeInteger(a.sizeBytes) || a.sizeBytes < 0) {
    problems.push(`${where}: sizeBytes ${JSON.stringify(a.sizeBytes)} is not a whole number of bytes`);
  }
  return problems;
}

/**
 * What a document offers, against the rules above: `latest` itself, `placeholder`, the notes and
 * every artefact.
 *
 * @param {any} signed the document's `signed` member
 * @returns {string[]}
 */
export function contentProblems(signed) {
  const latest = signed?.latest;
  if (!latest || typeof latest !== "object" || Array.isArray(latest)) return ["`latest` is not an object"];
  const problems = [];
  if (typeof latest.version !== "string" || !parseSemver(latest.version)) {
    problems.push(`latest.version ${JSON.stringify(latest.version)} is not a SemVer version`);
  }
  if ("placeholder" in latest && typeof latest.placeholder !== "boolean") {
    problems.push(`latest.placeholder is ${JSON.stringify(latest.placeholder)}, not a boolean; the client refuses the whole manifest`);
  }
  const notes = latest.notes ?? {};
  if (!notes || typeof notes !== "object" || Array.isArray(notes)) {
    problems.push("latest.notes is not an object of strings");
  } else {
    const entries = Object.entries(notes).map(([locale, text]) => ({ locale, where: `latest.notes.${locale}`, text }));
    problems.push(...notesProblems(entries).problems);
  }
  const artifacts = latest.artifacts;
  if (!Array.isArray(artifacts) || !artifacts.length) {
    problems.push("latest.artifacts offers nothing");
  } else {
    artifacts.forEach((a, i) => problems.push(...artefactProblems(a, latest.version, `latest.artifacts[${i}]`)));
  }
  return problems;
}

/**
 * The first object key that appears twice in one object, or undefined.
 *
 * `text` must already have parsed. The client's parser refuses a document with a duplicate key
 * outright (astra-core trust_envelope::parse_json_strict), while JSON.parse silently keeps the last
 * one, so without this check `--verify` would bless a document every client refuses.
 */
export function duplicateKey(text) {
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top?.object && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) return key;
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (c === "{") {
      stack.push({ object: true, keys: new Set(), expectKey: true });
    } else if (c === "[") {
      stack.push({ object: false });
    } else if (c === "}" || c === "]") {
      stack.pop();
    } else if (c === ",") {
      const top = stack[stack.length - 1];
      if (top?.object) top.expectKey = true;
    }
  }
  return undefined;
}

/**
 * The envelope of a document: JSON with no duplicate key, a signature from one of `roots` in
 * canonical base64, and the schema. Never exits.
 *
 * @param {string} text the file's bytes, as text
 * @param {{key_id: string, publicKey: import("node:crypto").KeyObject}[]} roots
 * @returns {{doc?: any, key_id?: string, problems: string[]}}
 */
export function envelopeProblems(text, roots) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { problems: [`it is not JSON: ${e.message}`] };
  }
  const problems = [];
  const dup = duplicateKey(text);
  if (dup !== undefined) {
    problems.push(
      `the key ${JSON.stringify(dup)} appears twice in one object. The client parses strictly and ` +
        "refuses the whole document; JSON.parse here would have kept the last one in silence",
    );
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { problems: [...problems, "it is not a JSON object"] };
  if (!Array.isArray(doc.signatures)) return { doc, problems: [...problems, "it has no `signatures` array"] };
  // The client decodes with the standard engine, which refuses what Node's lenient decoder accepts
  // (a missing "=", stray bytes). A signature only the lenient decoder can read is one no client
  // will ever try, so it is not tried here either.
  const canonical = doc.signatures.filter(
    (s) => typeof s?.sig === "string" && Buffer.from(s.sig, "base64").toString("base64") === s.sig,
  );
  const skipped = doc.signatures.length - canonical.length;
  let result;
  try {
    result = verifyEnvelope({ ...doc, signatures: canonical }, UPDATE_SCHEMA, roots);
  } catch (e) {
    // This repository's canonicaliser encodes integers only, so a body it cannot encode is one no
    // signer here produced. Refused as such, rather than crashing the tool with a stack trace.
    result = { ok: false, reason: `its signed body cannot be canonicalised here (${e.message})` };
  }
  if (!result.ok) {
    problems.push(
      `it does not verify: ${result.reason} (offered: ${doc.signatures.map((s) => s?.key_id).join(", ") || "none"})` +
        (skipped ? `; ${skipped} signature(s) are not canonical base64, which the client refuses to decode` : ""),
    );
  }
  if (doc.signed?.schema !== UPDATE_SCHEMA) {
    problems.push(
      `it declares schema ${JSON.stringify(doc.signed?.schema)}. A body of one version signed under ` +
        "another's domain VERIFIES, because the domain is not read from the file, which is exactly why " +
        "this is checked separately",
    );
  }
  return { doc, key_id: result.ok ? result.key_id : undefined, problems };
}

/**
 * Whether a client whose clock reads `now` would refuse the document as stale or as from the
 * future (update.rs `evaluate`, step 3).
 */
export function freshnessProblems(signed, now) {
  const problems = [];
  const expires = instant(signed?.expires);
  const signedAt = instant(signed?.signedAt);
  if (expires === undefined) {
    problems.push(`expires ${JSON.stringify(signed?.expires)} is not an RFC 3339 instant`);
  } else if (expires <= now.getTime()) {
    problems.push(`it expired at ${signed.expires} and this clock reads ${rfc3339(now)}: every client refuses it`);
  }
  if (signedAt === undefined) {
    problems.push(`signedAt ${JSON.stringify(signed?.signedAt)} is not an RFC 3339 instant`);
  } else if (signedAt > now.getTime() + FUTURE_SKEW_MS) {
    problems.push(
      `signedAt ${signed.signedAt} is more than 24 hours ahead of this clock (${rfc3339(now)}); the ` +
        "client refuses it as from the future",
    );
  }
  return problems;
}

/**
 * The `signed` block of a renewal: the previous document's, member for member and in the same
 * order, with a fresh `signedAt` and `expires` and nothing else changed.
 *
 * Throws unless the new `signedAt`, at the seconds precision it is published with, is strictly
 * later than the previous one. A pure function of its inputs, so the boundary is testable without
 * a clock flag on a tool that holds a root key: a way to choose `signedAt` from the command line
 * is a way to date a document next year and poison every client's floor.
 *
 * @param {Record<string, unknown>} prev the previous document's `signed` member, already verified
 * @param {Date} now
 * @param {number} days
 */
export function renewSigned(prev, now, days) {
  const prevAt = instant(prev.signedAt);
  if (prevAt === undefined) {
    throw new Error(
      `the previous document's signedAt ${JSON.stringify(prev.signedAt)} is not an RFC 3339 instant`,
    );
  }
  const signedAt = rfc3339(now);
  if (!(Date.parse(signedAt) > prevAt)) {
    throw new Error(
      `the renewal would be signed at ${signedAt}, which is not strictly later than the previous ` +
        `document's ${prev.signedAt}. A client refuses a manifest signed before one it has seen, and ` +
        "two documents with one signedAt cannot be ordered by anybody. Check this machine's clock; " +
        "if it is right, the previous document is dated in the future and must not be renewed.",
    );
  }
  return { ...prev, signedAt, expires: rfc3339(addDays(now, days)) };
}

/** Milliseconds since the epoch for an RFC 3339 date-time, or undefined for anything else. */
function instant(value) {
  if (typeof value !== "string") return undefined;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    return undefined;
  }
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : t;
}

/** "+1d 02:03:04": how far `ms` is, signed. */
function span(ms) {
  let s = Math.floor(Math.abs(ms) / 1000);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const pad = (n) => String(n).padStart(2, "0");
  return `${ms < 0 ? "-" : "+"}${d}d ${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`;
}

/** The published roots, as `verifyEnvelope` wants them. */
function publishedRoots() {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(ROOT_JSON, "utf8"));
  } catch (e) {
    die(`cannot read ${ROOT_JSON}: ${e.message}`);
  }
  if (doc.status !== "provisioned") {
    die(
      `${ROOT_JSON} says status ${JSON.stringify(doc.status)} — the ceremony has not run, so no ` +
        "shipped daemon trusts anything and there is nothing to sign with.",
    );
  }
  const roots = Array.isArray(doc.roots) ? doc.roots : [];
  if (!roots.length) die(`${ROOT_JSON} lists no roots`);
  return roots.map((r) => ({ key_id: r.key_id, publicKey: publicKeyFromBase64(r.public_key) }));
}

/**
 * Load a root private key and prove it is one of the published roots, in the role asked for.
 *
 * Without this, the happy path of a mistake writes a document that verifies
 * against itself and against nothing that ships.
 */
function loadRoot(pemPath, expectRole, flag) {
  let pem;
  try {
    pem = fs.readFileSync(pemPath);
  } catch (e) {
    die(`cannot read the root key at ${pemPath}: ${e.message}`);
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(pem);
  } catch (e) {
    die(`${pemPath} is not a private key OpenSSL wrote: ${e.message}`);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    die(`${pemPath} is a ${privateKey.asymmetricKeyType} key; the roots are ed25519`);
  }

  const pub = publicKeyBase64(privateKey);
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(ROOT_JSON, "utf8"));
  } catch (e) {
    die(`cannot read ${ROOT_JSON}: ${e.message}`);
  }
  const match = (doc.roots ?? []).find((r) => r.public_key === pub);
  if (!match) {
    die(
      `the key at ${pemPath} is not one of the roots published in registry/v1/root.json. ` +
        "A manifest signed with it would verify against itself and be refused by every shipped " +
        "Astra, and the first you would hear of it is a user who never got an update.",
    );
  }
  if (match.role !== expectRole) {
    die(
      `${flag} ${pemPath} is the ${match.role} root, and this needs the ${expectRole} one. The ` +
        "primary --root-key is the ACTIVE root unless --reserve says you mean the reserve, and " +
        "--also-reserve is always the reserve: spending the reserve by accident is refused here.",
    );
  }
  return { key_id: match.key_id, privateKey, role: match.role };
}

/** The signers named on the command line, each proved to be a published root in its role. */
function signersFromOpts(opts) {
  const keyPath = opts["--root-key"];
  if (!keyPath) die("--root-key <path to the decrypted root key> is required");
  const signers = [loadRoot(keyPath, opts["--reserve"] ? "reserve" : "active", "--root-key")];
  if (opts["--also-reserve"]) signers.push(loadRoot(opts["--also-reserve"], "reserve", "--also-reserve"));
  return signers;
}

function expiryDays(opts) {
  const raw = opts["--expires-days"];
  const days = raw === undefined ? DEFAULT_EXPIRY_DAYS : Number(raw);
  if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) {
    die(`--expires-days ${raw} is not a whole number of days between 1 and ${MAX_EXPIRY_DAYS}`);
  }
  return days;
}

/**
 * Where the signed document goes, refused when that is the previous document itself or anywhere
 * under releases/. The record is what went live, committed after the flip; the signer never
 * writes it, so a document that never went live cannot pass for one that did.
 */
function outputPath(opts, prevPath) {
  const out = path.resolve(opts["--out"] ?? "manifest.json");
  if (prevPath !== undefined && out === path.resolve(prevPath)) {
    die(`--out ${out} is the previous document itself; the input is never overwritten`);
  }
  const rel = path.relative(RELEASES, out);
  if (!rel.startsWith("..") && !path.isAbsolute(rel)) {
    die(
      `--out ${out} lies under releases/. A record is what went live, committed after the flip; ` +
        "the signer never writes one.",
    );
  }
  return out;
}

/**
 * Every committed release record, verified against the published roots (not for freshness: a
 * record is history). A record that does not verify refuses the run, because it might be the
 * newest and the rules that compare against the newest cannot be applied without it.
 */
function releaseRecords(roots) {
  let dirs;
  try {
    dirs = fs.readdirSync(RELEASES);
  } catch {
    return [];
  }
  const out = [];
  for (const v of dirs.sort()) {
    const file = path.join(RELEASES, v, "manifest.json");
    if (!fs.existsSync(file)) continue;
    const rel = path.relative(REPO, file);
    const { doc, problems } = envelopeProblems(fs.readFileSync(file, "utf8"), roots);
    if (problems.length) {
      die(
        `${rel}, a committed release record, does not verify: ${problems.join("; ")}. It might be ` +
          "the newest record, so nothing is compared or signed until it is fixed.",
      );
    }
    const at = instant(doc.signed.signedAt);
    const version = doc.signed.latest?.version;
    if (at === undefined || !parseSemver(version)) {
      die(`${rel} has no readable signedAt or version, so it cannot be ordered against anything`);
    }
    out.push({ rel, signedAt: doc.signed.signedAt, at, version });
  }
  return out;
}

/** The record signed last, and the record offering the highest version. */
function newestRecords(records) {
  let bySignedAt = records[0];
  let byVersion = records[0];
  for (const r of records) {
    if (r.at > bySignedAt.at) bySignedAt = r;
    if (compareSemver(r.version, byVersion.version) > 0) byVersion = r;
  }
  return { bySignedAt, byVersion };
}

function readOrDie(where, what) {
  try {
    return fs.readFileSync(where, "utf8");
  } catch (e) {
    return die(`cannot read ${what} at ${where}: ${e.message}`);
  }
}

/** Read one notes file into an entry for `notesProblems`, or a problem if it cannot be read. */
function readNoteFile(locale, where) {
  try {
    return { entry: { locale, where, text: fs.readFileSync(where, "utf8") } };
  } catch (e) {
    return { problem: `cannot read the ${locale} notes at ${where}: ${e.message}` };
  }
}

/** Release notes from the --notes-<locale> flags, refused by the one rule. */
function notesFromOpts(opts) {
  const entries = [];
  for (const locale of NOTE_LOCALES) {
    const where = opts[`--notes-${locale}`];
    if (where === undefined) continue;
    const read = readNoteFile(locale, where);
    if (read.problem) die(read.problem);
    entries.push(read.entry);
  }
  const { notes, problems } = notesProblems(entries);
  if (problems.length) die(problems.join("\n  "));
  return notes;
}

/** Size and digest, from the bytes themselves. Never from an argument. */
function artefactFromOpts(opts) {
  const where = opts["--artifact"];
  if (!where) die("--artifact is required — the size and digest are computed, never accepted");
  let bytes;
  try {
    bytes = fs.readFileSync(where);
  } catch (e) {
    die(
      `cannot read the artefact at ${where}: ${e.message}. If the installer is not on this ` +
        "machine, put it on this machine: a manifest naming a file nobody checked is the same " +
        "defect as a webhook naming a host that was never deployed.",
    );
  }
  const filename = path.basename(where);
  const art = {
    platform: opts["--platform"] ?? "windows-x64",
    kind: opts["--kind"] ?? "installer",
    filename,
    sizeBytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
  const version = opts["--version"] ?? FILENAME.exec(filename)?.[1];
  const problems = artefactProblems(art, version);
  if (problems.length) die(problems.join("\n  "));
  return { ...art, version };
}

/** The desk clock, next to a signature it is about to be compared with. */
function printClock(now, label, signedAt, where) {
  console.log(`  desk clock     ${rfc3339(now)}  (UTC, this machine's clock)`);
  if (signedAt === undefined) {
    console.log(`  ${label.padEnd(14)} none under releases/`);
    return;
  }
  console.log(
    `  ${label.padEnd(14)} ${signedAt}${where ? `  in ${where}` : ""}  ` +
      `(desk clock is ${span(now.getTime() - instant(signedAt))} after it)`,
  );
}

/** The truth about what a signature here does and does not establish. */
function printWhatWasNotChecked() {
  console.log("What it did NOT check: that this document may replace the one being served, or that clients");
  console.log("can download that file. The API server checks neither. Before installing it by hand, run");
  console.log("  publish-release.sh --check-manifest <this file>        (add --withdraw only for a withdrawal)");
  console.log("on the box: it refuses a signedAt not later than the served one or more than 5 minutes ahead of");
  console.log("the box's clock, and an older version. Reachability is still by hand: fetch the file through");
  console.log("the CDN and hash the body. The box step that probes it, publish-release.sh --stage, is planned");
  console.log("in minice M3 and does not exist yet.");
}

function verifyFile(where) {
  const roots = publishedRoots();
  const text = readOrDie(where, "the manifest");
  const now = new Date();
  const { doc, key_id, problems } = envelopeProblems(text, roots);
  if (doc?.signed && typeof doc.signed === "object") {
    problems.push(...freshnessProblems(doc.signed, now), ...contentProblems(doc.signed));
  }
  if (problems.length) {
    for (const p of problems) console.error(`sign-update-manifest: ${where}: ${p}`);
    die(`${where} is not a document a client would accept (${problems.length} problem(s))`);
  }
  const signed = doc.signed;
  const left = (instant(signed.expires) - now.getTime()) / DAY_MS;
  console.log(`ok  ${where}`);
  console.log(`    signed by      ${key_id}`);
  console.log(`    version        ${signed.latest.version}`);
  console.log(`    signedAt       ${signed.signedAt}`);
  console.log(`    expires        ${signed.expires}  (${left.toFixed(1)} days left)`);
  for (const a of signed.latest.artifacts) {
    console.log(`    ${a.platform}  ${a.filename}  ${a.sizeBytes} bytes  ${a.sha256.slice(0, 16)}…`);
  }
  console.log(`    a client whose clock reads ${rfc3339(now)} would accept it`);
}

/**
 * `--check-notes <dir-or-files…>`: the notes rule alone, with no key and no artefact.
 *
 * A directory contributes every `notes.<locale>.txt` in it; a file must be named that way, because
 * the locale is read from the name. Every problem is reported, not only the first, so a preflight
 * shows the whole list at once.
 */
function checkNotes(paths) {
  if (!paths.length) die("--check-notes needs a directory or notes.<locale>.txt files");
  const NAME = /^notes\.([^.]+)\.txt$/;
  const found = [];
  const problems = [];
  for (const p of paths) {
    let stat;
    try {
      stat = fs.statSync(p);
    } catch (e) {
      problems.push(`cannot read ${p}: ${e.message}`);
      continue;
    }
    if (stat.isDirectory()) {
      const names = fs.readdirSync(p).filter((n) => NAME.test(n)).sort();
      if (!names.length) problems.push(`${p} holds no notes.<locale>.txt`);
      for (const n of names) found.push({ locale: NAME.exec(n)[1], where: path.join(p, n) });
    } else {
      const m = NAME.exec(path.basename(p));
      if (!m) {
        problems.push(`${p}: cannot tell which locale this is; name it notes.<locale>.txt`);
        continue;
      }
      found.push({ locale: m[1], where: p });
    }
  }
  const entries = [];
  for (const { locale, where } of found) {
    const read = readNoteFile(locale, where);
    if (read.problem) problems.push(read.problem);
    else entries.push(read.entry);
  }
  const verdict = notesProblems(entries);
  problems.push(...verdict.problems);
  for (const { locale, where } of entries) {
    if (verdict.notes[locale] !== undefined) console.log(`ok  ${where}  ${locale}`);
  }
  if (problems.length) {
    for (const p of problems) console.error(`sign-update-manifest: ${p}`);
    die(`--check-notes found ${problems.length} problem(s); the signer would refuse these notes`);
  }
  console.log(`notes ok: ${Object.keys(verdict.notes).join(" ")}. The signer would accept these.`);
}

/** `--renew <prev>` and, with `withdrawal`, `--withdraw-to <prev>`. */
function renew(opts, prevPath, withdrawal) {
  const flag = withdrawal ? "--withdraw-to" : "--renew";
  const out = outputPath(opts, prevPath);
  const roots = publishedRoots();

  // Every check --verify makes except freshness: an expired document is what a renewal recovers.
  const { doc: prev, problems: envelope } = envelopeProblems(readOrDie(prevPath, "the previous document"), roots);
  if (envelope.length) die(`${prevPath} does not verify:\n  ${envelope.join("\n  ")}`);
  const carried = contentProblems(prev.signed);
  if (carried.length) {
    die(`${prevPath} verifies, but ${flag} would publish claims today's rules refuse:\n  ${carried.join("\n  ")}`);
  }

  const records = releaseRecords(roots);
  if (!records.length) {
    die(
      `there is no release record (releases/*/manifest.json) to compare ${prevPath} against. ${flag} ` +
        "re-dates a document for the whole fleet, so it refuses rather than guess which one is current.",
    );
  }
  const { bySignedAt, byVersion } = newestRecords(records);
  const prevAt = instant(prev.signed.signedAt);
  const version = prev.signed.latest.version;
  const now = new Date();

  console.log(`${withdrawal ? "WITHDRAWAL to" : "renewing"} ${prevPath}  (version ${version})`);
  printClock(now, "previous", prev.signed.signedAt);
  console.log(
    `  newest record  ${bySignedAt.rel}  signedAt ${bySignedAt.signedAt}, version ${bySignedAt.version}` +
      (byVersion !== bySignedAt ? `; highest version ${byVersion.version} in ${byVersion.rel}` : "") +
      `  (${records.length} record(s) compared)`,
  );

  if (!withdrawal) {
    if (prevAt < bySignedAt.at) {
      die(
        `${prevPath} is signed ${prev.signed.signedAt}, and ${bySignedAt.rel} was signed later ` +
          `(${bySignedAt.signedAt}). Renewing an older document would re-offer a superseded release to ` +
          "the whole fleet. Renew the newest record; if going back is the intent, say so with --withdraw-to.",
      );
    }
    if (compareSemver(version, byVersion.version) < 0) {
      die(
        `${prevPath} offers ${version}, and ${byVersion.rel} offers ${byVersion.version}. Renewing it ` +
          "would put an older release back in front of the fleet; if that is the intent, say so with --withdraw-to.",
      );
    }
  }

  const days = expiryDays(opts);
  let signed;
  try {
    signed = renewSigned(prev.signed, now, days);
  } catch (e) {
    die(e.message);
  }
  if (!(Date.parse(signed.signedAt) > bySignedAt.at)) {
    die(
      `the new signedAt ${signed.signedAt} is not strictly later than ${bySignedAt.rel}'s ` +
        `${bySignedAt.signedAt}. The clients that saw that document would refuse this one as a rollback ` +
        "and keep what it offers. Check this machine's clock.",
    );
  }
  if (now.getTime() - Math.max(prevAt, bySignedAt.at) > MAX_EXPIRY_DAYS * DAY_MS) {
    die(
      `this machine's clock (${rfc3339(now)}) is more than ${MAX_EXPIRY_DAYS} days after the newest ` +
        "signature it is compared with. No manifest lives that long, so the likelier explanation is a " +
        "wrong clock. Check it; if it is right, sign the current release afresh with --artifact.",
    );
  }

  const signers = signersFromOpts(opts);
  const doc = signEnvelope({ domain: UPDATE_SCHEMA, signed, signers });
  const check = verifyEnvelope(doc, UPDATE_SCHEMA, roots);
  if (!check.ok) {
    die(`the document this just signed does not verify: ${check.reason} — nothing written`);
  }

  fs.writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`${withdrawal ? "withdrew" : "renewed"} ${prevPath} -> ${out}`);
  console.log(`  signed by      ${signers.map((s) => `${s.key_id} (${s.role})`).join(" + ")}`);
  console.log(`  version        ${version}  (everything but signedAt and expires carried over unchanged)`);
  for (const a of prev.signed.latest.artifacts) {
    console.log(`  artefact       ${a.platform}  ${a.filename}  ${a.sizeBytes} bytes`);
    console.log(`  sha256         ${a.sha256}`);
  }
  console.log(`  signedAt       ${prev.signed.signedAt} -> ${signed.signedAt}`);
  console.log(`  expires        ${signed.expires}  (${days} days)`);
  if (withdrawal) {
    console.log(`  THIS OFFERS ${version} IN FRONT OF THE NEWER ${byVersion.version}. That is what --withdraw-to is for.`);
  }
  console.log("");
  console.log(`What this checked: ${prevPath} verifies against registry/v1/root.json; everything in it but`);
  console.log("signedAt and expires was carried over unchanged and passes today's filename, artefact and");
  console.log(
    withdrawal
      ? "notes rules; the new signedAt is strictly later than every record's; the new signature verifies."
      : "notes rules; it is the newest record by signedAt and by version; the new signedAt is strictly later; the new signature verifies.",
  );
  console.log("The artefact was NOT re-hashed: its size and sha256 are the previous document's, which a");
  console.log("published root already signed.");
  printWhatWasNotChecked();
}

function signFresh(opts) {
  const out = outputPath(opts);
  const roots = publishedRoots();
  const signers = signersFromOpts(opts);
  const art = artefactFromOpts(opts);
  const days = expiryDays(opts);
  const notes = notesFromOpts(opts);
  const records = releaseRecords(roots);
  const now = new Date();
  const newest = records.length ? newestRecords(records) : undefined;

  console.log(`signing ${art.filename}  (version ${art.version})`);
  printClock(now, "newest record", newest?.bySignedAt.signedAt, newest?.bySignedAt.rel);
  if (newest) {
    const { bySignedAt, byVersion } = newest;
    if (!(Date.parse(rfc3339(now)) > bySignedAt.at)) {
      die(
        `this would be signed at ${rfc3339(now)}, which is not strictly later than ${bySignedAt.rel}'s ` +
          `${bySignedAt.signedAt}. The clients that saw that document would refuse this one as a rollback. ` +
          "Check this machine's clock.",
      );
    }
    if (compareSemver(art.version, byVersion.version) < 0) {
      die(
        `${art.version} is older than the ${byVersion.version} that ${byVersion.rel} offers. Putting an older ` +
          `release in front of the fleet is a withdrawal: use --withdraw-to releases/${art.version}/manifest.json ` +
          "(that release's record) instead.",
      );
    }
  }

  const signed = {
    schema: UPDATE_SCHEMA,
    channel: opts["--channel"] ?? "stable",
    signedAt: rfc3339(now),
    expires: rfc3339(addDays(now, days)),
    min_supported_version: opts["--min-supported"] ?? art.version,
    latest: {
      version: art.version,
      releasedAt: opts["--released-at"] ?? rfc3339(now),
      placeholder: false,
      notes,
      artifacts: [
        {
          platform: art.platform,
          kind: art.kind,
          filename: art.filename,
          sizeBytes: art.sizeBytes,
          sha256: art.sha256,
        },
      ],
    },
  };

  const doc = signEnvelope({ domain: UPDATE_SCHEMA, signed, signers });

  // **Verified before it is written, against the published roots rather than against
  // the key just used.** Signing and then trusting the arithmetic is how you find out
  // from a user; this is the same check every shipped daemon will make.
  const check = verifyEnvelope(doc, UPDATE_SCHEMA, roots);
  if (!check.ok) {
    die(`the document this just signed does not verify: ${check.reason} — nothing written`);
  }

  fs.writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`wrote ${out}`);
  console.log(`  signed by      ${signers.map((s) => `${s.key_id} (${s.role})`).join(" + ")}`);
  console.log(`  version        ${art.version}`);
  console.log(`  artefact       ${art.filename}  ${art.sizeBytes} bytes`);
  console.log(`  sha256         ${art.sha256}`);
  console.log(`  expires        ${signed.expires}  (${days} days)`);
  console.log("");
  console.log("What this checked: the key is a published root in its role; the size and sha256 above were");
  console.log("computed from the file on this machine; its name is in the set the client accepts; the notes");
  console.log("pass the server's rule with English present; the release is not older than the newest record");
  console.log("and signedAt is later than it; the signature verifies against registry/v1/root.json.");
  printWhatWasNotChecked();
}

function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (e) {
    die(e.message);
  }
  const { mode, opts } = parsed;
  if (mode === "check-notes") return checkNotes(opts["--check-notes"]);
  if (mode === "verify") return verifyFile(opts["--verify"]);
  if (mode === "renew") return renew(opts, opts["--renew"], false);
  if (mode === "withdraw") return renew(opts, opts["--withdraw-to"], true);
  return signFresh(opts);
}

// Run only when executed, so the pure functions above can be imported by the selftest without
// signing anything.
function executedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (executedDirectly()) main();
