#!/usr/bin/env node
// Sign the Astra update manifest with a production root key.
//
//   node tools/sign-update-manifest.mjs --root-key "$key" \
//     --artifact <where it is>/Astra-Installer-0.2.6.exe \
//     --notes-en releases/0.2.6/notes.en.txt \
//     --notes-ru releases/0.2.6/notes.ru.txt \
//     --notes-uk releases/0.2.6/notes.uk.txt \
//     [--version 0.2.6] [--min-supported 0.2.4] [--expires-days 180] \
//     [--also-reserve <reserve pem>] --out manifest.json
//
//   node tools/sign-update-manifest.mjs --renew releases/0.2.5/manifest.json \
//     --root-key "$key" [--expires-days 180] [--also-reserve <reserve pem>] --out manifest.json
//
//   node tools/sign-update-manifest.mjs --verify manifest.json
//
//   node tools/sign-update-manifest.mjs --check-notes releases/0.2.6           # a directory
//   node tools/sign-update-manifest.mjs --check-notes notes.en.txt notes.ru.txt  # or files
//
// Exit status: 0 when the mode did what it says, 1 for every refusal. A refusal writes nothing.
//
// ── where "$key" comes from: decrypt, check, sign, shred ────────────────────
//
// The root key is used ONLY by decrypting its symmetric `.pem.gpg` copy. Where that copy lives is
// recorded in the astra-rs repository, docs/KEY_CEREMONY.md §5, and is deliberately not repeated
// here. Never point --root-key at a plaintext PEM, wherever one may still sit. In bash, not fish:
//
//   set -euo pipefail
//   root_gpg='<the .pem.gpg that KEY_CEREMONY.md §5 names>'
//   : "${XDG_RUNTIME_DIR:?is unset: refusing to put a root key anywhere but tmpfs}"
//   GNUPGHOME="$(mktemp -d)"; export GNUPGHOME     # throwaway, never the archive key's home
//   keydir="$(mktemp -d -p "$XDG_RUNTIME_DIR")"   # tmpfs, mode 0700
//   key="$keydir/root.pem"
//   cleanup() {
//     if [ -e "$key" ]; then shred -u "$key"; fi
//     rm -rf "$keydir"
//     gpgconf --kill gpg-agent 2>/dev/null || true
//     rm -rf "$GNUPGHOME"
//   }
//   trap cleanup EXIT
//   trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
//
//   if ! (umask 077; gpg --no-symkey-cache --decrypt --output "$key" "$root_gpg"); then
//     echo "gpg failed: nothing was signed" >&2
//     exit 1
//   fi
//   node tools/sign-update-manifest.mjs --root-key "$key" ...     # or --renew ...
//   node tools/sign-update-manifest.mjs --verify manifest.json
//
// **Decrypt to a FILE, and check gpg's exit status BEFORE the signer runs.** Never hand this script
// a named FIFO (`mkfifo`, then `gpg … > fifo &`): if gpg fails, with a wrong passphrase or a
// pinentry that timed out, nobody ever opens the FIFO for writing, and `readFileSync` below blocks
// in open() forever with silence as the only symptom. That happened on 2026-09-11. Process
// substitution (`--root-key <(gpg …)`) does not hang, but it runs the signer without anybody having
// looked at gpg's status either.
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
// unchanged and refuses a bad file, which means a compromised API can withhold an
// update but can never ship one.
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
// **The key is proved to be a published root before anything is written.** The
// happy path of a mistake — the reserve key by accident, a key from a test
// directory, last year's key — writes a document that verifies against itself and
// against no shipped daemon, and you would find out from a user who never got an
// update. Borrowed wholesale from `sign-trust.mjs`, for the reason its own
// comment gives.
//
// **The size and digest are computed from the artefact, never accepted as
// arguments.** A manifest naming a file that is not there is August's webhook
// failure with a different noun: every delivery fails, nothing notices. If the
// installer is not on this machine, put it on this machine. (`--renew` is the one
// exception, and it takes them from a document a published root already signed,
// never from an argument; see below.)
//
// **The filename must be in the closed set the client already accepts.** It
// becomes a URL component and a path on disk over there, so `..`, a separator or
// a `%00` is a write outside the intended directory. The client widens that set
// BEFORE this publishes a new shape, never after.
//
// **Release notes are refused if they carry markup or a link, if they are empty, or
// if there is no English.** The client renders them as plain text and the server
// refuses them too; a refusal on three ends is a property rather than an agreement.
// The rule is `notesProblems` below, and it is written once: signing applies it,
// and so does `--check-notes`, which is what release.sh's preflight runs.
//
// **The signature is verified against the published roots before the file is
// written.** Signing and then not checking is how you find out from a user.
//
// **What it does NOT check: that clients can download the artefact.** Nothing on
// the API server checks that either; it serves this document and checks nothing
// about the file the document names. See the closing message.
//
// ── renewing: --renew, and why it needs no artefact ─────────────────────────
//
// `--renew <prev.json>` re-signs a document a release already published, with a
// fresh signedAt and expires and nothing else changed. It is what `release.sh
// --resign` calls, and it is why an expiry no longer means carrying the 88 MB
// installer back to the desk.
//
//   · The previous document must verify against registry/v1/root.json, exactly as
//     --verify checks it. Its size and digest were computed from the bytes when a
//     published root signed them, so carrying them over repeats a checked claim.
//   · `latest` is carried byte for byte (the same artefacts, notes and releasedAt),
//     and so is every other member except the two dates.
//   · The carried claims are checked against today's rules (the filename set, the
//     platforms, the notes), because a renewal publishes them again.
//   · The new signedAt must be STRICTLY later than the previous one. A client that
//     was offered an update keeps that document's signedAt as a floor and refuses
//     anything signed before it as a rollback; and two documents with one signedAt
//     and different contents cannot be ordered by anybody, which is why the box
//     requires strictly later too. The field has seconds precision, so a renewal in
//     the same second as its input is refused.
//
// It knows only the document it was given, not what the server serves now. Give it
// the live document: the record in releases/<v>/manifest.json is committed for that.
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

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const ROOT_JSON = path.join(REPO, "registry", "v1", "root.json");

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

/** The locales a manifest carries notes in. English is required; the rest fall back to it. */
export const NOTE_LOCALES = ["en", "ru", "uk"];

/** Anything the client would not render as plain text: a tag, a Markdown link, a URL. */
const MARKUP = /[<>]|\]\(|https?:\/\//;

/**
 * The artefact names the shipped client accepts. Widen THERE first, then here.
 *
 * `Astra-Installer-<semver>.exe` is the OUTER Slint launcher — the file a person downloads and
 * runs. The inner Inno setup is called `Astra-Setup-<semver>.exe`, is embedded in the launcher and
 * unpacked to %TEMP% for the seconds an install takes, and can never be on a CDN. This regex named
 * the inner one until 2026-09-02; it matched a file that does not exist.
 *
 * Windows only, by the owner's decision: a closed set should name what is actually published, and
 * today that is one file. The Linux shapes are in the contract for the day they ship.
 */
const FILENAME = /^Astra-Installer-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\.exe$/;

const PLATFORMS = new Set(["windows-x64"]);

/** The flags that describe WHAT is offered. `--renew` carries all of that over, so it refuses them. */
const CONTENT_FLAGS = [
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

function die(message) {
  console.error(`sign-update-manifest: ${message}`);
  process.exit(1);
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function has(name) {
  return process.argv.includes(name);
}

/** Every argument after `name` up to the next flag. */
function argList(name) {
  const i = process.argv.indexOf(name);
  if (i === -1) return [];
  const out = [];
  for (let j = i + 1; j < process.argv.length && !process.argv[j].startsWith("--"); j++) {
    out.push(process.argv[j]);
  }
  return out;
}

/**
 * The notes rule, and the only copy of it: signing applies it, `--check-notes` applies it, and
 * `--renew` applies it to the notes it carries over.
 *
 * Refused: a locale the manifest does not carry, the same locale twice, notes that are empty after
 * trimming, notes with markup or a link, and a set with no English. The client renders notes as
 * PLAIN TEXT and the server refuses markup as well, so anything refused here would otherwise be
 * published and then refused by both.
 *
 * @param {{locale: string, where: string, text: string}[]} entries the raw text of each file
 * @returns {{notes: Record<string, string>, problems: string[]}} the trimmed notes that passed,
 *   and one sentence per problem; the set is acceptable only when `problems` is empty
 */
export function notesProblems(entries) {
  const notes = {};
  const problems = [];
  const seen = new Set();
  for (const { locale, where, text: raw } of entries) {
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
        `${where}: the ${locale} notes carry markup or a link. The client renders notes as PLAIN ` +
          "TEXT and the server refuses them as well, so this would be published and then refused by both.",
      );
      continue;
    }
    notes[locale] = text;
  }
  if (!entries.some((e) => e.locale === "en")) {
    problems.push(
      "there are no English notes, and they are required: a locale nobody wrote falls back to " +
        "English, so English must exist",
    );
  }
  return { notes, problems };
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
 * Load a root private key and prove it is one of the published roots.
 *
 * Without this, the happy path of a mistake writes a document that verifies
 * against itself and against nothing that ships.
 */
function loadRoot(pemPath, expectRole) {
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
  if (expectRole && match.role !== expectRole) {
    die(`${pemPath} is the ${match.role} root; --${expectRole.toLowerCase()} was asked for`);
  }
  return { key_id: match.key_id, privateKey, role: match.role };
}

/** The signers named on the command line, each proved to be a published root. */
function signersFromArgs() {
  const keyPath = arg("--root-key");
  if (!keyPath) die("--root-key <path to the decrypted root key> is required");
  const signers = [loadRoot(keyPath, has("--reserve") ? "reserve" : undefined)];
  const also = arg("--also-reserve");
  if (also) signers.push(loadRoot(also, "reserve"));
  return signers;
}

function expiryDays() {
  const days = Number(arg("--expires-days") ?? DEFAULT_EXPIRY_DAYS);
  if (!Number.isFinite(days) || days < 1 || days > MAX_EXPIRY_DAYS) {
    die(`--expires-days ${days} is not a number of days between 1 and ${MAX_EXPIRY_DAYS}`);
  }
  return days;
}

/** Read one notes file into an entry for `notesProblems`, or a problem if it cannot be read. */
function readNoteFile(locale, where) {
  try {
    return { entry: { locale, where, text: fs.readFileSync(where, "utf8") } };
  } catch (e) {
    return { problem: `cannot read the ${locale} notes at ${where}: ${e.message}` };
  }
}

/** Read release notes from the --notes-<locale> flags, and refuse anything the client would not render as text. */
function notes() {
  const entries = [];
  for (const locale of NOTE_LOCALES) {
    const where = arg(`--notes-${locale}`);
    if (where === undefined) continue;
    const read = readNoteFile(locale, where);
    if (read.problem) die(read.problem);
    entries.push(read.entry);
  }
  const { notes: out, problems } = notesProblems(entries);
  if (problems.length) die(problems.join("\n  "));
  return out;
}

/**
 * The claims of one artefact entry, against the rules this signer enforces today: the filename in
 * the client's closed set, its version equal to `version`, a platform the client knows.
 */
function artefactProblems(a, version) {
  const problems = [];
  const m = FILENAME.exec(String(a?.filename));
  if (!m) {
    problems.push(
      `the artefact is named ${a?.filename}, which is outside the set the shipped client accepts. ` +
        "That name becomes a URL component AND a path on disk over there. Rename it to " +
        "Astra-Installer-<semver>.exe, or widen the set in the CLIENT first and ship that before " +
        "publishing a new shape here.",
    );
  } else if (m[1] !== version) {
    problems.push(`version ${version} disagrees with the filename's ${m[1]}: one of them is wrong`);
  }
  if (!PLATFORMS.has(a?.platform)) {
    problems.push(`platform ${a?.platform} is not one the client knows (${[...PLATFORMS].join(", ")})`);
  }
  return problems;
}

/** Size and digest, from the bytes themselves. Never from an argument. */
function artefact() {
  const where = arg("--artifact");
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
  const m = FILENAME.exec(filename);
  const version = arg("--version") ?? m?.[1];
  const art = {
    platform: arg("--platform") ?? "windows-x64",
    kind: arg("--kind") ?? "installer",
    filename,
    sizeBytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    version,
  };
  const problems = artefactProblems(art, version);
  if (problems.length) die(problems.join("\n  "));
  return art;
}

/**
 * Read a manifest and verify it against the published roots. Dies on anything --verify refuses;
 * `--verify` and `--renew` both come through here, so they cannot disagree about what verifies.
 */
function verifiedDocument(where) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(where, "utf8"));
  } catch (e) {
    die(`cannot read ${where}: ${e.message}`);
  }
  const result = verifyEnvelope(doc, UPDATE_SCHEMA, publishedRoots());
  if (!result.ok) {
    die(`${where} does not verify: ${result.reason} (offered: ${result.offered.join(", ") || "none"})`);
  }
  const signed = doc.signed ?? {};
  if (signed.schema !== UPDATE_SCHEMA) {
    die(
      `${where} verifies but declares schema ${JSON.stringify(signed.schema)}. A body of one ` +
        "version signed under another's domain VERIFIES, because the domain is not read from the " +
        "file — which is exactly why this is checked separately.",
    );
  }
  return { doc, key_id: result.key_id };
}

function verifyFile(where) {
  const { doc, key_id } = verifiedDocument(where);
  const signed = doc.signed;
  const left = (new Date(signed.expires) - Date.now()) / 86400000;
  console.log(`ok  ${where}`);
  console.log(`    signed by      ${key_id}`);
  console.log(`    version        ${signed.latest?.version}`);
  console.log(`    expires        ${signed.expires}  (${left.toFixed(1)} days left)`);
  for (const a of signed.latest?.artifacts ?? []) {
    console.log(`    ${a.platform}  ${a.filename}  ${a.sizeBytes} bytes  ${a.sha256.slice(0, 16)}…`);
  }
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

/** The truth about what a signature here does and does not establish. */
function printWhatWasNotChecked() {
  console.log("What it did NOT check: that clients can download that file. Nothing on the API server");
  console.log("checks it either; the server serves this document and checks nothing about the artefact");
  console.log("it names. Reachability is checked by publish-release.sh on the box (minice), whose --stage");
  console.log("step fetches the file through the origin and compares its sha256 with the one above before");
  console.log("it installs this document, and by the consuming probe after the flip. Installing by hand?");
  console.log("Then fetch the file through the CDN and hash the body yourself first.");
}

function renew(prevPath) {
  const stray = CONTENT_FLAGS.filter(has);
  if (stray.length) {
    die(
      `--renew carries every claim of the previous document unchanged, so ${stray.join(", ")} ` +
        "would be ignored, and an ignored flag is refused rather than obeyed in silence. To " +
        "change what is offered, sign afresh with --artifact.",
    );
  }
  const out = arg("--out") ?? "manifest.json";

  // Exactly what --verify checks, through the same function.
  const { doc: prev } = verifiedDocument(prevPath);
  const latest = prev.signed.latest ?? {};
  const artifacts = Array.isArray(latest.artifacts) ? latest.artifacts : [];
  if (!artifacts.length) die(`${prevPath} offers no artefact; there is nothing to renew`);
  const problems = artifacts.flatMap((a) => artefactProblems(a, latest.version));
  const carried = Object.entries(latest.notes ?? {}).map(([locale, text]) => ({
    locale,
    where: `${prevPath} latest.notes.${locale}`,
    text: String(text),
  }));
  problems.push(...notesProblems(carried).problems);
  if (problems.length) {
    die(
      `${prevPath} verifies, but a renewal would publish claims today's rules refuse:\n  ` +
        problems.join("\n  "),
    );
  }

  const days = expiryDays();
  let signed;
  try {
    signed = renewSigned(prev.signed, new Date(), days);
  } catch (e) {
    die(e.message);
  }

  const signers = signersFromArgs();
  const doc = signEnvelope({ domain: UPDATE_SCHEMA, signed, signers });
  const check = verifyEnvelope(doc, UPDATE_SCHEMA, publishedRoots());
  if (!check.ok) {
    die(`the document this just signed does not verify: ${check.reason} — nothing written`);
  }

  fs.writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`renewed ${prevPath} -> ${out}`);
  console.log(`  signed by      ${signers.map((s) => `${s.key_id} (${s.role})`).join(" + ")}`);
  console.log(`  version        ${latest.version}  (latest carried over unchanged)`);
  for (const a of artifacts) {
    console.log(`  artefact       ${a.platform}  ${a.filename}  ${a.sizeBytes} bytes`);
    console.log(`  sha256         ${a.sha256}`);
  }
  console.log(`  signedAt       ${prev.signed.signedAt} -> ${signed.signedAt}`);
  console.log(`  expires        ${signed.expires}  (${days} days)`);
  console.log("");
  console.log(`What this checked: ${prevPath} verifies against registry/v1/root.json; everything in it`);
  console.log("but signedAt and expires was carried over unchanged and passes today's filename, platform");
  console.log("and notes rules; the new signedAt is strictly later; the new signature verifies against");
  console.log("the same roots. The artefact was NOT re-hashed: its size and sha256 are the previous");
  console.log("document's, which a published root already signed.");
  printWhatWasNotChecked();
}

function main() {
  const modes = ["--verify", "--renew", "--check-notes"].filter(has);
  if (modes.length > 1) die(`${modes.join(" and ")} are separate modes; give one`);

  if (has("--check-notes")) return checkNotes(argList("--check-notes"));

  if (has("--verify")) {
    const verify = arg("--verify");
    if (!verify || verify.startsWith("--")) die("--verify needs the path of a manifest");
    return verifyFile(verify);
  }

  if (has("--renew")) {
    const prev = arg("--renew");
    if (!prev || prev.startsWith("--")) die("--renew needs the path of the previous signed manifest");
    return renew(prev);
  }

  const out = arg("--out") ?? "manifest.json";
  const signers = signersFromArgs();
  const art = artefact();
  const days = expiryDays();
  const now = new Date();

  const signed = {
    schema: UPDATE_SCHEMA,
    channel: arg("--channel") ?? "stable",
    signedAt: rfc3339(now),
    expires: rfc3339(addDays(now, days)),
    min_supported_version: arg("--min-supported") ?? art.version,
    latest: {
      version: art.version,
      releasedAt: arg("--released-at") ?? rfc3339(now),
      placeholder: false,
      notes: notes(),
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
  const check = verifyEnvelope(doc, UPDATE_SCHEMA, publishedRoots());
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
  console.log("What this checked: the key is a published root; the size and sha256 above were computed");
  console.log("from the file on this machine; its name is in the set the client accepts; the notes are");
  console.log("plain text with English present; the signature verifies against registry/v1/root.json.");
  printWhatWasNotChecked();
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
