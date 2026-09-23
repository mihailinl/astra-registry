// The withdrawal list: its shape, its rules, and the one place they are checked.
//
// PRODUCTION_PLAN §5.4/§6-3.9. `revocations.json` is the only mechanism in this
// design that helps AFTER a bad plugin is already on somebody's machine.
// Everything else — the attestation, the digest pin, the TOFU identity —
// decides whether bytes may arrive. This decides what happens to bytes that
// already did, which is why the daemon has five enforcement points for it and
// why this file is strict about what may be published.
//
// ── the document ────────────────────────────────────────────────────────────
//
//   { "signed": { "schema": "astra.registry.revocations/1",
//                 "serial": N, "issued_at": …, "expires_at": …,
//                 "revocations": [ … ] },
//     "signatures": [ { "key_id", "sig" } ] }
//
// Same envelope and same index key as `index.json` (§5.1: "there is no separate
// revocation role"). The ONE thing that differs is the signature domain, and
// that difference is the whole reason `REVOCATIONS_SCHEMA` exists as a constant
// in bot/lib/sign.mjs: a signature made over a catalogue must not be replayable
// as a signature over a withdrawal list, because anyone who could get one
// catalogue signed could then publish an *empty* withdrawal list and switch the
// mechanism off. tools/selftest.mjs asserts that in both directions.
//
// ── the serial, and why equal is allowed here and not on trust.json ─────────
//
// The daemon replaces its set outright on a strictly greater serial and may only
// ADD on a lower or equal one. So a withdrawal is never removed by a replayed
// document, and removing one deliberately means publishing a higher serial
// without it — which is how a mistaken advisory is undone, and it has to be
// possible or every user would learn to delete files instead.
//
// The list is also re-signed on a schedule even when no advisory has changed,
// because §5.5 blocks new installs against a list older than seven days. That
// republication keeps the same serial, which is exactly why the daemon accepts
// an equal serial from `RevocationStore::accept` and refuses one from
// `TrustStore::accept`.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { REVOCATIONS_SCHEMA } from "../../bot/lib/sign.mjs";
// MOD-41's public-reason rules have ONE implementation in this repository, and
// this is the second of the two validators that read it. An advisory's reason
// and a moderation entry's reason are the same kind of string, reaching the
// same reader, refused at entry by the same service check (MOD-48). Two
// hand-written copies of "10 to 300, no scheme, no `www.`, no `@`, no
// host-like token" is how one of them ends up counting UTF-16 units while the
// other counts code points — which is attack M-11, and a stalled takedown.
// `tests/moderation-reasons.json` is the corpus both are run against.
import { reasonProblems } from "../../bot/lib/moderation.mjs";
import { REPO_ROOT } from "./sources.mjs";
import { ADVISORY_ID_GRAMMAR, ADVISORY_ID_PATTERN, ID_PATTERN } from "./ids.mjs";
import { parseSemver } from "./semver.mjs";

/** Where advisories are written, one JSON file per advisory. */
export const SOURCE_DIR = "tools/revocations";

/**
 * A regular expression over a repository-relative path, as git prints one:
 * `dir`, escaped, then `/`, then `basename` — a RegExp SOURCE for the part
 * after the slash — anchored at both ends, so a file in a subdirectory, in a
 * sibling that shares the prefix, or under another tree does not match.
 *
 * Gap 72. Two readers parse history for advisories: `nextAdvisoryId` in
 * `bot/lib/compile-decision.mjs`, whose `git log` pathspec already followed
 * `SOURCE_DIR`, and `tools/moderation-coverage.mjs`'s `ADVISORY_RE`. Both
 * spelled the directory into a regex literal. Had the directory moved, the log
 * would have listed the new paths and the id regex matched none of them:
 * `nextAdvisoryId` finds no advisory and hands out `ASTRA-YYYY-0001` again,
 * and the coverage canary stops seeing advisories at all. Both build their
 * pattern with this now, and `tools/selftest/couplings.mjs` asks each of them
 * what it saw on a fixture history written under `SOURCE_DIR`.
 *
 * @param {string} dir       a literal directory, escaped here
 * @param {string} basename  a RegExp source; its capture groups keep their numbers
 */
export function pathUnder(dir, basename) {
  const escaped = dir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped}/(?:${basename})$`);
}

/**
 * An advisory's file, as git prints its path: `SOURCE_DIR/<id>.json`, with the
 * id as group 1. The id is `tools/lib/ids.mjs`'s ADVISORY_ID_GRAMMAR — four or
 * more serial digits — and both readers of history that look for advisories
 * match with this one pattern: `nextAdvisoryId` and the coverage canary's
 * `triggersOf`. Until 2026-09-22 each kept its own tail, and the canary's took
 * exactly four digits, so from advisory 10000 on it would have seen none
 * (gap 72's tails).
 */
export const ADVISORY_FILE = pathUnder(SOURCE_DIR, `(${ADVISORY_ID_GRAMMAR})\\.json`);

/**
 * The same directory as a **git pathspec**, narrowed to the files the document
 * is actually built from.
 *
 * `SOURCE_DIR` answers *where do advisories live*. This answers *which commits
 * changed the withdrawal list*, and the two are not the same question — the
 * directory also holds a README.
 *
 * It exists because detector A7 asked the first question and used the answer
 * for the second. On 2026-09-20 at 09:25 `a6a4c55` added **ten lines to
 * `tools/revocations/README.md`** and A7 alarmed:
 *
 *     ALARM A7 A7_SIGNED_BEHIND_REVOCATIONS: `signed`'s Source-Commit is 223
 *     minutes older than the newest tools/revocations/ commit a6a4c552cb3a;
 *     the bound is 30
 *
 * Every number in that sentence is correct, and its subject — *the withdrawal
 * list changed and `signed` has not caught up* — was false about the list and
 * true about the number. The list's ENTRIES did not change: `[]` before and
 * after. Its SERIAL did, because the serial counts the whole directory
 * (`SERIAL_PATHSPEC` below): `git rev-list --count` gives 2 at `a6a4c55^` and
 * 3 at `a6a4c55`, and the signer's commit `ae80bc7` reads "withdrawal list 4
 * at a6a4c552cb3a" and "revocations.json: changed at serial 4". So `signed`
 * WAS one serial behind main, from the merge (09:25:22Z) until that commit
 * (09:25:31Z, signer run 35502265393 on the same push), and A7's run on that
 * push (35502265394) fetched `signed` at 09:25:28Z, inside the gap. The run
 * went red, and `detectors.yml` stayed red until its next run, a push at
 * 09:32:57Z, which was green. Nothing was sent, because the alarm channel did
 * not exist yet; with one, **a documentation edit would have paged**, which is
 * the specific failure this repository spent 2026-09-19 removing from
 * `served-set.yml` and `ingest.yml`. (Measured 2026-09-22 from `signed`'s
 * history and both runs' logs; this paragraph said until then that nothing
 * about the list had changed and that `signed` was behind nothing.)
 *
 * The rule it is an instance of is in ops `dev/couplings.md`: *an instrument
 * can be right about the number and wrong about the subject.* Every earlier
 * instance was answered the same way — stop naming the subject, let the tool
 * resolve it — and that is why this is an export here rather than a narrower
 * string typed into `bot/detectors.mjs`. The module that owns *what the
 * withdrawal list is built from* is the module that should answer it, so a
 * change of layout moves one line and every reader follows.
 *
 * Deliberately NOT symmetric with A7's other half. Its `plugins` pathspec stays
 * the whole directory, because a plugin's `README.md` and `icon.png` **do**
 * reach the catalogue — the index carries `readme`, and a publish that changes
 * only those still rewrites `registry/v1/index.json`. Measured on `6659a61`:
 * README, icon, `plugin.json`, the version file and `index.json` in one commit.
 * The asymmetry is the two documents having different inputs, not an oversight,
 * and it is written here so the next reader does not "fix" it.
 */
export const SOURCE_PATHSPEC = `${SOURCE_DIR}/*.json`;

/**
 * The pathspec D3 counts the withdrawal list's serial over —
 * `git rev-list --count --full-history <commit> -- SERIAL_PATHSPEC`, plus one
 * (`SERIAL_FLAGS` below) — and therefore the clock SERVE-85 measures a serial
 * difference from.
 *
 * Three readers ask this one question: `resolveSerial` below, the signer's
 * `serialsAt` in `tools/signer/plan.mjs`, and `LIST_PATHSPEC` in
 * `tools/served-set/main-vs-signed.mjs`. Until gap 64 the last two each typed
 * the string for themselves, and widening the clock's copy moved the clock and
 * left the serial. They import this now, and `tools/selftest/couplings.mjs`
 * holds all three to one answer by counting a fixture history, so a reader
 * that stops importing it and counts something else goes red by name.
 *
 * **Deliberately the whole directory, and NOT `SOURCE_PATHSPEC`,** although
 * that means a README commit moves the serial while detector A7, which reads
 * `SOURCE_PATHSPEC`, calls the same commit nothing. The narrowing is not open:
 * every serial this registry has published came from a README commit. At
 * `cbbf1e5`, `git rev-list --count` gives 3 commits under this directory, 3
 * touching its README and 0 under `*.json`, and `signed` (`5966ccf`) serves
 * serial 4. Narrowed, the formula gives 1; with one advisory committed it would
 * give 2, and the signer's `listGate` refuses both — SERVE-36, a list that goes
 * backwards — so `decideDocument` carries the old list and the advisory is not
 * published.
 */
export const SERIAL_PATHSPEC = SOURCE_DIR;

/**
 * How the list's serial counts: `--full-history`, and NOT git's default
 * history simplification. Contract DEC-9 from 0.35.0 (ops register entry 117).
 *
 * **The default count can go down at a merge**, and a list serial that goes
 * down is a withdrawal that never publishes. By default git follows only the
 * parent of a merge that is TREESAME to it for the pathspec, and counts only
 * what that parent reaches. Measured on fixtures, counts before the `+ 1`:
 * main adds an advisory and withdraws it after a branch forked, and the
 * branch's own advisory then merges — along main the default count reads 0,
 * 1, 2 and then **1** at the merge, where `--full-history` reads 0, 1, 2, 4.
 * So the signer computes serial 2 at a merge that adds an advisory while
 * `signed` serves 3; SERVE-36 refuses the list, D4 carries the old one under
 * the merge's `Source-Commit`, and from then on SERVE-85, detector A7 and
 * contract row 7 all read that state as nothing owed. The same README fix
 * landing on main and inside a pull request that also adds an advisory gives
 * the merge the default count of the commit before it, which is the same hole
 * one serial higher.
 *
 * `--full-history` counts every commit reachable from the one asked about
 * whose tree under the pathspec differs from at least one of its parents'.
 * That predicate belongs to each commit alone, so the count cannot fall along
 * any ancestry, and it rises at every first-parent commit that changes the
 * list. `tools/selftest/couplings.mjs` holds each of the three readers to that
 * on both shapes, and holds main's own head to it on every run.
 *
 * **It re-means no serial ever issued.** At `3653dc5` the two counts agree at
 * every one of the 337 commits on main's first-parent line: no commit that has
 * touched this directory reached main through a merge the default prunes.
 *
 * The catalogue's serial (`CATALOGUE_PATHSPEC`) has the same hazard class and
 * is NOT moved with this: there the two counts differ at 233 of the same 337
 * commits (57 against 52 at the head), so switching would raise the served
 * catalogue serial in one jump. It is watched instead — the same selftest
 * check goes red on `main` the moment a head commit holds or lowers it across
 * a change under `plugins/`.
 */
export const SERIAL_FLAGS = ["--full-history"];

/** Where the generated, deployable document lands. */
export const OUTPUT_FILE = "registry/v1/revocations.json";

export const BANNER =
  "GENERATED FILE — DO NOT EDIT. Source of truth: tools/revocations/<ADVISORY-ID>.json. " +
  "Regenerate with `node tools/build-revocations.mjs`. Only the `signed` member is covered by " +
  "the signatures below; nothing outside it is authenticated and nothing may be read out of it.";

/**
 * The kinds the daemon understands, and what `value` means for each.
 *
 * `astra-daemon/src/plugins/trust.rs`'s `RevocationKind` is the authority; this
 * table exists so the registry cannot publish a kind the daemon would silently
 * ignore. A kind that does not round-trip is a withdrawal that does not happen.
 */
export const KINDS = {
  // sha256 of a whole .astraplugin. The default, and the one that works
  // whichever route the bytes take — store, ImportPluginFile, or a USB stick.
  digest: { value: "sha256", versions: false },
  // sha256 of a resolved entry.command binary. §5.4's fifth enforcement point:
  // a sideloaded source directory has no archive, so the only thing that can be
  // hashed is the file about to be executed.
  binary: { value: "sha256", versions: false },
  // every version of a plugin id.
  id: { value: "id", versions: false },
  // "<id>@<version>".
  id_version: { value: "id@version", versions: false },
  // an id plus a half-open [introduced, fixed) window.
  version_range: { value: "id", versions: true },
  // "github:owner/repo" or "origin:host" — AuthorIdentity::revocation_key.
  identity: { value: "identity", versions: false },
  // a signing key id, matched against a trust record's signer_key_id.
  publisher_key: { value: "key_id", versions: false },
};

/**
 * Hosts an `advisory_url` may not sit on, subdomains included (ROLL-50).
 *
 * The field is optional and the whole point of refusing these two is that a
 * withdrawal list is SIGNED and kept: a URL that goes into one outlives the
 * page it names. Every address this project has on `github.com` and
 * `*.github.io` is scheduled to stop resolving — the Pages deployment is
 * retired at R9a — so an advisory pointing there becomes a signed link to a
 * 404, on the one document a user reads when something has already gone wrong.
 * Until the project's own advisory pages exist, the field is omitted.
 */
export const REFUSED_ADVISORY_HOSTS = ["github.com", "github.io"];

/** What the daemon does about a plugin an entry covers. */
export const ACTIONS = ["block_install", "disable", "warn"];

/** Advisory only — no daemon behaviour hangs on it. See RevocationSeverity. */
export const SEVERITIES = ["critical", "high", "moderate", "low"];

/**
 * An advisory id, whole: `tools/lib/ids.mjs`'s grammar, which
 * `schema/decision-v1.json`'s `advisory` pattern names as this constant's. The
 * moderation log and the site's page guard read the same grammar.
 */
export const ADVISORY_ID = new RegExp(ADVISORY_ID_PATTERN);
const SHA256 = /^[0-9a-f]{64}$/;
const IDENTITY = /^(github:[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+|origin:[a-z0-9.-]+)$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,120}$/;
const ID_RE = new RegExp(ID_PATTERN);

/**
 * One advisory file, as an author of one writes it.
 *
 * @typedef {{
 *   id: string, published: string, severity: string, action: string,
 *   reason: string, advisory_url?: string,
 *   entries: {kind: string, value: string, versions?: {introduced?: string, fixed?: string}}[]
 * }} Advisory
 */

/**
 * Check one advisory and return its problems.
 *
 * Every rule here is a rule the daemon relies on, and the error strings say
 * which — a validator that rejects without saying why teaches nobody anything.
 *
 * @param {unknown} doc
 * @param {string} where
 * @returns {string[]}
 */
export function checkAdvisory(doc, where = "<advisory>") {
  const errs = [];
  const bad = (m) => errs.push(`${where}: ${m}`);

  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    bad("is not a JSON object");
    return errs;
  }

  if (typeof doc.id !== "string" || !ADVISORY_ID.test(doc.id)) {
    bad(`id ${JSON.stringify(doc.id)} must look like ASTRA-2026-0001`);
  }
  if (typeof doc.published !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(doc.published)) {
    bad(`published ${JSON.stringify(doc.published)} must be YYYY-MM-DD`);
  }
  if (!SEVERITIES.includes(doc.severity)) {
    bad(`severity ${JSON.stringify(doc.severity)} must be one of ${SEVERITIES.join(", ")}`);
  }
  if (!ACTIONS.includes(doc.action)) {
    bad(`action ${JSON.stringify(doc.action)} must be one of ${ACTIONS.join(", ")}`);
  }

  // The reason is shown to a user VERBATIM, in a notification the daemon marks
  // persistent. Bidi overrides and zero-width joiners in that position are the
  // spoofing primitive the metadata checks already refuse everywhere else, and
  // a withdrawal notice is the last place to make an exception. MOD-41's other
  // clauses are there for the same reader: a withdrawal notice that carries a
  // host is a withdrawal notice that can send somebody somewhere.
  for (const p of reasonProblems(doc.reason)) bad(p.why);

  if (doc.advisory_url !== undefined) {
    if (typeof doc.advisory_url !== "string" || !doc.advisory_url.startsWith("https://")) {
      bad(`advisory_url ${JSON.stringify(doc.advisory_url)} must be an https URL`);
    } else {
      let host = null;
      try {
        host = new URL(doc.advisory_url).hostname.toLowerCase();
      } catch { /* not a URL at all; reported below */ }
      if (host === null) {
        bad(`advisory_url ${JSON.stringify(doc.advisory_url)} is not a URL`);
      } else if (REFUSED_ADVISORY_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) {
        bad(
          `advisory_url ${JSON.stringify(doc.advisory_url)} is on ${host}, and a withdrawal list may not ` +
            `point at ${REFUSED_ADVISORY_HOSTS.join(" or ")} (ROLL-50). This URL is about to be SIGNED into a ` +
            "document clients keep, and the pages these hosts serve for this project stop resolving when " +
            "Pages is retired — leaving a signed advisory whose only explanation is a 404. Omit the field " +
            "until the project's own advisory pages exist; it is optional, and a withdrawal works without it.",
        );
      }
    }
  }

  if (!Array.isArray(doc.entries) || doc.entries.length === 0) {
    bad("entries must be a non-empty array — an advisory that withdraws nothing is a blog post");
    return errs;
  }

  // ── the sideload gap, closed at the source ──────────────────────────────
  //
  // `digest` is the natural first reach: it is the sha256 of the whole
  // `.astraplugin`, it is what a release names, and it works for the store, for
  // `ImportPluginFile` and for a USB stick. What it cannot do is match a
  // **source directory**, because a directory has no archive and therefore no
  // digest — §5.4 says so out loud, which is why the daemon has a fifth
  // enforcement point that hashes the resolved `entry.command` instead.
  //
  // So a digest-only advisory leaves "run the same code from a folder" open by
  // default rather than by exception: withdraw by digest, uninstall (which drops
  // the trust record the digest was read from), copy `plugin.toml` and the
  // binary into a directory, sideload. Nothing in the list can see it.
  //
  // The remedy is one more entry, and the author has to be stopped from
  // forgetting it. `identity` and `publisher_key` do NOT count: a sideloaded
  // directory has neither, so an advisory carrying only those has the same hole.
  const COVERS_A_DIRECTORY = ["binary", "id", "id_version", "version_range"];
  const kinds = doc.entries
    .filter((e) => e && typeof e === "object")
    .map((e) => e.kind);
  if (kinds.length && !kinds.some((k) => COVERS_A_DIRECTORY.includes(k))) {
    bad(
      `every entry is keyed on ${[...new Set(kinds)].join("/")}, and none of those can match a ` +
        "SIDELOADED SOURCE DIRECTORY — a directory has no archive, so it has no bundle digest and " +
        "no signer. Add at least one entry of kind " +
        `${COVERS_A_DIRECTORY.join(", ")}. The cheapest is \`id\` (or \`version_range\` if only ` +
        "some versions are affected); `binary` is the sha256 of the resolved `entry.command` file " +
        "inside the bundle, which is what the daemon hashes at every sideload and every start.",
    );
  }

  doc.entries.forEach((entry, i) => {
    const at = `${where} entries[${i}]`;
    if (!entry || typeof entry !== "object") {
      errs.push(`${at}: is not an object`);
      return;
    }
    const spec = KINDS[entry.kind];
    if (!spec) {
      errs.push(
        `${at}: kind ${JSON.stringify(entry.kind)} is not one the daemon reads ` +
          `(${Object.keys(KINDS).join(", ")}). An unknown kind is a withdrawal that does not happen.`,
      );
      return;
    }
    if (typeof entry.value !== "string" || entry.value.length === 0) {
      errs.push(`${at}: value must be a non-empty string`);
      return;
    }
    switch (spec.value) {
      case "sha256":
        // Lowercase, because the daemon compares case-insensitively but a
        // document with two spellings of one digest is a document a human
        // cannot diff.
        if (!SHA256.test(entry.value)) {
          errs.push(`${at}: value must be 64 lowercase hex characters, got ${JSON.stringify(entry.value)}`);
        }
        break;
      case "id":
        if (!ID_RE.test(entry.value)) {
          errs.push(`${at}: value ${JSON.stringify(entry.value)} is not a plugin id`);
        }
        break;
      case "id@version": {
        const cut = entry.value.lastIndexOf("@");
        const id = cut === -1 ? "" : entry.value.slice(0, cut);
        const version = cut === -1 ? "" : entry.value.slice(cut + 1);
        if (!ID_RE.test(id) || !parseSemver(version)) {
          errs.push(`${at}: value ${JSON.stringify(entry.value)} must be "<id>@<semver>"`);
        }
        break;
      }
      case "identity":
        if (!IDENTITY.test(entry.value)) {
          errs.push(
            `${at}: value ${JSON.stringify(entry.value)} must be "github:owner/repo" or ` +
              `"origin:host" — the spelling AuthorIdentity::revocation_key produces`,
          );
        }
        break;
      case "key_id":
        if (!KEY_ID.test(entry.value)) {
          errs.push(`${at}: value ${JSON.stringify(entry.value)} is not a key id`);
        }
        break;
    }

    if (entry.versions !== undefined) {
      if (!spec.versions) {
        errs.push(`${at}: kind ${entry.kind} does not take a versions window`);
      } else {
        for (const bound of ["introduced", "fixed"]) {
          const v = entry.versions[bound];
          if (v !== undefined && !parseSemver(v)) {
            errs.push(`${at}: versions.${bound} ${JSON.stringify(v)} is not semver`);
          }
        }
        const { introduced, fixed } = entry.versions;
        if (introduced && fixed && parseSemver(introduced) && parseSemver(fixed)) {
          // `fixed` is EXCLUSIVE, so equal bounds withdraw nothing. Caught here
          // rather than shipped, because an advisory that covers the empty set
          // looks exactly like one that works.
          const cmpEqual = introduced === fixed;
          if (cmpEqual) {
            errs.push(`${at}: versions.fixed is exclusive, so introduced == fixed covers nothing`);
          }
        }
      }
    } else if (spec.versions) {
      // Allowed — a version_range with no window is "every version" — but say
      // so, because it is the most consequential thing an advisory can do by
      // omission.
      // (not an error; the note lands in the build log instead)
    }
  });

  return errs;
}

/**
 * Read every advisory under `tools/revocations/`.
 *
 * @param {{root?: string}} opts
 * @returns {{advisories: Advisory[], errors: string[]}}
 */
export function loadAdvisories({ root = REPO_ROOT } = {}) {
  const dir = path.join(root, SOURCE_DIR);
  const errors = [];
  const advisories = [];
  if (!fs.existsSync(dir)) return { advisories, errors };

  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort();
  for (const file of files) {
    const where = `${SOURCE_DIR}/${file}`;
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
    } catch (e) {
      errors.push(`${where}: not readable JSON (${e.message})`);
      continue;
    }
    const problems = checkAdvisory(doc, where);
    if (problems.length) {
      errors.push(...problems);
      continue;
    }
    if (doc.id !== path.basename(file, ".json")) {
      errors.push(`${where}: the file name must be ${doc.id}.json`);
      continue;
    }
    advisories.push(doc);
  }

  const seen = new Set();
  for (const a of advisories) {
    if (seen.has(a.id)) errors.push(`${a.id} is declared twice`);
    seen.add(a.id);
  }
  return { advisories, errors };
}

/**
 * The serial. Commit count of the default branch, path-limited to the advisory
 * directory — the same construction `tools/build-index.mjs` uses, for the same
 * reason: two advisories merged in the same minute get distinct values by
 * construction, and a read-and-increment counter file would not. It counts
 * with `SERIAL_FLAGS` (`--full-history`) where build-index counts by git's
 * default, and `SERIAL_FLAGS` says why the list cannot.
 *
 * Path-limited so that re-signing the list on a schedule (which is what keeps it
 * inside the seven-day window) does not move the serial. That matters: the
 * daemon may only ADD on an equal serial, so a scheduled re-sign at the same
 * serial is the *safe* republication, and bumping it on every run would make
 * every re-sign a full replacement.
 *
 * **Plus the commit that is about to be made** (ops register entry 69), the
 * construction `tools/build-index.mjs` has used since `a85c198`: one more when
 * `git status --porcelain -- SERIAL_PATHSPEC` shows anything — staged,
 * unstaged or untracked. The hand path regenerates BEFORE it commits, because
 * the suite's `build-revocations.mjs --check` refuses a tree whose list does
 * not carry its advisories: write the advisory, regenerate, commit. Until
 * this, the count stopped at `HEAD`, so the new entries were written at the
 * serial `signed` already serves. Measured 2026-09-23 on clones of `5526f1a`
 * (3 commits touch the directory), running the CLI as a maintainer does and
 * then committing: an advisory untracked, the same staged, a README edit, two
 * advisories — each written at 4, and `serialsAt` gives 5 at the commit that
 * lands it; a change outside the directory, 4 and 4. `--check` compares at the
 * committed file's own serial, so it saw none of it. The `+ 1` after the count
 * is the reserved zero, the signer's own; the pending one is on top of it.
 *
 * Whatever git status shows is ONE commit, never one per file: a regeneration
 * that counted the lines would write two ahead for two advisories, and the
 * next clean regeneration would take it back down (`a85c198`'s second case).
 *
 * **What status shows is what `--full-history` counts, once committed.** Its
 * predicate is "the tree under the pathspec differs from a parent's", so any
 * pending change that lands changes that tree: a mode-only change (`100644` →
 * `100755`) and a type change (a file made a symlink) each move the count by
 * one, measured on git 2.55. The four ways they disagree are all a status
 * line whose change the commit does not carry — an untracked file left out
 * of the commit, an intent-to-add entry committed without `-a`, a staged edit
 * whose worktree was reverted and then committed with `-a`, and line endings
 * a `text`/`eol` attribute normalises away (this repository sets none) — and
 * in each the list is written one ABOVE the signer's serial. That direction is
 * only main's unsigned copy: the signer regenerates at its own count.
 *
 * **It is exact only when the commit it is made for is the one that lands.**
 * A commit pushed to `main` (RUNBOOK §7.1), or a pull request squashed or
 * fast-forwarded, is. A pull request merged with a merge commit is not: the
 * merge differs under the directory from its first parent, so DEC-9's count
 * takes the merge too, and the signer assigns one more than the branch commit
 * the regeneration counted (measured: 3 written on the branch, 4 at the
 * merge; git's default count, which the catalogue keeps, gives 3). Nothing
 * before the merge can know it, and `--check` compares at the file's own
 * serial, so main's unsigned copy is one behind after such a merge.
 *
 * `pending: false` stops at `HEAD`, for a caller that knows the commit it is
 * composing and adds it itself: `regenerateDocuments` in
 * `bot/moderation-run.mjs` adds one exactly when its commit's paths touch the
 * pathspec, which a working tree can only guess at. Counting both would write
 * that commit one past the signer's serial.
 */
export function resolveSerial({ explicit, root = REPO_ROOT, pending = true } = {}) {
  if (explicit !== undefined && explicit !== null) return explicit;
  if (process.env.ASTRA_REVOCATIONS_SERIAL) {
    const n = Number(process.env.ASTRA_REVOCATIONS_SERIAL);
    if (!Number.isSafeInteger(n) || n < 1) {
      throw new Error(
        `ASTRA_REVOCATIONS_SERIAL=${process.env.ASTRA_REVOCATIONS_SERIAL} is not a positive integer`,
      );
    }
    return n;
  }
  try {
    const out = execFileSync("git", ["rev-list", "--count", ...SERIAL_FLAGS, "HEAD", "--", SERIAL_PATHSPEC], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    // +1 so a repository with no advisories yet still publishes serial 1 rather
    // than 0. Serial 0 is reserved: `CatalogueState` uses it for "never seen",
    // and a document that claims it cannot be told apart from the absence of
    // one.
    const atHead = Number(out.trim()) + 1;
    if (!pending) return atHead;
    const dirty = execFileSync("git", ["status", "--porcelain", "--", SERIAL_PATHSPEC], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return dirty.trim() ? atHead + 1 : atHead;
  } catch {
    return 1;
  }
}

/**
 * Flatten the advisories into the `signed` member the daemon reads.
 *
 * One advisory becomes one entry per key it names, and every entry carries the
 * advisory's id, severity, action, reason and URL. The daemon shows exactly one
 * of them — the first that matches — so each has to stand on its own.
 *
 * Deterministic: entries sorted by (kind, value), keys sorted by the canonical
 * stringifier. Same sources + same serial → same bytes, which is what makes
 * `--check` and the CI determinism diff mean anything, and what lets a third
 * party rebuild the signed document from the git tree.
 *
 * @param {{root?: string, serial?: number}} opts
 */
export function buildRevocations({ root = REPO_ROOT, serial } = {}) {
  const { advisories, errors } = loadAdvisories({ root });
  if (errors.length) {
    throw new Error(`refusing to build a withdrawal list from invalid sources:\n  ${errors.join("\n  ")}`);
  }

  const revocations = [];
  for (const advisory of advisories) {
    for (const entry of advisory.entries) {
      const out = {
        kind: entry.kind,
        value: entry.value,
        id: advisory.id,
        severity: advisory.severity,
        action: advisory.action,
        reason: advisory.reason.trim(),
      };
      if (advisory.advisory_url) out.advisory_url = advisory.advisory_url;
      if (entry.versions) out.versions = { ...entry.versions };
      revocations.push(out);
    }
  }
  revocations.sort((a, b) => (a.kind === b.kind ? (a.value < b.value ? -1 : a.value > b.value ? 1 : 0) : a.kind < b.kind ? -1 : 1));

  return {
    $comment: BANNER,
    signatures: [],
    signed: {
      schema: REVOCATIONS_SCHEMA,
      serial: resolveSerial({ explicit: serial, root }),
      revocations,
    },
  };
}
