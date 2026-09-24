// Reads plugins/** into memory. Structure only — no policy, no schema.
// Everything here reports the file it failed on, because "unexpected token }"
// with no path is the reason people stop trusting a tool.

import fs from "node:fs";
import path from "node:path";

import { confusableSkeleton } from "./ids.mjs";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

export function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new Error(`${file}: cannot read (${e.code ?? e.message})`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${file}: not valid JSON — ${e.message}`);
  }
}

/**
 * @param {string} root repo root
 * @returns {{errors: {file: string, message: string}[],
 *            plugins: {dir: string, id: string, file: string, doc: object,
 *                      versions: {file: string, basename: string, doc: object}[]}[]}}
 */
export function loadSources(root = REPO_ROOT) {
  const errors = [];
  const plugins = [];
  const pluginsDir = path.join(root, "plugins");
  if (!fs.existsSync(pluginsDir)) {
    return { errors: [{ file: "plugins/", message: "directory does not exist" }], plugins };
  }

  const dirents = fs.readdirSync(pluginsDir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );

  for (const dirent of dirents) {
    const rel = path.join("plugins", dirent.name);
    if (dirent.isSymbolicLink()) {
      errors.push({ file: rel, message: "is a symlink; plugins/ holds real directories only" });
      continue;
    }
    if (!dirent.isDirectory()) {
      errors.push({ file: rel, message: "is not a directory; plugins/ holds one directory per plugin" });
      continue;
    }

    const manifestFile = path.join(pluginsDir, dirent.name, "plugin.json");
    if (!fs.existsSync(manifestFile)) {
      errors.push({ file: path.join(rel, "plugin.json"), message: "missing" });
      continue;
    }

    let doc;
    try {
      doc = readJson(manifestFile);
    } catch (e) {
      errors.push({ file: path.join(rel, "plugin.json"), message: e.message });
      continue;
    }

    const versions = [];
    const versionsDir = path.join(pluginsDir, dirent.name, "versions");
    if (!fs.existsSync(versionsDir)) {
      errors.push({ file: path.join(rel, "versions/"), message: "missing; a listing with no version has nothing to install" });
    } else {
      const files = fs.readdirSync(versionsDir, { withFileTypes: true }).sort((a, b) =>
        a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
      );
      for (const f of files) {
        const vrel = path.join(rel, "versions", f.name);
        if (!f.isFile()) {
          errors.push({ file: vrel, message: "is not a regular file" });
          continue;
        }
        if (!f.name.endsWith(".json")) {
          errors.push({ file: vrel, message: "is not a .json file" });
          continue;
        }
        try {
          versions.push({
            file: vrel,
            basename: f.name.slice(0, -".json".length),
            doc: readJson(path.join(versionsDir, f.name)),
          });
        } catch (e) {
          errors.push({ file: vrel, message: e.message });
        }
      }
    }

    plugins.push({
      dir: dirent.name,
      id: doc?.id,
      file: path.join(rel, "plugin.json"),
      doc,
      versions,
    });
  }

  return { errors, plugins };
}

/**
 * MIG-20's migration baseline marker (registry plan B-T3.7b).
 *
 * `log/` is the first directory in this repository that holds records the bot
 * writes ABOUT its own decisions rather than about a listing, and this marker is
 * its first file. Four things key on it — B-T3.7's legacy writer, detector A1's
 * ignore set (BOT-75), MIG-28's hold for ids with no baseline, and B-T3.6 step
 * 0's work source — so a marker that is the wrong shape is not a cosmetic
 * problem: it is four mechanisms reading a file they each believe something
 * different about.
 */
export const BASELINE_FILE = path.join("log", "baseline.json");

export const BASELINE_SCHEMA = "astra.registry.baseline/1";

/**
 * The marker, or null when the baseline has not been written.
 *
 * Absence is the ordinary state until R3 and is NOT an error here: this is the
 * loader, and "there is no baseline yet" is a fact the callers act on. What is
 * an error is a file that exists and cannot be read, which is returned as
 * `{file, error}` so the caller reports the path rather than throwing a
 * `SyntaxError` with no location in it.
 *
 * @returns {{file: string, doc?: object, error?: string}|null}
 */
export function loadBaseline(root = REPO_ROOT) {
  const file = path.join(root, BASELINE_FILE);
  if (!fs.existsSync(file)) return null;
  try {
    return { file: BASELINE_FILE, doc: readJson(file) };
  } catch (e) {
    return { file: BASELINE_FILE, error: e.message };
  }
}

/**
 * The population MIG-20's baseline is taken over: every published version that
 * is not a staging entry.
 *
 * One line, in one place, because three readers need the same answer and the
 * one that disagreed would be the one nobody re-read: `tools/validate.mjs`
 * checks the marker's count against it, `bot/baseline.mjs` writes one
 * `migration` record per member, and `bot/detectors.mjs` runs MIG-20's tree
 * check over it. "staging entries and null ids never count" is MIG-20's own
 * sentence; this is the first half of it.
 */
export function nonStagingVersions(plugins) {
  const out = [];
  for (const plugin of plugins) {
    for (const version of plugin.versions ?? []) {
      if (!version.doc || typeof version.doc !== "object") continue;
      if (version.doc.staging === true) continue;
      out.push({ plugin, version });
    }
  }
  return out;
}

export function loadPolicy(root = REPO_ROOT) {
  return {
    limits: readJson(path.join(root, "policy", "limits.json")),
    spdx: readJson(path.join(root, "policy", "spdx-allowlist.json")),
    reserved: readJson(path.join(root, "policy", "reserved-ids.json")),
    listingLanguage: readJson(path.join(root, "policy", "listing-language-exemptions.json")),
  };
}

export function loadSchemas(root = REPO_ROOT) {
  return {
    index: readJson(path.join(root, "schema", "index-v1.json")),
    plugin: readJson(path.join(root, "schema", "plugin-v1.json")),
    version: readJson(path.join(root, "schema", "version-v1.json")),
    publisher: readJson(path.join(root, "schema", "publisher-v1.json")),
    // B-T2.1's three. They are loaded here, beside the four this module has
    // always loaded, for the reason the comment at tools/validate.mjs's `ctx`
    // gives: schemas come from THIS repository and never from the tree under
    // test, so `--registry-dir` cannot supply the rules it is judged by.
    decision: readJson(path.join(root, "schema", "decision-v1.json")),
    identity: readJson(path.join(root, "schema", "identity-v1.json")),
    queue: readJson(path.join(root, "schema", "queue-v1.json")),
    // Contract 0.31.0's. MIG-13's markers are committed by hand with each
    // round's sends (registry plan M-T5.3), and this schema is here for the
    // reason the three above are — tools/validate.mjs
    // judges the marker against a rule taken from THIS repository, never from
    // the tree under test — and that reading is what makes the file a gate
    // input rather than a document, which is TRUST-31's test for its set.
    migrationNotice: readJson(path.join(root, "schema", "migration-notice-v1.json")),
    // Contract 2.4.0's: B.4's alert record, TRUST-31's fourteenth schema,
    // loaded here for the reason the others are.
    alert: readJson(path.join(root, "schema", "alert-v1.json")),
  };
}

// ── B.4's other records: the ones nothing in this repository used to read ────
//
// Four paths, and until B-T2.1 this module could not name one of them. That is
// the defect being repaired, and it is worth stating in the form it actually
// took rather than as "support was added":
//
// `loadSources` walks `plugins/<id>/` for `plugin.json` and `versions/*.json`
// and IGNORES everything else in that directory. So a hand-committed
// `plugins/<id>/identity.json` — the file that decides, through ID-41 and
// TRUST-23, whether a listing's next release is accepted at all — was a file
// this repository's own validator passed over in silence. It was not refused
// and it was not checked; it was invisible. The same held for the decision log
// and for the alert records: `tools/priv-scan.mjs` could CLASSIFY all three by
// path (its `COMPOSED` table has had them for a while), which meant their
// contents were scanned for personal data, while nothing anywhere asked
// whether they were the shape they claimed to be.
//
// An invisible file is worse than a refused one in exactly the way row 10 of
// §1.6 describes: a hand-committed identity record and a `source.repo` take
// over a listing, with genuine bot results after it, and the only thing that
// notices is a detector on the service's side, at a party boundary, later.
//
// THE NAME IS PART OF THE RECORD for three of the four. A decision record's
// basename IS its `decision_id`, an alert record's IS its fingerprint, and a
// queue entry's is `<id>@<version>`; a file whose name does not match its
// contents is a record two readers disagree about while both parse it fine.
// So the grammars below are checked against the name, and tools/validate.mjs
// compares the name with the document where the document repeats it.

/** `plugins/<id>/identity.json` (contract B.4; ID-15; DEC-17). */
export const IDENTITY_BASENAME = "identity.json";
export const IDENTITY_SCHEMA = "astra.registry.identity/1";

/** `log/decisions/<YYYY>/<MM>/<decision_id>.json` (DEC-7). */
export const DECISIONS_DIR = "log/decisions";
export const DECISION_SCHEMA = "astra.registry.decision/1";

/**
 * `state/alerts/<fingerprint>.json` (contract TRUST-14; registry plan RC-R1-4).
 *
 * ACCEPTED HERE, AND NOT SCHEMA-CHECKED, and the difference is deliberate.
 * B-T2.1 writes three schemas and this record's is not among them — it is
 * RC-R1-4's. What this module can say today is that the path is a record
 * location rather than a stray file, and what its name must look like; what it
 * cannot say is the member set, and inventing one here would put a second,
 * older answer in the tree on the day RC-R1-4 writes the first. That is the
 * same reasoning B-T2.2 applied to this very schema, one task earlier, and it
 * left a canary instead of a guess.
 */
export const ALERTS_DIR = "state/alerts";

/** `state/queue/<id>@<version>.json` (BOT-33's publication queue; BOT-38). */
export const QUEUE_DIR = "state/queue";
export const QUEUE_SCHEMA = "astra.registry.queue/1";

/** §0.7: a `decision_id` is 32 lowercase hex, and so is a decision record's name. */
const DECISION_ID_RE = /^[0-9a-f]{32}$/;
/** bot/lib/policy/release.mjs's FINGERPRINT_CHARS: 16 lowercase hex. */
const FINGERPRINT_RE = /^[0-9a-f]{16}$/;
const YEAR_RE = /^[0-9]{4}$/;
const MONTH_RE = /^(?:0[1-9]|1[0-2])$/;

function jsonFilesIn(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function readRecord(rel, full, out, errors) {
  try {
    out.push({ file: rel, doc: readJson(full) });
  } catch (e) {
    errors.push({ file: rel, message: e.message });
  }
}

/**
 * `plugins/<dir>/identity.json` for each of `pluginDirs` that has one, as
 * `{file, doc}`, and every one that could not be read, as `{file, message}`.
 *
 * ONE READER, TWO CALLERS. `loadRecords` below reads identity records for
 * tools/validate.mjs to judge, and `tools/build-index.mjs` reads them for the
 * badge join (registry plan RC-R3-5; TRUST-25): a listing with an identity
 * record takes a badge only from a publisher record whose `owner_ids` carries
 * that record's `repository_owner_id`. Two readers of one path would be two
 * answers to "does this listing have an identity record", and the one that
 * answered "no" would badge by login — which is exactly the recycled-login
 * case the join exists to refuse. Structure only, like the rest of this
 * module: the schema is tools/validate.mjs's.
 *
 * @param {string} root
 * @param {string[]} pluginDirs the directory names under `plugins/` to look in
 */
export function loadIdentities(root = REPO_ROOT, pluginDirs = []) {
  const identities = [];
  const errors = [];
  for (const dir of pluginDirs) {
    const full = path.join(root, "plugins", dir, IDENTITY_BASENAME);
    if (!fs.existsSync(full)) continue;
    readRecord(`plugins/${dir}/${IDENTITY_BASENAME}`, full, identities, errors);
  }
  return { identities, errors };
}

/**
 * Every B.4 record outside `plugins/<id>/plugin.json` and `versions/*.json`.
 *
 * Structure and NAME only — no schema, no policy — which is this module's whole
 * contract. `errors` carries a file that could not be read or whose name is not
 * the grammar its directory fixes; the documents themselves go to
 * tools/validate.mjs, which owns the rules.
 *
 * ABSENCE IS THE ORDINARY STATE for all four directories and is NOT an error:
 * no listing is bound yet, no decision has been written yet, R3 has not
 * happened. An empty result and a missing directory are the same answer on
 * purpose.
 *
 * @param {{plugins?: {dir: string}[]}} sources the result of `loadSources`, for
 *   the plugin directories to look for an identity record in
 * @returns {{identities: {file: string, doc: object}[],
 *            decisions: {file: string, doc: object}[],
 *            alerts: {file: string, doc: object}[],
 *            queue: {file: string, doc: object}[],
 *            errors: {file: string, message: string}[]}}
 */
export function loadRecords(root = REPO_ROOT, sources = null) {
  const errors = [];
  const identities = [];
  const decisions = [];
  const alerts = [];
  const queue = [];

  // Off the tree rather than off `sources`, when `sources` is not given: an
  // identity record for a plugin directory that has no `plugin.json` is a
  // record for a listing that does not exist, and reading only the directories
  // `loadSources` returned would be the one arrangement that cannot see it.
  const pluginDirs = sources?.plugins
    ? sources.plugins.map((p) => p.dir)
    : (fs.existsSync(path.join(root, "plugins"))
      ? fs.readdirSync(path.join(root, "plugins"), { withFileTypes: true })
        .filter((d) => d.isDirectory()).map((d) => d.name).sort()
      : []);

  const loaded = loadIdentities(root, pluginDirs);
  identities.push(...loaded.identities);
  errors.push(...loaded.errors);

  const decisionsRoot = path.join(root, ...DECISIONS_DIR.split("/"));
  for (const year of jsonFilesIn(decisionsRoot)) {
    const yrel = `${DECISIONS_DIR}/${year.name}`;
    if (!year.isDirectory() || !YEAR_RE.test(year.name)) {
      errors.push({ file: yrel, message: "is not a four-digit year directory; DEC-7's log is <YYYY>/<MM>/<decision_id>.json" });
      continue;
    }
    for (const month of jsonFilesIn(path.join(decisionsRoot, year.name))) {
      const mrel = `${yrel}/${month.name}`;
      if (!month.isDirectory() || !MONTH_RE.test(month.name)) {
        errors.push({ file: mrel, message: "is not a two-digit month directory (01–12)" });
        continue;
      }
      for (const f of jsonFilesIn(path.join(decisionsRoot, year.name, month.name))) {
        const rel = `${mrel}/${f.name}`;
        if (!f.isFile() || !f.name.endsWith(".json")) {
          errors.push({ file: rel, message: "is not a .json file, and DEC-7's log holds records and nothing else" });
          continue;
        }
        if (!DECISION_ID_RE.test(f.name.slice(0, -".json".length))) {
          errors.push({
            file: rel,
            message: "is not named for a `decision_id` (§0.7: 32 lowercase hex). The name IS the id — " +
              "bot/lib/decisions.mjs's dedupe reads the basename, so a record under any other name is one " +
              "BOT-36 cannot find and will write a second copy of",
          });
          continue;
        }
        readRecord(rel, path.join(decisionsRoot, year.name, month.name, f.name), decisions, errors);
      }
    }
  }

  const alertsRoot = path.join(root, ...ALERTS_DIR.split("/"));
  for (const f of jsonFilesIn(alertsRoot)) {
    const rel = `${ALERTS_DIR}/${f.name}`;
    if (!f.isFile() || !f.name.endsWith(".json")) {
      errors.push({ file: rel, message: "is not a .json file" });
      continue;
    }
    if (!FINGERPRINT_RE.test(f.name.slice(0, -".json".length))) {
      errors.push({
        file: rel,
        message: "is not named for a submission fingerprint (16 lowercase hex). TRUST-14's record is found by " +
          "fingerprint and by nothing else, so a name that is not one is a record no alert will ever match",
      });
      continue;
    }
    readRecord(rel, path.join(alertsRoot, f.name), alerts, errors);
  }

  const queueRoot = path.join(root, ...QUEUE_DIR.split("/"));
  for (const f of jsonFilesIn(queueRoot)) {
    const rel = `${QUEUE_DIR}/${f.name}`;
    if (!f.isFile() || !f.name.endsWith(".json")) {
      errors.push({ file: rel, message: "is not a .json file" });
      continue;
    }
    readRecord(rel, path.join(queueRoot, f.name), queue, errors);
  }

  return { identities, decisions, alerts, queue, errors };
}

/**
 * Reads `publishers/*.json` into a map keyed by the LOWERCASED owner login —
 * `owner`, plus every login the record's `covers` list says it also speaks for,
 * all pointing at the SAME record object. Use `publisherRecords` when you want
 * each record once rather than each key once.
 *
 * Structure only, like `loadSources` — no policy, no schema, and no clock. The
 * expiry a `verified` record carries is deliberately NOT enforced here: this
 * module feeds a generator whose whole contract is "same sources, same bytes",
 * and a rule that consults the date makes today's index differ from tomorrow's
 * for reasons no diff can show. Expiry is a CHECK (see `expiredPublishers`),
 * which fails loudly and puts a person in front of it, rather than a silent
 * disappearance nobody can date.
 *
 * GitHub logins are case-insensitive, so `mihailinl` and `MihailinL` are one
 * account; keying on the lowercase form is what makes a listing's
 * `source.repo` find its publisher regardless of how either was typed.
 */
export function loadPublishers(root = REPO_ROOT) {
  const dir = path.join(root, "publishers");
  const errors = [];
  const publishers = new Map();
  if (!fs.existsSync(dir)) return { errors, publishers };

  const files = fs.readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const ent of files) {
    const rel = `publishers/${ent.name}`;
    if (ent.isSymbolicLink()) {
      errors.push({ file: rel, message: "is a symlink; publishers/ holds real files only" });
      continue;
    }
    if (!ent.isFile() || !ent.name.endsWith(".json")) continue;
    let doc;
    try {
      doc = readJson(path.join(dir, ent.name));
    } catch (e) {
      errors.push({ file: rel, message: `is not readable JSON — ${e.message}` });
      continue;
    }
    const stem = ent.name.slice(0, -".json".length);
    if (typeof doc?.owner !== "string" || doc.owner.toLowerCase() !== stem.toLowerCase()) {
      // The file name is the key the index is built on, so a record naming a
      // different owner than its file would attach a badge to an account
      // nobody reviewed.
      errors.push({ file: rel, message: `owner ${JSON.stringify(doc?.owner)} does not match the file name` });
      continue;
    }
    // The record's own login, plus every login it says it also speaks for.
    // `covers` exists because the badge is keyed on the owner half of
    // `source.repo` and a person's plugins do not all live under their personal
    // login: `KnlCE`'s reviewed record reached none of their listings, because
    // those live under the organisation `MINICE-AI` (named `KNICE-TECH` until 2026-09). A second file for the org
    // is NOT the fix — it would carry the same `display_name` and trip
    // `publisherNameCollisions`, correctly, since two records rendering as one
    // word is exactly what that check is for.
    //
    // Every key is claimed the same way and refused the same way, so a
    // `covers` entry cannot quietly take an owner another record already owns,
    // in either direction and whichever file was read first.
    const claims = [doc.owner, ...(Array.isArray(doc.covers) ? doc.covers : [])];
    const taken = claims.map((c) => String(c).toLowerCase()).find((k) => publishers.has(k));
    if (taken !== undefined) {
      const by = publishers.get(taken);
      errors.push({
        file: rel,
        message: taken === doc.owner.toLowerCase() && by.doc.owner.toLowerCase() === taken
          ? `a second record for ${doc.owner}`
          : `claims ${taken}, which ${by.file} already claims`,
      });
      continue;
    }
    const record = { file: rel, doc };
    for (const claim of claims) publishers.set(String(claim).toLowerCase(), record);
  }
  return { errors, publishers };
}

/**
 * The DISTINCT records in a publishers map, once each.
 *
 * The map is keyed by login and a record with `covers` is stored under several,
 * so `publishers.values()` yields the same object more than once. Every caller
 * that reasons about records rather than about keys wants this instead — and
 * one of them, `publisherNameCollisions`, would otherwise compare a record with
 * itself, find its own display name identical to its own display name, and
 * report every multi-login publisher as an impersonation of itself.
 */
export function publisherRecords(publishers) {
  return [...new Set(publishers.values())];
}

/**
 * The records whose evidence has not been confirmed inside its own window.
 *
 * Separate from the loader and from the generator because it is the one part
 * of this that has to know what day it is. A tier granted once and never
 * revisited is a claim about who somebody USED to be; this is what notices.
 */
export function expiredPublishers(publishers, now = new Date()) {
  const today = now.toISOString().slice(0, 10);
  const out = [];
  for (const { file, doc } of publisherRecords(publishers)) {
    if (typeof doc.expires_at === "string" && doc.expires_at < today) {
      out.push({ file, owner: doc.owner, expires_at: doc.expires_at });
    }
  }
  return out;
}

/**
 * Publisher names that a person could not tell apart.
 *
 * The display name is the word a user reads beside a trust mark, so two
 * publishers who render as the same word are an impersonation whether or not
 * anybody intended one. The catalogue already refuses this for plugin NAMES;
 * the argument is stronger here, because a plugin name sits beside a
 * description and a badge sits beside a claim about identity.
 *
 * `confusableSkeleton` and not a fold, and this repository already contains the
 * example that shows why: `KNICE` and `KnlCE` differ by a capital i against a
 * lowercase L. Case folding leaves them distinct — `knice` and `knlce` — and a
 * reader cannot tell them apart in any typeface they are likely to meet. The
 * skeleton collapses both to `knice`, which is the honest answer.
 *
 * A record's OWN login and display name are allowed to collide, and that is not
 * an oversight: `KnlCE` publishing as `KNICE` is one account spelling its own
 * name, which is the case this whole field exists to serve. What is refused is
 * one publisher wearing another's word.
 */
export function publisherNameCollisions(publishers) {
  const out = [];
  const records = publisherRecords(publishers);
  for (let i = 0; i < records.length; i++) {
    for (let j = i + 1; j < records.length; j++) {
      const a = records[i].doc;
      const b = records[j].doc;
      const an = confusableSkeleton(a.display_name ?? "");
      const bn = confusableSkeleton(b.display_name ?? "");
      if (an && an === bn) {
        out.push({ a: a.owner, b: b.owner, why: `both display as ${JSON.stringify(an)} once confusables are folded` });
        continue;
      }
      // Somebody else's LOGIN is also a word users see — in a repository URL,
      // and in this UI as the fallback when a display name is missing.
      if (an && an === confusableSkeleton(b.owner)) {
        out.push({ a: a.owner, b: b.owner, why: `${JSON.stringify(a.display_name)} is confusable with the login ${JSON.stringify(b.owner)}` });
      } else if (bn && bn === confusableSkeleton(a.owner)) {
        out.push({ a: b.owner, b: a.owner, why: `${JSON.stringify(b.display_name)} is confusable with the login ${JSON.stringify(a.owner)}` });
      }
    }
  }
  return out;
}
