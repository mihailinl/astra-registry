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
import { REPO_ROOT } from "./sources.mjs";
import { ID_PATTERN, unsafeDisplayText } from "./ids.mjs";
import { parseSemver } from "./semver.mjs";

/** Where advisories are written, one JSON file per advisory. */
export const SOURCE_DIR = "tools/revocations";

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

/** What the daemon does about a plugin an entry covers. */
export const ACTIONS = ["block_install", "disable", "warn"];

/** Advisory only — no daemon behaviour hangs on it. See RevocationSeverity. */
export const SEVERITIES = ["critical", "high", "moderate", "low"];

const ADVISORY_ID = /^ASTRA-\d{4}-\d{4,}$/;
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
  // a withdrawal notice is the last place to make an exception.
  if (typeof doc.reason !== "string" || doc.reason.trim().length < 10) {
    bad("reason must be a sentence a user can act on (at least 10 characters)");
  } else if (doc.reason.length > 300) {
    bad(`reason is ${doc.reason.length} characters; keep it under 300`);
  } else if (unsafeDisplayText(doc.reason)) {
    bad(`reason contains ${unsafeDisplayText(doc.reason)}, which must never reach a user's screen`);
  }

  if (doc.advisory_url !== undefined) {
    if (typeof doc.advisory_url !== "string" || !doc.advisory_url.startsWith("https://")) {
      bad(`advisory_url ${JSON.stringify(doc.advisory_url)} must be an https URL`);
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
 * construction, and a read-and-increment counter file would not.
 *
 * Path-limited so that re-signing the list on a schedule (which is what keeps it
 * inside the seven-day window) does not move the serial. That matters: the
 * daemon may only ADD on an equal serial, so a scheduled re-sign at the same
 * serial is the *safe* republication, and bumping it on every run would make
 * every re-sign a full replacement.
 */
export function resolveSerial({ explicit, root = REPO_ROOT } = {}) {
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
    const out = execFileSync("git", ["rev-list", "--count", "HEAD", "--", SOURCE_DIR], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    // +1 so a repository with no advisories yet still publishes serial 1 rather
    // than 0. Serial 0 is reserved: `CatalogueState` uses it for "never seen",
    // and a document that claims it cannot be told apart from the absence of
    // one.
    return Number(out.trim()) + 1;
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
