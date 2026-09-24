// The decision-record writer: one place that knows what a `decision_id` is.
//
// Registry plan B-T2.2. DARK at R2 exit — four tasks call it and none of them
// has landed: B-T3.4's record commit (`bot/publish-apply.mjs`), B-T3.7's legacy
// trigger (`bot/decide.mjs`), B-T3.7b's baseline write (`bot/baseline.mjs`) and
// M-T3.8's compose leg (`bot/export-issues.mjs`). Three of those four already
// refuse BY NAME against this file's absence, and two of them state the export
// they want, so the surface below is not a guess: `writeDecisionRecord({ key,
// record, root })` returning `{ path }` is what `bot/export-issues.mjs`'s
// `resolveWriter` asks for, in those words, and what `bot/baseline.mjs` calls.
//
// ── WHY THIS IS A MODULE AND NOT FOUR FUNCTIONS IN FOUR FILES ───────────────
//
// BOT-35 gives `decision_id` ONE formula. `bot/publish-apply.mjs` says what
// happens if it gets two, and it is worth quoting because it is the whole
// reason this file exists rather than a helper in each caller: "a second
// composer is a second answer to what a decision id is, and the two collide
// silently because both are 32 hex characters".
//
// Silently is the operative word. A wrong id is not a crash and not a diff —
// it is a second file in `log/decisions/` saying the same thing under another
// name, which BOT-36's dedupe then fails to find, which BOT-19's terminal
// search then fails to find, which the service's detector B then reports as a
// decision with no record. Every one of those reads as somebody else's bug.
//
// ── THE FIVE KEY DOMAINS (BOT-35), AND WHICH ONE IS STILL AN EXTENSION ──────
//
//   submission:<submission_id>:<fingerprint>:<state>
//   migration:<owner/name>@<tag>                     B-T3.7b's baseline (MIG-20)
//   legacy:<owner/name>@<tag>:<fingerprint>:<state>  B-T3.7's legacy path
//   service-decision:<service_decision_id>:<plugin_id>:<version>:<state>
//   history:<owner/name>@<tag>:<decided_at>:<state>  M-T3.8's export (MIG-21)
//
// The fifth is contract 2.5.0's (lane S3b's spelling). MIG-21 asks for one
// record per historic decision. This registry decided some versions more than
// once on one issue thread: a refusal, a re-check, an approval. Under
// `migration:` all of those derived one id, so each later record landed on the
// first one's path. `decided_at` and `state` separate them.
//
// The fourth is contract 0.13.0's own tuple, spelled with a domain in front of
// it: BOT-35 now derives an author-action record's id over (`service_decision_id`,
// `plugin_id`, `version`, `state`), because the first tuple is derived over a
// submission id and a fingerprint, and a yank has neither. Only `legacy:` is
// still this plan's extension of BOT-35, and it is raised for ops.22 alone
// (registry plan §1.3 row 6).
//
// **The plan spells the fourth domain twice and not identically.** Its B-T2.2
// entry and its §1.2 both say `service-decision:<service_decision_id>:<plugin_id>:
// <version>:<state>`; the amendment list ops.22 is written from says
// `service-decision:<service_decision_id>:<version>`, two members short. The
// long form is the one that matches the contract's tuple, so it is the one
// here, and the short one is a finding against the plan rather than a choice
// this file gets to make. If the contract MINOR ever publishes the short form,
// the service and this writer derive different ids for the same yank — which is
// exactly the collision the paragraph above is about, across a party boundary
// where nobody can see both halves.
//
// ── WHAT COMPOSES, AND WHAT MERELY WRITES ───────────────────────────────────
//
// `composeAuthorActions` is the one record shape composed HERE, because DEC-7
// enumerates it exactly and FLOW-79 fixes every one of its values. Every other
// record is composed by its caller — `bot/baseline.mjs` and
// `bot/export-issues.mjs` each have a `RECORD_MEMBERS` allowlist and a grammar
// per member, deliberately, and duplicating those here would be the second
// composer this module exists to prevent. What this file does for them is
// stamp `schema`, derive `decision_id`, refuse under PRIV-2, and place the
// file. A caller that hands over a `schema` or a `decision_id` of its own is
// refused: that is a caller that has started deriving ids.
//
// ── INV-37 ─────────────────────────────────────────────────────────────────
//
// Nothing here reads an artifact, a network or a submitter's bytes. It takes
// values its caller re-read from git or from a verified certificate, and the
// refusals below are a second line rather than the first one: `verify`'s facts
// and `decide`'s outputs are the inputs, and the committing job is where they
// are composed.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { safeRepo, safeTag } from "./intake.mjs";
import { ID_PATTERN } from "../../tools/lib/ids.mjs";
import { SEMVER_PATTERN } from "../../tools/lib/semver.mjs";
import { stableStringify } from "../../tools/lib/canonical.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { TIME, isTime } from "../../tools/lib/time.mjs";
import { DOCUMENT_MEMBERS, scanDocument, shapeFindings } from "../../tools/lib/priv-rules.mjs";

/** `astra.registry.decision/1` (DEC-7). Stamped here and nowhere else. */
export const RECORD_SCHEMA = "astra.registry.decision/1";

/** Where records live. `bot/baseline.mjs`'s reader walks the same two levels. */
export const DECISIONS_DIR = "log/decisions";

/**
 * The schema a composed record is read by, which B-T2.1 landed.
 *
 * B-T2.2's canary list asks that an author-action record "validates against
 * `schema/decision-v1.json`". When this module was written that file was a
 * later task's, and DEC-7 had only just gained the author-action member list
 * in contract 0.13.0 — before which the schema "had to guess". Guessing it
 * here would have put a second, older answer to the record's shape in the tree
 * on the day B-T2.1 wrote the first, so the assertion was left unwired and
 * `bot/tests/decisions.test.mjs` carried a canary asserting this file's
 * ABSENCE, which went red the day it arrived and named the assertion to wire.
 *
 * That is what happened, and the assertion is wired. The constant stays
 * exported and `decisionSchema` below stays a probe, now pointing the other
 * way: the schema is a file on disk, and a rename would turn "validates
 * against the schema" into "validates against nothing" with nothing red.
 */
export const DECISION_SCHEMA_FILE = "schema/decision-v1.json";

/** §0.7: `decision_id` is 32 lowercase hex, deterministic. */
export const DECISION_ID_CHARS = 32;

const ID_RE = new RegExp(ID_PATTERN);
const SEMVER_RE = new RegExp(SEMVER_PATTERN);
// §0.7's time is `tools/lib/time.mjs`' `TIME` and `isTime`: RFC 3339 UTC, whole
// seconds, `Z`, a real instant, and never second 60 (contract 0.34.0). This
// module spelled the grammar for itself until then, and admitted `…:60Z`, hour
// 24 and `2026-02-30` in `decided_at`, the record's path and `Decided-At:`.
/** §0.7: `repository_id` is a canonical base-10 digit string, never coerced. */
const BASE10_RE = /^[0-9]{1,20}$/;
/** §0.7: `submission_id` and `service_decision_id` are lowercase UUID v4 or v7. */
const UUID_V47_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECISION_ID_RE = new RegExp(`^[0-9a-f]{${DECISION_ID_CHARS}}$`);
/** bot/lib/policy/release.mjs's FINGERPRINT_CHARS: 16 lowercase hex. */
const FINGERPRINT_RE = /^[0-9a-f]{16}$/;

// ── BOT-35: one key, one hash, five domains ─────────────────────────────────

/**
 * The five domains, each with the builder that spells its key.
 *
 * A table rather than five exported functions with five spellings, so that
 * "the key has a domain prefix" is a property of the data and a canary can
 * drop one and watch the derivation refuse. Dropping the prefix is the
 * mutation B-T2.2's canary list names.
 */
const DOMAINS = {
  submission: {
    tuple: "(`submission_id`, `fingerprint`, `state`)",
    build: ({ submission_id, fingerprint, state }) => {
      if (typeof submission_id !== "string" || !UUID_V47_RE.test(submission_id)) {
        throw new Error(
          `\`submission_id\` ${JSON.stringify(submission_id)} is not §0.7's lowercase UUID v4 or v7, and a key ` +
          "derived over a malformed id is a decision nothing can ever find again",
        );
      }
      return `submission:${submission_id}:${fingerprintPart(fingerprint)}:${statePart(state)}`;
    },
  },
  // MIG-20's one record per version: unique by construction, because a
  // version has one tag and one record. The plan notes spell this domain with
  // `:<fingerprint>:<state>` too; the tree keeps the short form because every
  // baseline record is `published` over its version's one fingerprint, so the
  // two spellings separate exactly the same records — and the short form is
  // the one `bot/baseline.mjs` and `bot/export-issues.mjs` already spell.
  migration: { tuple: "(`owner/name`, `tag`)", build: (f) => `migration:${repoTag(f)}` },
  legacy: {
    tuple: "(`owner/name`, `tag`, `fingerprint`, `state`)",
    build: (f) => `legacy:${repoTag(f)}:${fingerprintPart(f.fingerprint)}:${statePart(f.state)}`,
  },
  "service-decision": {
    tuple: "(`service_decision_id`, `plugin_id`, `version`, `state`)",
    build: ({ service_decision_id, plugin_id, version, state }) => {
      if (typeof service_decision_id !== "string" || !UUID_V47_RE.test(service_decision_id)) {
        throw new Error(
          `\`service_decision_id\` ${JSON.stringify(service_decision_id)} is not §0.7's lowercase UUID v4 or v7`,
        );
      }
      // `typeof` before the pattern, because `RegExp.test` stringifies: a
      // numeric `plugin_id` of 123 matches the id pattern as "123".
      if (typeof plugin_id !== "string" || !ID_RE.test(plugin_id)) {
        throw new Error(`\`plugin_id\` ${JSON.stringify(plugin_id)} is not a plugin id`);
      }
      if (typeof version !== "string" || !SEMVER_RE.test(version)) {
        throw new Error(`\`version\` ${JSON.stringify(version)} is not a semver`);
      }
      if (typeof state !== "string") throw new Error(`\`state\` ${JSON.stringify(state)} is not a state`);
      if (!state) throw new Error("the author-action tuple's `state` is missing, and BOT-35 derives the id over it");
      return `service-decision:${service_decision_id}:${plugin_id}:${version}:${state}`;
    },
  },
  // MIG-21's export (contract 2.5.0): one record per historic decision, where
  // one version may have been decided more than once on its issue thread.
  history: {
    tuple: "(`owner/name`, `tag`, `decided_at`, `state`)",
    build: (f) => {
      if (!isTime(f.decided_at)) {
        throw new Error(
          `\`decided_at\` ${JSON.stringify(f.decided_at)} is not a §0.7 time, and BOT-35 derives a \`history:\` ` +
          "id over it: it is what separates two decisions about one version",
        );
      }
      return `history:${repoTag(f)}:${f.decided_at}:${statePart(f.state)}`;
    },
  },
};

/** Every domain BOT-35 knows, in the order the plan lists them. */
export const KEY_DOMAINS = Object.freeze(Object.keys(DOMAINS));

/**
 * BOT-35's fingerprint member: 16 lowercase hex, or none.
 *
 * **Why the tuple carries it at all, and what its absence cost.** BOT-35
 * derives the id over (`submission_id`, or `owner/name@tag`; fingerprint;
 * state). This module first keyed the submission and legacy domains on the
 * submission alone — so a submission's `held` record and the `published`
 * record its approval produces derived ONE id, and BOT-36's dedupe below,
 * which matches on the id, dropped the publication as "already at" the hold's
 * path. Every approval would have published nothing, reported `written:
 * false`, and thrown nothing. The same held for a delayed release draining:
 * `delayed` and `published` were one id.
 *
 * DEC-7 lets a record carry no fingerprint where none applies — an
 * `A_WITHDRAW` from `received` hashed no release — and the tuple member is
 * then the EMPTY string, never "null": a key reading `…:null:…` would
 * collide with nothing and be spelled by nobody else.
 */
function fingerprintPart(fingerprint) {
  if (fingerprint === null || fingerprint === undefined) return "";
  if (typeof fingerprint !== "string" || !FINGERPRINT_RE.test(fingerprint)) {
    throw new Error(
      `\`fingerprint\` ${JSON.stringify(fingerprint)} is not 16 lowercase hex (FINGERPRINT_CHARS), and BOT-35 ` +
      "derives the id over it: a key over a malformed fingerprint names a decision nothing can find again",
    );
  }
  return fingerprint;
}

/**
 * BOT-35's state member: required, and the record's own shape.
 *
 * The shape is schema/decision-v1.json's `state` (lowercase letters and `_`,
 * 1 to 32), not a closed list, for that schema's reason: DEC-7 covers
 * decisions about submissions, fingerprints and versions and names no single
 * list of its own. A missing state is refused rather than defaulted, because
 * the state is exactly what separates a hold from the publication it becomes.
 */
function statePart(state) {
  if (typeof state !== "string" || !/^[a-z][a-z_]{0,31}$/.test(state)) {
    throw new Error(
      `\`state\` ${JSON.stringify(state)} is not a decision record's state, and BOT-35 derives the id over it: ` +
      "without it a submission's hold and its publication are one id, and BOT-36 drops the second",
    );
  }
  return state;
}

function repoTag({ repo, tag }) {
  if (!safeRepo(repo)) {
    throw new Error(`\`repo\` ${JSON.stringify(repo)} is not an \`owner/name\`, so the key would name no repository`);
  }
  if (!safeTag(tag)) {
    throw new Error(`\`tag\` ${JSON.stringify(tag)} is not a release tag, so the key would name no release`);
  }
  return `${repo}@${tag}`;
}

/**
 * The key an id is derived over, for one domain.
 *
 * @param {"submission"|"migration"|"legacy"|"service-decision"|"history"} domain
 * @param {object} parts the tuple members for that domain
 */
export function decisionKey(domain, parts) {
  const entry = DOMAINS[domain];
  if (!entry) {
    throw new Error(
      `\`${domain}\` is not one of BOT-35's key domains (${KEY_DOMAINS.join(", ")}). A sixth domain is a sixth ` +
      "kind of decision, which is a contract amendment (`history:` needed 2.5.0) and not an argument",
    );
  }
  return entry.build(parts ?? {});
}

/** `submission:<submission_id>:<fingerprint>:<state>` (BOT-35, first tuple). */
export const submissionKey = (parts) => decisionKey("submission", parts);
/** `migration:<owner/name>@<tag>` — MIG-20's baseline, one record per published version. */
export const migrationKey = (parts) => decisionKey("migration", parts);
/** `legacy:<owner/name>@<tag>:<fingerprint>:<state>` — B-T3.7's legacy path (BOT-35; ops.22). */
export const legacyKey = (parts) => decisionKey("legacy", parts);
/** `service-decision:<service_decision_id>:<plugin_id>:<version>:<state>` (BOT-35, second tuple). */
export const serviceDecisionKey = (parts) => decisionKey("service-decision", parts);
/** `history:<owner/name>@<tag>:<decided_at>:<state>` — MIG-21's export (BOT-35, contract 2.5.0). */
export const historyKey = (parts) => decisionKey("history", parts);

/** The domain a key carries, or `null` when it carries none. */
export function keyDomain(key) {
  const text = String(key ?? "");
  for (const domain of KEY_DOMAINS) {
    if (text.startsWith(`${domain}:`) && text.length > domain.length + 1) return domain;
  }
  return null;
}

/**
 * BOT-35's derivation: the first 32 hex of SHA-256 over the domain-separated key.
 *
 * The domain check is not a formality. Without a prefix, `migration:` and
 * `legacy:` records for one `owner/name@tag` derive the SAME id — the case
 * B-T2.2's canary list calls out by name — and the second write lands on the
 * first's path, so one of two decisions disappears with nothing red anywhere.
 * `service-decision:` collides the same way with any tuple that happens to
 * stringify alike.
 */
export function decisionId(key) {
  if (!keyDomain(key)) {
    throw new Error(
      `\`${key}\` carries none of BOT-35's domains (${KEY_DOMAINS.map((d) => `${d}:`).join(", ")}). The domain is ` +
      "what keeps a `migration` and a `legacy` record for one `owner/name@tag` from deriving one id and " +
      "overwriting each other",
    );
  }
  return crypto.createHash("sha256").update(String(key), "utf8").digest("hex").slice(0, DECISION_ID_CHARS);
}

/** `log/decisions/<YYYY>/<MM>/<decision_id>.json`, `/`-separated. */
export function recordPath({ decision_id, decided_at }) {
  if (!DECISION_ID_RE.test(String(decision_id ?? ""))) {
    throw new Error(`\`decision_id\` ${JSON.stringify(decision_id)} is not ${DECISION_ID_CHARS} lowercase hex (§0.7)`);
  }
  if (!isTime(decided_at)) {
    throw new Error(
      `\`decided_at\` ${JSON.stringify(decided_at)} is not §0.7's RFC 3339 UTC with whole seconds, and the ` +
      "record's path is derived from it — a record filed under the wrong month is a record the year's walk misses",
    );
  }
  return `${DECISIONS_DIR}/${decided_at.slice(0, 4)}/${decided_at.slice(5, 7)}/${decision_id}.json`;
}

// ── DEC-7's author-action record (FLOW-79; §7.2) ────────────────────────────

/**
 * DEC-7's author-action members, in DEC-7's own order. Exactly thirteen.
 *
 * `schema` and `decision_id` are the writer's; the other eleven are composed.
 * The list is here rather than inline because the canary asserts the SET —
 * "no more, no fewer" — and a set asserted against a literal written twice is
 * a set asserted against itself.
 */
export const AUTHOR_ACTION_MEMBERS = Object.freeze([
  "schema", "decision_id", "decided_at", "actor", "trigger", "plugin_id", "version",
  "repo", "repository_id", "repository_owner_id", "state", "reasons", "category",
]);

/**
 * The two members an author-action record must NOT have, named rather than
 * merely absent.
 *
 * DEC-7: "it carries no `submission_id` and no `fingerprint`, which a yank has
 * not." They are refused by name so the refusal can SAY that, because both are
 * legitimate members of the other record shape and a caller copying a
 * submission record's composer would supply them without noticing. The canary
 * adds `submission_id` and watches this fire.
 */
export const AUTHOR_ACTION_FORBIDDEN = Object.freeze(["submission_id", "fingerprint"]);

/**
 * Every composed member of an author-action record, and the grammar of each.
 *
 * `str` is not a tidy-up. `RegExp.prototype.test` stringifies its argument, so
 * `BASE10_RE.test(912345678)` — a JSON **number** where §0.7 requires a
 * canonical base-10 digit **string** — passes. `bot/baseline.mjs` has the
 * failure written out in full for the same member: a GitHub repository id is
 * past 2^31 and heading for 2^53, JSON has one number type and it is a double,
 * and 9007199254740993 round-trips as …92, which names a repository that never
 * published the bytes. A record is written once and never rewritten, so the
 * coercion is caught here or not at all.
 *
 * Found by this suite before it was written down: the null case was refused
 * and the number case was not.
 */
const str = (re) => (v) => typeof v === "string" && re.test(v);

const AUTHOR_ACTION_GRAMMAR = {
  decided_at: str(TIME),
  actor: (v) => v === "author",
  trigger: (v) => v === "moderation",
  plugin_id: str(ID_RE),
  version: str(SEMVER_RE),
  repo: (v) => typeof v === "string" && safeRepo(v) !== null,
  repository_id: str(BASE10_RE),
  repository_owner_id: str(BASE10_RE),
  state: (v) => v === "yanked",
  reasons: (v) => Array.isArray(v) && v.length === 1 && v[0] === "A_YANK",
  category: (v) => v === "author_request",
};

/**
 * One author-action record per version an `A_YANK` names (DEC-7; FLOW-79).
 *
 * **Per version, and that is the point of the second tuple.** An `A_YANK`
 * names listed versions, plural; DEC-7's `version` is a single member. So a
 * yank of three versions is three records, and BOT-35's tuple carries
 * `version` so their ids differ. Writing one record with a joined `version` is
 * the mutation the canary uses, and it is not hypothetical: it is what a
 * composer written against the submission record — where `version` is one
 * value because a submission is one release — produces by default.
 *
 * `repository_id` and `repository_owner_id` may not be null here, unlike a
 * baseline record. FLOW-79 since 0.13.0 forbids an unbound listing a yank at
 * all: its author asks a moderator instead. A yank with no ids is therefore
 * a yank of a listing that should never have reached this function, and
 * M-T3.3 holds it as `unbound_yank` rather than composing a record with holes.
 *
 * @param {{service_decision_id: string, plugin_id: string, versions: string[],
 *   repo: string, repository_id: string, repository_owner_id: string, decided_at: string}} act
 * @returns {{key: string, record: object}[]} one per version, in the order given
 */
export function composeAuthorActions(act) {
  const versions = act?.versions ?? [];
  if (!Array.isArray(versions) || versions.length === 0) {
    throw new Error(
      "an `A_YANK` names at least one listed version, and a compile that produced none is a yank that yanked " +
      "nothing — BOT-34's CI refusal counts records against the versions the commit names, and zero of zero passes",
    );
  }
  const seen = new Set();
  for (const version of versions) {
    if (seen.has(version)) {
      throw new Error(
        `\`${version}\` is named twice by one \`A_YANK\`, so two records would derive one id from BOT-35's tuple ` +
        "and the commit would carry fewer records than the versions it names",
      );
    }
    seen.add(version);
  }
  return versions.map((version) => {
    const record = {
      decided_at: act.decided_at,
      actor: "author",
      trigger: "moderation",
      plugin_id: act.plugin_id,
      version,
      repo: act.repo,
      repository_id: act.repository_id,
      repository_owner_id: act.repository_owner_id,
      state: "yanked",
      reasons: ["A_YANK"],
      category: "author_request",
    };
    refuseUncomposableAuthorAction(record);
    return {
      key: serviceDecisionKey({
        service_decision_id: act.service_decision_id,
        plugin_id: act.plugin_id,
        version,
        state: "yanked",
      }),
      record,
    };
  });
}

/** The grammar half of the author-action refusal, before `schema`/`decision_id` are stamped. */
export function refuseUncomposableAuthorAction(record) {
  for (const member of AUTHOR_ACTION_FORBIDDEN) {
    if (Object.prototype.hasOwnProperty.call(record, member)) {
      throw new Error(
        `an author-action record carries no \`${member}\` (DEC-7): a yank enters no submission and hashes no ` +
        "release, so a value here is a value copied from a record about something else",
      );
    }
  }
  for (const [member, value] of Object.entries(record)) {
    const grammar = AUTHOR_ACTION_GRAMMAR[member];
    if (!grammar) {
      throw new Error(
        `\`${member}\` is not one of DEC-7's author-action members, and DEC-7's sentence is "with only these ` +
        `members": ${AUTHOR_ACTION_MEMBERS.join(", ")}`,
      );
    }
    if (!grammar(value)) {
      throw new Error(
        `\`${member}\` does not match its own grammar, so it is not the thing it claims to be: ` +
        `${JSON.stringify(value)}`,
      );
    }
  }
  const missing = AUTHOR_ACTION_MEMBERS
    .filter((m) => m !== "schema" && m !== "decision_id")
    .filter((m) => !Object.prototype.hasOwnProperty.call(record, m));
  if (missing.length) {
    throw new Error(
      `an author-action record is missing ${missing.join(", ")}. DEC-7 lists thirteen members and marks none of ` +
      "them optional for this shape, so a record short of one is a record the schema will refuse after it is committed",
    );
  }
  return record;
}

// ── BOT-37's trailers ───────────────────────────────────────────────────────

/**
 * The five trailers, each with the grammar of its value.
 *
 * **The grammar is what makes "trailers carry no login" a check rather than a
 * hope.** A trailer value is free text as far as git is concerned, so the only
 * thing that can keep a handle, an address or a subject id out of one is a
 * pattern narrow enough to exclude them — and all five of these are: digits, a
 * UUID, 32 hex, a UUID, an instant. There is no value that is both a login and
 * any of those.
 *
 * ── THE FIFTH, AND WHY IT IS DECLARED HERE RATHER THAN RENDERED PAST HERE ───
 *
 * Until this line, `Decided-At:` was a trailer this list did not carry while
 * `bot/lib/compile-decision.mjs` returned one and `bot/moderation-run.mjs`
 * rendered it, against a private copy of §0.7's timestamp, immediately after
 * the block `renderTrailers` composed. That is not "a fifth trailer nobody
 * declared"; it is worse, and the direction is what matters: `privacyFindings`
 * below scans the trailers it is HANDED, so a trailer appended after it ran was
 * a line reaching a public, permanent git record that the privacy scanner could
 * not see. Declaring it is the narrowing. Leaving it outside the list would
 * have inverted the scanner's purpose — the refusal exists to force
 * declaration, not to cap the count at four, and the one trailer added after
 * the scanner was written is exactly the one it must be able to read.
 *
 * The name and its constraint were not this repository's to choose and are
 * already published: contract 0.20.0 carries, as one of the two conditions
 * `minice-be` set on their agreement, *"a `Decided-At:` trailer carries a time
 * and not a moderator's identity (PRIV-2)"*. So the grammar below is not
 * decoration around a name — it IS that condition, stated as the only thing
 * that can enforce it. §0.7: "Times are RFC 3339 UTC, whole seconds, ending in
 * `Z`". `mod-7` is §0.7's moderator handle and does not match it; neither does
 * a login, an address, or the 1-to-64-character subject-id shape.
 *
 * Measured on the peer's side rather than assumed, because a fifth trailer is
 * a change to bytes they read: `minice` at `plugins/crates/plugins-git/src/
 * records/trailer.rs` pins three trailer tokens — `Service-Decision`,
 * `Badge-Withdrawn`, `Source-Commit` — and `Decided-At` is not among them; its
 * `trailer_values(message, token)` looks up a trailer BY NAME and never
 * enumerates the block, so it cannot meet an unknown one; and a value it cannot
 * parse is, in that file's own words, "dropped, not refused". A fifth trailer
 * is invisible over there today and would need a deliberate change there to
 * start being read.
 *
 * `Run:` carries `run_id`, or `run_id/run_attempt`, and NOT the run URL that
 * `bot/lib/alert-verdict.mjs`'s `runUrl` builds. The URL embeds
 * `GITHUB_REPOSITORY`, whose owner is a login — permitted by PRIV-2 as a
 * repository coordinate, but it would make the "no login" canary above assert
 * nothing, since the one trailer that could carry one always would. §0.7
 * expects `run_id` and `run_attempt` to be base-10 digit strings (pending
 * OPEN-OPS-13's measurement of a real bot token) and that is what correlation
 * needs: the URL is reconstructible from the id, and the id is not
 * reconstructible from a login.
 */
const TRAILER_GRAMMAR = {
  Run: { re: /^[0-9]{1,20}(?:\/[0-9]{1,5})?$/, uuidOk: false, says: "§0.7's `run_id`, or `run_id/run_attempt`" },
  Submission: { re: UUID_V47_RE, uuidOk: true, says: "§0.7's lowercase UUID v4 or v7" },
  Decision: { re: DECISION_ID_RE, uuidOk: false, says: `§0.7's ${DECISION_ID_CHARS} lowercase hex` },
  "Service-Decision": { re: UUID_V47_RE, uuidOk: true, says: "§0.7's lowercase UUID v4 or v7" },
  // Last, because the plan's order is "a `Decided-At:` beside each
  // `Service-Decision:`" and `TRAILERS` is the order a commit carries them in.
  "Decided-At": { re: TIME, uuidOk: false, says: "§0.7's RFC 3339 UTC with whole seconds, ending in `Z`" },
};

/** BOT-37's trailer names, in the order a commit carries them. */
export const TRAILERS = Object.freeze(Object.keys(TRAILER_GRAMMAR));

/**
 * One trailer line, held to the grammar its NAME declares.
 *
 * The one place a trailer's name is turned into a line, so that "every rendered
 * trailer is declared and every declared trailer has a grammar" is a property
 * of the code rather than of four callers agreeing. `bot/moderation-run.mjs`
 * renders the per-decision trailers — a `Decision:`, a `Service-Decision:` and
 * a `Decided-At:` per decision, which `renderTrailers` cannot express because
 * it renders one of each — and it calls THIS rather than keeping a second copy
 * of §0.7's timestamp, which is what it did while `Decided-At:` was undeclared.
 *
 * A second copy of a grammar is not a tidiness complaint here: the copy is the
 * only thing standing between a free-text trailer and a value PRIV-2 refuses,
 * and the copy that drifts is always the one further from the list.
 */
export function trailerLine(name, value) {
  const grammar = TRAILER_GRAMMAR[name];
  if (!grammar) {
    throw new Error(
      `\`${name}:\` is not one of BOT-37's trailers (${TRAILERS.join(", ")}). A trailer reaches a public git ` +
      "record for ever and `privacyFindings` scans the declared set, so an undeclared name is a line the privacy " +
      "scanner cannot see rather than a line it allowed",
    );
  }
  if (!grammar.re.test(String(value))) {
    throw new Error(
      `\`${name}: ${value}\` is not ${grammar.says}. A trailer is correlation and never authority (BOT-37), so ` +
      "its value is a bare id with a grammar — which is also the only thing keeping a login out of one",
    );
  }
  return `${name}: ${value}`;
}

/**
 * Render BOT-37's trailers for a bot commit.
 *
 * `Run:` is required of every bot commit. The other three appear "where they
 * exist" — and `Service-Decision:` exists for every commit carrying an
 * author-action record, which is why `authorAction` is an argument and not an
 * inference: detector B row 2 matches a decision record that has no
 * `submission_id` — every author-action record — by this trailer alone. A yank
 * committed without it reads to the service as a record with no service
 * outcome, and the failure is at the far end of a party boundary where nothing
 * on this side can see it. So the absence is refused here, loudly, rather than
 * rendered as a shorter list.
 *
 * @param {{run: string, submission?: string|null, decision?: string|null,
 *   service_decision?: string|null, decided_at?: string|null,
 *   authorAction?: boolean}} t
 * @returns {string[]} the trailer lines, in `TRAILERS` order
 */
export function renderTrailers(t = {}) {
  const values = {
    Run: t.run,
    Submission: t.submission,
    Decision: t.decision,
    "Service-Decision": t.service_decision,
    "Decided-At": t.decided_at,
  };
  if (values.Run === undefined || values.Run === null || values.Run === "") {
    throw new Error("BOT-37: every bot commit carries a `Run:` trailer, and correlation must outlive a 14-day artifact");
  }
  if (t.authorAction && !values["Service-Decision"]) {
    throw new Error(
      "a commit carrying an author-action record carries a `Service-Decision:` trailer (BOT-37). That trailer is " +
      "how the service's detector B matches a decision record with no `submission_id`, which every author-action " +
      "record is; without it the yank reads over there as a record with no service outcome",
    );
  }
  const lines = [];
  for (const name of TRAILERS) {
    const value = values[name];
    if (value === undefined || value === null || value === "") continue;
    lines.push(trailerLine(name, value));
  }
  return lines;
}

/**
 * A commit message for a decision commit: a subject, an optional body, and
 * BOT-37's trailer block.
 *
 * The body is scanned under PRIV-2 (see `subjectIdFindings`) and the subject
 * with it. Nothing else this repository composes for git has a free-text half,
 * which is why `tools/priv-scan.mjs` — whose rule is positional — states
 * plainly that a commit body is where its position rule cannot reach, and
 * names B-T2.2 as what catches a subject id there. This is that.
 */
export function decisionCommitMessage({ subject, body = "", ...trailers }) {
  if (!subject || /\n/.test(subject)) throw new Error("a commit subject is one non-empty line");
  const lines = renderTrailers(trailers);
  // Paragraphs joined by ONE BLANK LINE, and an absent body is dropped whole.
  // This joined the parts with their blank separators filtered out, so git
  // read the body's first paragraph as part of the subject and the trailer
  // block as body text — `%(trailers)` printed nothing for a commit ending
  // "Run: …". Measured by committing one (bot/tests/decisions.test.mjs).
  const text = [subject, String(body ?? "").trim(), lines.join("\n")].filter((p) => p !== "").join("\n\n");
  const found = subjectIdFindings(text);
  if (found.length) {
    throw new Error(
      `${found.length} line(s) of this commit message are a lone token of PRIV-2's subject-id shape and match no ` +
      "coordinate this registry composes; describe the value instead of quoting it (PRIV-2)",
    );
  }
  return `${text}\n`;
}

// ── PRIV-2 over composed content ────────────────────────────────────────────

/**
 * minice-be's own database constraint, `account_subject_shape`, cited by its
 * attack at `data-storage.md`:545 as the answer to registry plan §1.3 row 4:
 *
 *     CONSTRAINT account_subject_shape
 *       CHECK (subject IS NULL OR subject ~ '^[A-Za-z0-9_-]{1,64}$')
 *
 * NOT `MBE-PENDING` any more, and this is where the pattern lands on this side.
 *
 * ── AND IT CANNOT BE APPLIED THE WAY THE PLAN'S SENTENCE READS ─────────────
 *
 * B-T2.2's text says "every other string member and trailer is refused when it
 * holds … the Minice subject-id shape", applied "after `repo`, `tag` and the
 * exempt UUID members are taken out". Run literally over a valid author-action
 * record, that refuses the record: `state` is `yanked`, `actor` is `author`,
 * `trigger` is `moderation`, `category` is `author_request` and `reasons[0]`
 * is `A_YANK` — five members, five matches, on the first correct record this
 * registry would ever write. The plan half-says so itself ("the pattern is
 * wide"), and `tools/priv-scan.mjs` measured the same thing from the other
 * side: 23,556 of 29,462 tokens in a hundred commit messages match.
 *
 * So the shape is enforced the way this estate already enforces it, and the
 * rule is stated in one sentence by `bot/export-issues.mjs`: asking "does this
 * value look personal" of a value that could be anything has no safe answer;
 * asking "is this value a semver" of a member that may only ever be a semver
 * has one. Every member of every record this file writes is declared, with a
 * grammar, and an undeclared member is refused whatever it holds — which is
 * exactly where a subject id would land, since there is no declared member it
 * could pass the grammar of.
 *
 * ── THE ONE PLACE THE SHAPE ITSELF STILL DOES WORK ─────────────────────────
 *
 * A commit message has no members, so position cannot reach it. There the
 * shape is applied to a LINE that is a lone token of 16 to 64 of those
 * characters — the range the plan itself names — minus the coordinates PRIV-2
 * permits: a plugin id, a semver, a commit or digest hex, a decision id.
 *
 * Measured before it was written, on this repository at `b60dae6`: over the
 * last 200 commit messages, 8,662 lines, **zero** lines match. A rule with a
 * measured false-positive rate of zero on the corpus it will run over is a
 * rule that can be left switched on, which is the whole difference between
 * this and the 23,556-token version.
 *
 * The plan's own false-positive fixture — an author `README.md` line — stays
 * green for two independent reasons, and both are asserted: a README is not a
 * document this module composes, and a line that IS a lone long token is
 * almost always a plugin id, which is exempt by name.
 */
export const SUBJECT_ID_PATTERN = "^[A-Za-z0-9_-]{1,64}$";
export const SUBJECT_ID_RE = new RegExp(SUBJECT_ID_PATTERN);

/** The narrow half: 16 to 64, the range B-T2.2 calls out as the ambiguous one. */
const LONE_TOKEN_RE = /^[A-Za-z0-9_-]{16,64}$/;
const HEX_RE = /^[0-9a-f]{16}$|^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/;

/** A coordinate PRIV-2 permits by name, so a line that is one is not a finding. */
export function permittedCoordinate(token) {
  return ID_RE.test(token) || SEMVER_RE.test(token) || HEX_RE.test(token) || UUID_V47_RE.test(token);
}

/**
 * Lines of composed free text that are a lone subject-id-shaped token.
 *
 * @param {string} text
 * @returns {{code: string, what: string}[]}
 */
export function subjectIdFindings(text) {
  const out = [];
  for (const line of String(text ?? "").split("\n")) {
    const token = line.trim();
    if (!LONE_TOKEN_RE.test(token)) continue;
    if (permittedCoordinate(token)) continue;
    out.push({ code: "E_PRIV_SUBJECT_ID", what: token });
  }
  return out;
}

/**
 * PRIV-2 over one composed record and its trailers.
 *
 * The four shape rules are `tools/priv-scan.mjs`'s, IMPORTED rather than
 * re-written — from `tools/lib/priv-rules.mjs`, where they live so that this
 * module need not import the canary — and that is the load-bearing decision in
 * this function. PRIV-2's published Check and this composition-time refusal
 * are the same rule asked at two moments; two implementations of it would be
 * two answers to "is this personal", and the one that would drift is the one
 * that runs on every commit rather than the one that runs on a composition
 * nobody has made yet.
 *
 * The position rule comes from the same file's `DOCUMENT_MEMBERS.decision`,
 * which is DEC-7's twenty-five members with `submission_id` and
 * `service_decision_id` marked UUID-exempt and `moderator` handle-exempt. For
 * an author-action record this module then narrows it further, to the thirteen.
 *
 * ── A TRAILER IS CHECKED TWICE: ITS NAME, THEN ITS GRAMMAR ──────────────────
 *
 * The name half was here from the first line of this function. The grammar half
 * was NOT, and its absence was the hole that declaring a fifth trailer would
 * have widened rather than closed: this function looked up
 * `TRAILER_GRAMMAR[name]`, kept the `uuidOk` flag out of it, and threw the
 * pattern away — so `privacyFindings({ trailers: { Run: "mod-7" } })` returned
 * nothing. Every shape rule this file imports is keyed on a shape that is
 * ALREADY a login, an address, a Telegram id or a UUID; `HANDLE_RE` needs a
 * leading `@`, so §0.7's own moderator handle, `^mod-[1-9][0-9]*$`, matched
 * none of them. Declaration would then have meant "this name is allowed to hold
 * anything", which is the opposite of the sentence this module states twice:
 * asking *is this value a semver* of a member that may only ever be a semver
 * has a safe answer, and that is the whole reason a declared trailer carries a
 * grammar at all.
 *
 * Both halves run, and a value can produce both findings: the grammar says the
 * value is not the thing its name claims, and the shapes say what it is instead.
 *
 * ── NO REPOSITORY FILE WIDENS IT ───────────────────────────────────────────
 *
 * It takes no `root`, and refuses one. It used to take a root and read
 * `bot/security-contact.json` under it through the canary's `roleAddresses`,
 * exempting every address the file held — so an address added to a file
 * outside TRUST-31's hashed set passed this refusal and went into a public
 * record for ever, and the bot stayed live (dev/couplings.md entry 104). A role
 * mailbox is still exempt, by its local part, which is what the file's own
 * intended `security@` address is; that rule needs no file, and the canary
 * keeps the file-read rule for its own walk. A caller handing over a root is
 * a caller that believes something under it changes the answer, and nothing
 * may.
 *
 * @param {{record: object, trailers?: object}} opts
 * @returns {{code: string, what: string}[]}
 */
export function privacyFindings({ record, trailers = {}, ...rest }) {
  if (Object.prototype.hasOwnProperty.call(rest, "root")) {
    throw new Error(
      "privacyFindings takes no `root`: no file under a repository changes what PRIV-2 refuses in a record the " +
      "bot writes (dev/couplings.md entry 104). Role mailboxes are exempt by their local part",
    );
  }
  const roles = new Set(); // none published: the local-part rule is the whole role exemption here
  const found = scanDocument(record, "decision", roles);
  for (const [name, value] of Object.entries(trailers)) {
    if (value === undefined || value === null || value === "") continue;
    const grammar = TRAILER_GRAMMAR[name];
    if (!grammar) {
      found.push({
        code: "E_PRIV_UNDECLARED_TRAILER",
        what: `\`${name}:\` is not one of BOT-37's trailers (${TRAILERS.join(", ")})`,
      });
      continue;
    }
    if (!grammar.re.test(String(value))) {
      found.push({
        code: "E_PRIV_TRAILER_GRAMMAR",
        what: `\`${name}: ${value}\` is not ${grammar.says}, so it is not the thing its name claims to be`,
      });
    }
    for (const f of shapeFindings(String(value), { roles, member: name, uuidOk: grammar.uuidOk, handleOk: false })) {
      found.push({ ...f, what: `${name}: ${f.what}` });
    }
  }
  return found;
}

/** `privacyFindings`, as a refusal. */
export function refusePrivate(opts) {
  const found = privacyFindings(opts);
  if (found.length) {
    throw new Error(
      `PRIV-2 refuses ${found.length} value(s) in this record: ` +
      found.map((f) => `${f.code} ${f.what}`).join("; ") +
      ". Git never forgets (DEC-7), so this is refused at composition rather than repaired afterwards",
    );
  }
  return opts.record;
}

// ── BOT-36: the write that is dropped ───────────────────────────────────────

/**
 * Every record already in `log/decisions/`, as `{ file, decision_id }`.
 *
 * Walked rather than stat'ed at the path `recordPath` would produce, and the
 * difference matters: the path carries `decided_at`'s year and month, so the
 * same tuple written with a different clock lands in a different directory.
 * A dedupe that only looked where it was about to write would find nothing,
 * and BOT-36's whole purpose is the run that retries after a rebase.
 */
export function recordsOnMain(root = REPO_ROOT) {
  const base = path.join(root, ...DECISIONS_DIR.split("/"));
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.isFile() || !e.name.endsWith(".json")) continue;
      out.push({
        file: path.relative(root, full).split(path.sep).join("/"),
        decision_id: e.name.slice(0, -".json".length),
      });
    }
  };
  walk(base);
  return out;
}

// ── the writer ──────────────────────────────────────────────────────────────

/**
 * Derive, refuse, dedupe, place. The one function the four callers ask for.
 *
 * `{ key, record, root }` is the shape `bot/export-issues.mjs`'s
 * `resolveWriter` documents and `bot/baseline.mjs` calls with; `{ path }` is
 * what it prints. The rest is optional and defaulted, so those two callers
 * work unchanged.
 *
 * **`terminal` is passed in rather than computed.** BOT-36's second clause
 * drops a write when a BOT-19 terminal record already exists, and BOT-19's
 * search lives in `bot/decide.mjs`'s `terminalOnMain` — over the record set,
 * the plugin id, the repository and the tag, none of which a key carries. A
 * second search here would be a second answer to "has this already been
 * decided", which is the same defect as a second id.
 *
 * @param {{key: string, record: object, root?: string, terminal?: object|null,
 *   existing?: {decision_id: string, file: string}[]|null}} opts
 * @returns {{path: string, decision_id: string, key: string, written: boolean, dropped: string|null}}
 */
export function writeDecisionRecord({ key, record, root = REPO_ROOT, terminal = null, existing = null }) {
  const domain = keyDomain(key);
  const decision_id = decisionId(key);

  for (const member of ["schema", "decision_id"]) {
    if (record && Object.prototype.hasOwnProperty.call(record, member)) {
      throw new Error(
        `this record arrived carrying its own \`${member}\`. Stamping the schema and deriving the id are what ` +
        "this module is for: a caller that supplies either has become a second composer, and two composers " +
        "collide silently because both produce 32 hex characters (BOT-35)",
      );
    }
  }

  const composed = { schema: RECORD_SCHEMA, decision_id, ...record };

  if (domain === "service-decision") {
    const { schema, decision_id: _id, ...rest } = composed;
    refuseUncomposableAuthorAction(rest);
    const extra = Object.keys(composed).filter((m) => !AUTHOR_ACTION_MEMBERS.includes(m));
    if (extra.length) {
      throw new Error(`\`${extra.join("`, `")}\` is not one of DEC-7's thirteen author-action members`);
    }
  }

  refusePrivate({ record: composed });

  const rel = recordPath(composed);

  // BOT-36, both clauses.
  if (terminal) {
    return {
      path: rel,
      decision_id,
      key,
      written: false,
      dropped:
        "BOT-19: `main` already carries a terminal record for this work, and a second record saying the same " +
        "thing is a second answer to what the registry decided",
    };
  }
  const already = (existing ?? recordsOnMain(root)).find((r) => r.decision_id === decision_id);
  if (already) {
    return {
      path: already.file,
      decision_id,
      key,
      written: false,
      dropped: `BOT-36: a record carrying this tuple is already at ${already.file}`,
    };
  }

  const full = path.join(root, ...rel.split("/"));
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, stableStringify(composed));
  return { path: rel, decision_id, key, written: true, dropped: null };
}

/**
 * Whether the schema is in this checkout, so a caller and a canary can say so
 * rather than assume either way.
 *
 * It has landed (B-T2.1), and this stays because the question outlived its
 * first answer. `bot/tests/decisions.test.mjs` asserts `present` is TRUE
 * before it validates a record against `full`: without that, deleting or
 * renaming the schema would turn the one assertion that checks a decision
 * record's shape into a read of a file that is not there — and a validator
 * given nothing finds nothing and passes.
 */
export function decisionSchema(root = REPO_ROOT) {
  const file = DECISION_SCHEMA_FILE;
  const full = path.join(root, ...file.split("/"));
  return { present: fs.existsSync(full), file, full };
}

/** DEC-7's twenty-five members, as `tools/lib/priv-rules.mjs` holds them for this writer and the canary. Re-exported so a canary can compare. */
export const DECISION_MEMBERS = Object.freeze([...DOCUMENT_MEMBERS.decision.members]);
