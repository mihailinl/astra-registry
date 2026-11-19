// Astra's own GitHub accounts, by numeric id (policy/first-party.json, contract
// 6.32.0). The one reader of that file: `tools/build-index.mjs` grants the
// `astra_team` tier from it, `tools/validate.mjs` refuses a record claiming
// that tier for any other id, and `bot/lib/service-decide.mjs` skips MIG-10's
// `R_FIRST_BINDING` hold for a repository owner in it.
//
// Never a login. A login is a name its holder can give away; a numeric id is
// never reissued. `isFirstPartyId` therefore takes only §0.7's canonical
// base-10 string (or a safe integer, as the catalogue's `github_id` is), and a
// login, an empty value or a number written with a leading zero is not first
// party, whatever account it may name.

import fs from "node:fs";
import path from "node:path";

export const FIRST_PARTY_FILE = "policy/first-party.json";
export const FIRST_PARTY_SCHEMA = "astra.registry.first-party/1";
const ID_RE = /^[1-9][0-9]{0,19}$/;

/** The canonical base-10 string of a GitHub numeric id, or null for anything else. */
export function canonicalGithubId(value) {
  if (typeof value === "number") return Number.isSafeInteger(value) && value > 0 ? String(value) : null;
  return typeof value === "string" && ID_RE.test(value) ? value : null;
}

/**
 * The first-party ids, as a frozen Set of canonical strings. A file that is
 * missing or malformed is an EMPTY set — fail closed: no tier is granted and
 * no hold is skipped — and `problems` says why, for the validator to report.
 *
 * @returns {{ids: Set<string>, problems: string[]}}
 */
export function loadFirstParty(root) {
  const file = path.join(root, FIRST_PARTY_FILE);
  // A tree with no file has no first party: nothing is granted, nothing is
  // skipped, and nothing else changes (a fixture tree is one). The registry's
  // own tree carries the file, and tools/validate.mjs says so when it does not.
  if (!fs.existsSync(file)) return { ids: new Set(), logins: new Map(), problems: [], missing: true };
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    return { ids: new Set(), logins: new Map(), problems: [`${FIRST_PARTY_FILE} cannot be read: ${e.message}`] };
  }
  return firstPartyFrom(doc);
}

/** `loadFirstParty` over a parsed document. */
export function firstPartyFrom(doc) {
  const problems = [];
  if (doc?.schema !== FIRST_PARTY_SCHEMA) problems.push(`schema is ${JSON.stringify(doc?.schema)}, not ${FIRST_PARTY_SCHEMA}`);
  const listed = doc?.github_ids;
  if (listed === null || typeof listed !== "object" || Array.isArray(listed)) {
    problems.push("github_ids is not an object keyed by numeric id");
    return { ids: new Set(), logins: new Map(), problems };
  }
  const ids = new Set();
  const logins = new Map();
  for (const [key, value] of Object.entries(listed)) {
    if (canonicalGithubId(key) === null) { problems.push(`github_ids key ${JSON.stringify(key)} is not a canonical numeric id (a login never counts)`); continue; }
    if (!value || typeof value.login !== "string" || !LOGIN_RE.test(value.login)) { problems.push(`github_ids.${key} names no login`); continue; }
    ids.add(key);
    logins.set(key, value.login);
  }
  for (const key of Object.keys(doc?.not_first_party ?? {})) {
    if (ids.has(key)) problems.push(`${key} is both first party and named as not first party`);
  }
  return problems.length ? { ids: new Set(), logins: new Map(), problems } : { ids, logins, problems };
}

const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

/**
 * A publisher record's claims on first-party ids that are NOT its own
 * (review of #512, H2). `owner_ids` is typed by whoever writes the record, so
 * an entry mapping a login to a first-party id is honoured only when the
 * policy names that very login for the id, compared case-insensitively.
 *
 * @returns {string[]} one line per false claim; empty when there is none
 */
export function firstPartyClaimProblems(doc, firstParty) {
  const ids = doc?.owner_ids;
  if (!firstParty?.logins || ids === null || typeof ids !== "object" || Array.isArray(ids)) return [];
  const out = [];
  for (const [login, value] of Object.entries(ids)) {
    const id = canonicalGithubId(value);
    if (id === null || !firstParty.ids.has(id)) continue;
    const expected = firstParty.logins.get(id);
    if (String(login).toLowerCase() !== String(expected).toLowerCase()) {
      out.push(`owner_ids maps ${JSON.stringify(login)} to ${id}, which is ${expected}'s first-party id`);
    }
  }
  return out;
}

/**
 * Is this record Astra's own, by id and login together: its owner and every
 * `covers` login each map, in `owner_ids`, to a first-party id the policy
 * names for exactly that login, and it claims no other first-party id?
 */
export function isFirstPartyRecord(doc, firstParty, ownerIdOf) {
  if (!firstParty?.logins) return false;
  if (firstPartyClaimProblems(doc, firstParty).length) return false;
  const logins = [doc?.owner, ...(Array.isArray(doc?.covers) ? doc.covers : [])];
  return logins.every((login) => {
    const id = ownerIdOf(doc, login);
    return isFirstPartyId(id, firstParty.ids) && String(firstParty.logins.get(id)).toLowerCase() === String(login).toLowerCase();
  });
}

/** Is this numeric id one of Astra's own accounts? */
export function isFirstPartyId(value, ids) {
  if (ids && !(ids instanceof Set) && ids.ids instanceof Set) ids = ids.ids;
  const id = canonicalGithubId(value);
  return id !== null && ids instanceof Set && ids.has(id);
}

// ── a rename inside one first-party account (owner, 2026-11-19) ────────────
//
// ONE predicate, read by both sides that must agree: bot/lib/service-decide.mjs,
// which publishes such a rename without an `R_IDENTITY_CHANGED` hold, and
// tools/validate.mjs, which then accepts the versions it left under the old
// name. Two spellings drifted once already (review of #521, finding 1: the
// decide side let through renames validate refused, and the publication failed
// the whole run), so neither side has its own.

const ownerLogin = (repo) => {
  const owner = String(repo ?? "").split("/")[0];
  return owner === "" ? null : owner.toLowerCase();
};

/**
 * Is `to` the repository `from` was, renamed inside the same first-party
 * account? Both numeric ids equal (one repository, TRUST-23), the owner id in
 * policy/first-party.json, and the same owner LOGIN on both names. An
 * organisation rename keeps the ids and changes the login: it frees the old
 * login (KNICE-TECH, by the rename to MINICE-AI) for anybody to register and
 * serve bytes under every old URL, so it stays a held change of hands.
 *
 * @param {{from: {repo: string, repository_id: unknown, repository_owner_id: unknown},
 *   to: {repo: string, repository_id: unknown, repository_owner_id: unknown}, firstParty: Set<string>|null}} opts
 */
export function sameAccountRename({ from, to, firstParty }) {
  if (!from || !to || !(firstParty instanceof Set)) return false;
  const rid = canonicalGithubId(String(from.repository_id ?? ""));
  const oid = canonicalGithubId(String(from.repository_owner_id ?? ""));
  if (rid === null || oid === null) return false;
  if (String(to.repository_id ?? "") !== rid || String(to.repository_owner_id ?? "") !== oid) return false;
  if (!isFirstPartyId(oid, firstParty)) return false;
  const login = ownerLogin(from.repo);
  return login !== null && login === ownerLogin(to.repo);
}

/**
 * Does a published version stand under the listing's `sourceRepo` although its
 * `release.repo` is another name? Yes when it is yanked, when the names are the
 * same, or when a `published` decision record of that version names its
 * `release.repo` with ids that `sameAccountRename` makes the listing's own
 * (`identity`: the listing's identity record).
 *
 * @param {{pluginId: string, version: object, identity: object|null, sourceRepo: string,
 *   records: object[], firstParty: Set<string>|null}} opts `records` are decision record documents
 */
export function versionStandsUnderSource({ pluginId, version, identity, sourceRepo, records, firstParty }) {
  const repo = version?.release?.repo;
  if (version?.yanked === true || typeof repo !== "string" || repo === sourceRepo) return true;
  if (!identity) return false;
  const to = { repo: sourceRepo, repository_id: identity.repository_id, repository_owner_id: identity.repository_owner_id };
  return (records ?? []).some((r) => r?.state === "published" && r.plugin_id === pluginId && r.version === version.version
    && r.repo === repo && sameAccountRename({ from: r, to, firstParty }));
}
