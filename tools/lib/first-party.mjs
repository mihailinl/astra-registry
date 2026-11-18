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
