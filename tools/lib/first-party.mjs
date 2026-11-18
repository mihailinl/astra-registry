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
  if (!fs.existsSync(file)) return { ids: new Set(), problems: [], missing: true };
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    return { ids: new Set(), problems: [`${FIRST_PARTY_FILE} cannot be read: ${e.message}`] };
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
    return { ids: new Set(), problems };
  }
  const ids = new Set();
  for (const key of Object.keys(listed)) {
    if (canonicalGithubId(key) === null) problems.push(`github_ids key ${JSON.stringify(key)} is not a canonical numeric id (a login never counts)`);
    else ids.add(key);
  }
  for (const key of Object.keys(doc?.not_first_party ?? {})) {
    if (ids.has(key)) problems.push(`${key} is both first party and named as not first party`);
  }
  return { ids: problems.length ? new Set() : ids, problems };
}

/** Is this numeric id one of Astra's own accounts? */
export function isFirstPartyId(value, ids) {
  const id = canonicalGithubId(value);
  return id !== null && ids instanceof Set && ids.has(id);
}
