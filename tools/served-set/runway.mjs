// How long the trust document has left, and the one alarm that says so early
// enough to be actionable (ROLL-45).
//
// `registry/v1/trust.json` is what delegates to the index key; every client
// that verifies a catalogue or a withdrawal list verifies it under a key this
// document names, and the document carries its own `expires_at`. When it runs
// out there is no degraded mode to fall back on and no fix that is not a root
// ceremony: the operator holds the root key offline, `keygen-root.sh` and
// `sign-trust.mjs` are run by hand, and ROLL-45 fixes a dress rehearsal 45 days
// before the ceremony because that is how long the rehearsal has taken to
// schedule. An alarm that first fires the week the document expires is an
// alarm about an outage rather than about a renewal.
//
// **Why this is a live check and not a selftest case.** Every other row of
// RC-R1-6 is a property of a commit, and CI is the right place to decide those.
// This one is a property of the CALENDAR: the repository can sit untouched for
// a month while the runway runs out, and a check that only runs when somebody
// pushes is a check that is silent exactly when nothing is happening. So it
// runs on `served-set.yml`'s schedule, and reaches a person through the same
// `alert` job the two comparisons beside it use (BOT-46: the job that holds the
// channel's credential runs no author code and reads only what this reported).
//
// **90 days, and nothing here knows about 60.** ROLL-45's own table gives the
// operator a 60-day step; that is a runbook row for a person who has already
// been told. This is the first telling, and it is deliberately the only
// threshold in code — two thresholds in one check is two alarms for one fact,
// and the second one trains the reader to wait for it.

import { finding, minutesSince, verdict } from "./report.mjs";

/** ROLL-45's runway: less than this to expiry and the ceremony is late. */
export const RUNWAY_DAYS = 90;

const DAYS = (minutes) => minutes / (60 * 24);

/**
 * Days from `now` until `when`, or `null` when either instant is unreadable.
 *
 * `null` is not zero and not infinity: an unreadable expiry is itself the
 * fault, and the caller says so rather than choosing a number that excuses it.
 */
export function daysUntil(when, now) {
  const mins = minutesSince(now, when);
  return mins === null ? null : DAYS(mins);
}

/**
 * @param {{documents: {where: string, doc: unknown}[], waiting?: string[], now: string}} o
 */
export function runwayVerdict({ documents, waiting = [], now }) {
  const findings = [];
  const notes = [];

  // A floor on the population, for the reason every set-enumerating check in
  // this repository carries one (ROLL-44): this function's whole answer is a
  // loop, and a loop over nothing is green. A caller that found no trust
  // document at all has not found a healthy estate.
  if (documents.length === 0) {
    return verdict({
      findings: [finding(
        "ROLL_45_NO_TRUST_DOCUMENT",
        "no trust document was read at all, so the runway below was measured on an empty set. " +
        "`registry/v1/trust.json` is committed to `main` and published on `signed`; neither could be read.",
      )],
      waiting,
    });
  }

  for (const { where, doc } of documents) {
    const signed = doc && typeof doc === "object" ? doc.signed : null;
    if (!signed || typeof signed !== "object") {
      findings.push(finding(
        "ROLL_45_TRUST_UNREADABLE",
        `${where} has no \`signed\` member, so nothing can be said about when it expires.`,
      ));
      continue;
    }

    const left = daysUntil(signed.expires_at, now);
    if (left === null) {
      findings.push(finding(
        "ROLL_45_TRUST_UNREADABLE",
        `${where} carries expires_at ${JSON.stringify(signed.expires_at ?? null)}, which is not an instant ` +
        `this check can read. An expiry nothing can measure is an expiry nothing is watching.`,
      ));
    } else if (left < RUNWAY_DAYS) {
      findings.push(finding(
        "ROLL_45_TRUST_EXPIRES_SOON",
        `${where} expires ${signed.expires_at} — ${Math.floor(left)} day(s) from now, inside ROLL-45's ` +
        `${RUNWAY_DAYS}-day runway. Renewal is a root ceremony the operator runs by hand, with a dress ` +
        `rehearsal before it; when this document expires every client that verifies a catalogue under it ` +
        `stops, and there is no degraded mode. Start the ceremony, do not silence this.`,
      ));
    } else {
      notes.push(`${where} expires ${signed.expires_at}, ${Math.floor(left)} days out`);
    }

    // A key's own `not_after` is the same ceremony by another name, and
    // ROLL-45 is the commit that gives `astra-index-2026a` one. Without this
    // line, adding the field the requirement asks for would quietly narrow
    // what is watched: the document would still say 2027-08-19 while the key
    // signing under it went dead months earlier.
    for (const key of Array.isArray(signed.index_keys) ? signed.index_keys : []) {
      if (!key || key.not_after === undefined) continue;
      const keyLeft = daysUntil(key.not_after, now);
      if (keyLeft === null) {
        findings.push(finding(
          "ROLL_45_TRUST_UNREADABLE",
          `${where}: index key ${String(key.key_id)} carries not_after ${JSON.stringify(key.not_after)}, ` +
          `which is not an instant this check can read.`,
        ));
      } else if (keyLeft < RUNWAY_DAYS) {
        findings.push(finding(
          "ROLL_45_INDEX_KEY_EXPIRES_SOON",
          `${where}: index key ${String(key.key_id)} stops being usable at ${key.not_after} — ` +
          `${Math.floor(keyLeft)} day(s) from now, inside ROLL-45's ${RUNWAY_DAYS}-day runway. The catalogue ` +
          `is signed with this key; a successor has to be delegated before it lapses.`,
        ));
      } else {
        notes.push(`${where}: index key ${String(key.key_id)} usable until ${key.not_after}`);
      }
    }
  }

  return verdict({ findings, waiting, notes });
}
