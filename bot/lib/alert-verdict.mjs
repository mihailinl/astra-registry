// What may reach the alarm channel, and the message built from it.
//
// BOT-46's channel is the one path this estate has to a person, and the jobs
// that post to it run over bytes a stranger chose: a plugin's id, a release's
// tag, a detector's finding about a submitted listing. So the message is not
// composed by the job. The job writes a VERDICT — a small document of fixed
// codes, hex digests, plugin ids and one run URL — and this module refuses
// anything else and renders what is left. A free-text field would be a
// stranger writing into the owner's Telegram, and a stranger writing into the
// alarm channel is a stranger who can bury the alarm underneath it.
//
// **Unknown members are refused, not ignored, and that is the opposite of the
// rule for cross-party documents.** SCOPE-3 makes readers ignore members they
// do not know because the other party may add an optional one in a MINOR and
// neither side may break (attack M-1 is what happens when that rule is missed).
// Nothing here crosses a party line: this document is written and read inside
// this repository, in the same commit range, so there is no MINOR to survive.
// What there is instead is a member somebody added expecting an operator to
// see it — and ignoring that member means the operator never does, in the one
// message whose whole job is to be read. Refusing it turns that into a red run
// in CI, where its author is standing.

import { invalidId } from "../../tools/lib/ids.mjs";

export const VERDICT_SCHEMA = "astra.registry.alert-verdict/1";

/** Fixed codes: `SERVE_85_DRIFT`, `E_ATTESTATION_INVALID`, `A1`. Never a sentence. */
export const CODE_PATTERN = "^[A-Z][A-Z0-9_]{0,47}$";
const CODE_RE = new RegExp(CODE_PATTERN);

// §0.7's three hex lengths, and all three are needed. RC-R1-0's own text says
// "40-hex SHAs", which is the commit; but TRUST-14's alert names a FINGERPRINT,
// which §0.7 fixes at 16, and an artifact digest is 64. A grammar that took 40
// alone would refuse the first alert TRUST-14 asks for.
const HEX_LENGTHS = [16, 40, 64];
const HEX_RE = /^[0-9a-f]+$/;

// A run URL on github.com and nothing else. `${{ github.server_url }}` is a
// workflow-controlled string and this is the check that it did not become a
// link to somewhere else in a message the owner is being asked to click.
export const RUN_URL_PATTERN =
  "^https://github\\.com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/actions/runs/[0-9]{1,20}(?:/job/[0-9]{1,20})?$";
const RUN_URL_RE = new RegExp(RUN_URL_PATTERN);

const CHECK_NAME_RE = /^[a-z][a-z0-9-]{1,38}[a-z0-9]$/;

const MEMBERS = ["schema", "check", "status", "codes", "ids", "hexes", "run"];
const REQUIRED = ["schema", "check", "status"];

const MAX_ELEMENTS = 40;

/**
 * @param {unknown} verdict
 * @returns {string[]} the reasons it may not be sent; empty means it may
 */
export function verdictProblems(verdict) {
  const problems = [];
  if (verdict === null || typeof verdict !== "object" || Array.isArray(verdict)) {
    return ["the verdict is not a JSON object"];
  }
  for (const key of Object.keys(verdict)) {
    if (!MEMBERS.includes(key)) {
      problems.push(
        `member ${JSON.stringify(key)} is not one this channel renders (${MEMBERS.join(", ")}); ` +
        `an unrendered member is a member the operator never sees`,
      );
    }
  }
  for (const key of REQUIRED) {
    if (verdict[key] === undefined) problems.push(`member ${JSON.stringify(key)} is missing`);
  }
  if (verdict.schema !== undefined && verdict.schema !== VERDICT_SCHEMA) {
    problems.push(`schema is ${JSON.stringify(verdict.schema)} and not ${JSON.stringify(VERDICT_SCHEMA)}`);
  }
  if (verdict.check !== undefined && (typeof verdict.check !== "string" || !CHECK_NAME_RE.test(verdict.check))) {
    problems.push(`check ${JSON.stringify(verdict.check)} is not a receiver check name`);
  }
  if (verdict.status !== undefined && verdict.status !== "red" && verdict.status !== "green") {
    problems.push(`status ${JSON.stringify(verdict.status)} is neither "red" nor "green"`);
  }
  const list = (key, describe) => {
    const value = verdict[key];
    if (value === undefined) return [];
    if (!Array.isArray(value)) {
      problems.push(`${key} is not an array`);
      return [];
    }
    if (value.length > MAX_ELEMENTS) {
      // A detector that found two thousand things must say so in a count and a
      // run URL, not by pasting two thousand ids into a Telegram message that
      // the API will truncate at 4096 bytes anyway — silently, in the middle.
      problems.push(`${key} carries ${value.length} entries, over the ${MAX_ELEMENTS} this channel will send`);
      return [];
    }
    for (const entry of value) {
      const why = describe(entry);
      if (why) problems.push(`${key}: ${JSON.stringify(entry)} ${why}`);
    }
    return value;
  };
  list("codes", (c) => (typeof c === "string" && CODE_RE.test(c) ? null : `is not a fixed code (${CODE_PATTERN})`));
  list("ids", (id) => {
    if (typeof id !== "string") return "is not a string";
    const why = invalidId(id);
    return why ? `is not a plugin id: ${why}` : null;
  });
  list("hexes", (h) => {
    if (typeof h !== "string" || !HEX_RE.test(h)) return "is not lowercase hex";
    return HEX_LENGTHS.includes(h.length) ? null : `is ${h.length} hex characters and not ${HEX_LENGTHS.join(", ")}`;
  });
  if (verdict.run !== undefined && (typeof verdict.run !== "string" || !RUN_URL_RE.test(verdict.run))) {
    problems.push(`run ${JSON.stringify(verdict.run)} is not a github.com Actions run URL`);
  }
  return problems;
}

/**
 * The message, built only from what passed above.
 *
 * Plain text: no `parse_mode`, so the Bot API applies no markup and there is no
 * entity for a value to escape out of. Every line is `key: value`, so the same
 * alarm always looks the same and a reader notices the line that is new.
 *
 * @param {object} verdict
 * @param {string} [ackUrl] the acknowledgement link, which comes from the
 *   receiver's own secret and never from the verdict
 */
export function renderVerdict(verdict, ackUrl) {
  const problems = verdictProblems(verdict);
  if (problems.length) {
    throw new Error(`refusing to render a verdict this channel will not carry:\n  - ${problems.join("\n  - ")}`);
  }
  const lines = [
    verdict.status === "red" ? "ASTRA REGISTRY ALARM" : "ASTRA REGISTRY",
    `check: ${verdict.check}`,
    `status: ${verdict.status}`,
  ];
  if (verdict.codes?.length) lines.push(`codes: ${verdict.codes.join(" ")}`);
  if (verdict.ids?.length) lines.push(`ids: ${verdict.ids.join(" ")}`);
  if (verdict.hexes?.length) lines.push(`hex: ${verdict.hexes.join(" ")}`);
  if (verdict.run) lines.push(`run: ${verdict.run}`);
  if (ackUrl) lines.push(`acknowledge: ${ackUrl}`);
  return lines.join("\n");
}

/**
 * The run URL of the run this is executing in, or null.
 *
 * Read from the environment and then put through the same grammar as a
 * verdict's own `run`, because `GITHUB_SERVER_URL` is a value a workflow can
 * set and this is the one place that notices.
 */
export function runUrl(env = process.env) {
  const { GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID } = env;
  if (!GITHUB_SERVER_URL || !GITHUB_REPOSITORY || !GITHUB_RUN_ID) return null;
  const url = `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}`;
  return RUN_URL_RE.test(url) ? url : null;
}
