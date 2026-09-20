#!/usr/bin/env node
// Does the published root.json still say what the bot has compiled in?
//
//     node bot/check-roots.mjs                      check, and print why not
//     node bot/check-roots.mjs --relay --out v.json compose the alert job's verdict
//
// Two modes and no others. The check mode writes its verdict to
// `$GITHUB_OUTPUT` and the `alert` job of `ingest.yml` sends what it finds
// there; the relay mode is that job's half. A `--roots <file>` flag was
// written here and taken out again before it was committed — the same commit
// removes one from `bot/ingest.mjs`, where it let a command line choose the
// bot's anchor, and two flags of one name meaning two different things is how
// the wrong one gets reached for. `checkRoots({rootsFile})` is the seam the
// tests use.
//
// `bot/lib/roots.mjs` holds the root keys `bot/ingest.mjs` verifies a
// `trust.json` under, and it holds them as code precisely so that editing
// `registry/v1/root.json` cannot move the bot's anchor. That leaves one thing
// worth watching, and it is the thing nothing else would notice: the two
// drifting apart.
//
// Both directions matter and they fail differently.
//
//   * A key published in root.json that the bot does not hold tells every
//     third party — and the ceremony's own audit trail — that a key is a root
//     of this registry, while the verifier that guards the catalogue has never
//     heard of it. Whoever added it believes they rotated a root; they did
//     not, and they will find out when a trust.json signed by it is refused,
//     which is after the ceremony, with the key out of its envelope.
//   * A key the bot holds and root.json does not is SERVE-92's step 1 and is
//     correct for exactly as long as the rotation takes.
//
// So the two shapes get different treatment: a superset in the compiled
// direction is REPORTED, and everything else is an ALARM. See
// `rootFileProblems()` for why a key whose value changed is never a rotation.
//
// **This posts no BOT-85 heartbeat and the job that calls it says why.**
// `ingest.yml` runs on BOT-51's schedule, which is deliberately outside
// BOT-85's dead-man list because the plugins service's BOT-47 watches it; a
// heartbeat from here would be posting to a receiver check nobody created.
// The verdict's `check` member is therefore `ingest-roots`, which is the
// subject of the alarm and NOT a receiver check name — `bot/lib/alert-checks.mjs`
// does not list it, and nothing should create it there.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { VERDICT_SCHEMA, runUrl, verdictProblems } from "./lib/alert-verdict.mjs";
import { COMPILED_ROOTS, ROOT_CODES, compiledSetProblems, rootFileProblems } from "./lib/roots.mjs";

const REPO_ROOT = path.resolve(import.meta.dirname, "..");

/** The subject of this alarm. Not a receiver check; see the header. */
export const VERDICT_CHECK = "ingest-roots";

/**
 * What a relayed verdict is replaced by when there is none.
 *
 * The `roots` job writes its verdict to a job output and the `alert` job sends
 * what it finds there. An empty output is the case that has to be loud: the
 * check job died before it could report, which is indistinguishable from the
 * check job having nothing to say if the alert job simply sends nothing. It is
 * also the shape every "the alarm was never wired up" defect takes.
 */
export const NO_REPORT_CODE = "E_ROOT_CHECK_DID_NOT_REPORT";

/**
 * Run the check.
 *
 * @param {{rootsFile?: string, env?: object}} opts
 * @returns {{ok: boolean, verdict: object, problems: string[], expected: string[]}}
 */
export function checkRoots({ rootsFile = path.join(REPO_ROOT, "registry", "v1", "root.json"), env = process.env } = {}) {
  const codes = new Set();
  const problems = [];
  const expected = [];
  let hexes = COMPILED_ROOTS.map((r) => r.fingerprint_sha256);

  // Asked first, and about this file alone. A comparison between a corrupted
  // table and a file can agree, and would then report that all is well about
  // a key nobody can verify anything with.
  const corrupt = compiledSetProblems();
  if (corrupt.length) {
    codes.add(ROOT_CODES.CORRUPT);
    problems.push(...corrupt);
  }

  let doc = null;
  try {
    doc = JSON.parse(fs.readFileSync(rootsFile, "utf8"));
  } catch (e) {
    codes.add(ROOT_CODES.UNREADABLE);
    problems.push(
      `${rootsFile} could not be read as JSON (${String(e.message ?? e)}). The bot still has its roots — they ` +
      `are compiled in — but the document a third party reads them out of is gone, and nothing else looks at it.`,
    );
  }

  if (doc !== null) {
    const verdict = rootFileProblems(doc);
    if (verdict.problems.length) codes.add(ROOT_CODES.DIVERGED);
    problems.push(...verdict.problems);
    expected.push(...verdict.expected);
    if (verdict.fingerprints.length) hexes = verdict.fingerprints;
  }

  const ok = problems.length === 0;
  const verdict = {
    schema: VERDICT_SCHEMA,
    check: VERDICT_CHECK,
    status: ok ? "green" : "red",
    ...(codes.size ? { codes: [...codes] } : {}),
    // The fingerprints of the keys this bot holds, so the alarm says WHICH set
    // the reader should be looking at without carrying a public key into a
    // Telegram message.
    hexes,
    ...(runUrl(env) ? { run: runUrl(env) } : {}),
  };
  return { ok, verdict, problems, expected };
}

/**
 * The alert job's verdict, out of what the check job relayed.
 *
 * Grammar-checked here rather than only by `bot/alert.mjs`, because the two
 * failures are different: alert.mjs refusing an ungrammatical verdict is a red
 * job with nothing sent, and that is the right answer for a verdict somebody
 * composed wrongly — but it is the WRONG answer for an absent one, which is
 * the check job having died. An absent verdict becomes a red alarm saying so.
 *
 * @param {string|undefined} relayed the raw job output
 * @returns {object} a verdict `bot/alert.mjs` will carry
 */
export function relayVerdict(relayed) {
  const fallback = {
    schema: VERDICT_SCHEMA,
    check: VERDICT_CHECK,
    status: "red",
    codes: [NO_REPORT_CODE],
  };
  if (typeof relayed !== "string" || relayed.trim() === "") return fallback;
  let parsed;
  try {
    parsed = JSON.parse(relayed);
  } catch {
    return fallback;
  }
  return verdictProblems(parsed).length ? fallback : parsed;
}

function parseArgs(argv) {
  const args = { relay: false, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--relay") args.relay = true;
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

function main(argv) {
  const args = parseArgs(argv);

  // The alert job's half. It composes a file and exits 0: whether an alarm
  // goes out is `bot/alert.mjs --if-red`'s decision, out of the verdict's own
  // status, and a non-zero exit here would fail the step before it could send.
  if (args.relay) {
    if (!args.out) {
      console.error("FAIL  --relay needs --out <file>");
      return 1;
    }
    const verdict = relayVerdict(process.env.ASTRA_ROOTS_VERDICT);
    fs.writeFileSync(args.out, `${JSON.stringify(verdict, null, 2)}\n`);
    if (verdict.codes?.includes(NO_REPORT_CODE)) {
      console.error(
        "FAIL  the roots job relayed no usable verdict, so this job is sending one that says so. The check " +
        "either did not run or died before it wrote its output; either way the alarm is the absence.",
      );
    } else {
      console.log(`ok    relaying the roots job's ${verdict.status} verdict`);
    }
    return 0;
  }

  const out = checkRoots();

  for (const line of out.expected) console.log(`note  ${line}`);
  for (const line of out.problems) console.error(`FAIL  ${line}`);
  if (out.ok) {
    console.log(
      `ok    registry/v1/root.json publishes the ${COMPILED_ROOTS.length} root key(s) bot/lib/roots.mjs ` +
      `compiles in: ${COMPILED_ROOTS.map((r) => r.key_id).join(", ")}`,
    );
  }

  // The output is written BEFORE the non-zero exit, and that order is the
  // point: the alert job sends what it finds here, so a check that failed and
  // reported nothing would be a check whose failure is silent.
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(
      process.env.GITHUB_OUTPUT,
      `status=${out.verdict.status}\nverdict=${JSON.stringify(out.verdict)}\n`,
    );
  }
  return out.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
