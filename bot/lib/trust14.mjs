// TRUST-14's alarm, composed into the verdict the ingest run's alert job sends.
//
//   node bot/lib/trust14.mjs --merge --verdict verdict.json    (ASTRA_DECIDE_ALERTS in env)
//
// Registry plan B-T3.3b. `decide` names every approval and every delayed
// fingerprint past its `publish_after` that lacks a `state/alerts/` record for
// that event, and every disagreement it refused to write anything over
// (BOT-15, BOT-21). This composes those names into the ONE verdict the alert
// job sends, beside what the roots check relayed, so a run pages once. The
// `publish` job then writes the alert record with the `delivered_at` the
// channel reported, and TRUST-32 counts its window from that.
//
// Codes, plugin ids and fingerprints — nothing else reaches the channel
// (`bot/lib/alert-verdict.mjs`'s members). A fingerprint is 16 hex, a length
// the channel renders; a submission id is not among the channel's members and
// is not sent.
//
// This file is in the alert job's sparse checkout, so it imports nothing but
// the verdict grammar it composes against.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

import { verdictProblems } from "./alert-verdict.mjs";

/** The two TRUST-14 events, as channel codes. */
export const TRUST14_CODES = Object.freeze({ approval: "TRUST14_APPROVAL", delay_elapsed: "TRUST14_DELAY_ELAPSED" });

const CODE_RE = /^[A-Z][A-Z0-9_]{0,47}$/;
const FP_RE = /^[0-9a-f]{16}$/;

/**
 * The roots verdict, with `decide`'s names merged in. Red when anything was
 * named; the roots half keeps its own status otherwise.
 *
 * @param {object} verdict what `bot/check-roots.mjs --relay` wrote
 * @param {{trust14?: {fingerprint: string, event: string}[], operator?: {code: string}[]}} alerts
 */
export function mergeAlerts(verdict, alerts = {}) {
  const trust14 = Array.isArray(alerts.trust14) ? alerts.trust14 : [];
  const operator = Array.isArray(alerts.operator) ? alerts.operator : [];
  if (!trust14.length && !operator.length) return verdict;
  const codes = new Set(verdict.codes ?? []);
  const hexes = new Set(verdict.hexes ?? []);
  for (const a of trust14) {
    const code = TRUST14_CODES[a?.event];
    if (!code) throw new Error(`decide named a TRUST-14 event ${JSON.stringify(a?.event)} this composer has no code for`);
    if (!FP_RE.test(String(a.fingerprint))) throw new Error("decide named a TRUST-14 alert without a 16-hex fingerprint");
    codes.add(code);
    hexes.add(a.fingerprint);
  }
  for (const o of operator) {
    if (!CODE_RE.test(String(o?.code))) throw new Error(`decide named an operator alert whose code is not a fixed code: ${JSON.stringify(o?.code)}`);
    codes.add(o.code);
  }
  const merged = { ...verdict, status: "red", codes: [...codes].sort() };
  if (hexes.size) merged.hexes = [...hexes].sort();
  const problems = verdictProblems(merged);
  if (problems.length) throw new Error(`the merged verdict is not one the channel sends: ${problems.join("; ")}`);
  return merged;
}

async function main(argv) {
  let file = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--merge") continue;
    if (argv[i] === "--verdict") file = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (!file) throw new Error("--merge --verdict <file>");
  const raw = String(process.env.ASTRA_DECIDE_ALERTS ?? "").trim();
  const alerts = raw === "" ? {} : JSON.parse(raw);
  const merged = mergeAlerts(JSON.parse(fs.readFileSync(file, "utf8")), alerts);
  fs.writeFileSync(file, `${JSON.stringify(merged, null, 2)}\n`);
  const n = (alerts.trust14 ?? []).length + (alerts.operator ?? []).length;
  console.log(n ? `ok    ${n} alert(s) named by decide merged into the verdict` : "ok    decide named no alert in this run");
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((c) => process.exit(c)).catch((e) => {
    console.error(`::error::${String(e.message ?? e)}`);
    process.exit(1);
  });
}
