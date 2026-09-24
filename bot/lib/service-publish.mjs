// `plugins-ingest.yml`'s `publish` job: compose every record this run
// produced into report directories `bot/publish-apply.mjs` applies as ONE
// commit, then compose the results `report` posts (registry plan B-T3.4,
// B-T3.5; BOT-33, BOT-34, BOT-36, BOT-38, BOT-73, BOT-92, TRUST-14, TRUST-32).
//
//   node bot/lib/service-publish.mjs --compose  --decisions decisions --listings listings \
//                                    --reports reports --results results/pending.json
//   node bot/lib/service-publish.mjs --finalize --results results/pending.json \
//                                    --applied applied.json --out results/results.json
//
// The job holds `contents: write` and therefore no bot token (BOT-2). Its
// inputs are the `decisions` artifact from the job that holds nothing, the
// listing artifacts by exact name (BOT-56), the alert job's `delivered_at`,
// and `main`.
//
// ── one writer of a decision id ─────────────────────────────────────────────
//
// Every record goes through `bot/lib/decisions.mjs`'s `writeDecisionRecord`,
// which stamps `schema`, derives `decision_id` over BOT-35's tuple and refuses
// under PRIV-2 — written into the REPORT directory, deduped against `main`
// (BOT-36). A record that is already on `main` is not written again, and the
// result names the one that is there and the commit that holds it.
//
// ── nothing for shadow ──────────────────────────────────────────────────────
//
// A plan a `shadow: true` answer named arrives here as kind `none` with
// `shadow: true` (`bot/lib/service-decide.mjs` empties it), so no record, no
// queue entry, no identity record, no listing file and no result is composed
// for it (BOT-92). The commits no service answer drives stay outside that rule
// — B-T3.7b's `migration` records and the legacy path — and neither passes
// through this file.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { recordsOnMain, submissionKey, trailerLine, writeDecisionRecord } from "./decisions.mjs";
import { OPERATOR_WINDOW_HOURS } from "./service-decide.mjs";
import { recordAgreement, resultBody } from "./service-results.mjs";
import { stableStringify } from "../../tools/lib/canonical.mjs";
import { cleanEnv } from "../../tools/lib/git-env.mjs";
import { isTime } from "../../tools/lib/time.mjs";

/** `astra.registry.alert/1` (registry-only; TRUST-14's record). */
export const ALERT_SCHEMA = "astra.registry.alert/1";
/** Its members, exactly (registry plan B-T3.3b). */
export const ALERT_MEMBERS = Object.freeze(["schema", "fingerprint", "event", "approval_decided_at", "delivered_at", "run"]);

const RUN_RE = /^[0-9]{1,20}(?:\/[0-9]{1,5})?$/;
const PRESENTATION = /^(README\.md|icon\.(png|webp|svg|jpg|jpeg|ico))$/;

/**
 * Everything wrong with one alert record. Registry-only: no other party reads
 * it, and it is held to its members here and in `tools/validate.mjs` because
 * the schema file that would carry it is an entry of TRUST-31's enumerated
 * set, which a contract version publishes first.
 */
export function alertProblems(doc) {
  const p = [];
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return ["not an object"];
  for (const k of Object.keys(doc)) if (!ALERT_MEMBERS.includes(k)) p.push(`an unnamed member \`${k}\``);
  if (doc.schema !== ALERT_SCHEMA) p.push(`schema ${JSON.stringify(doc.schema)}`);
  if (!/^[0-9a-f]{16}$/.test(String(doc.fingerprint))) p.push("fingerprint");
  if (!["approval", "delay_elapsed"].includes(doc.event)) p.push("event");
  if (doc.event === "approval" ? !isTime(doc.approval_decided_at) : doc.approval_decided_at !== null) p.push("approval_decided_at");
  if (!isTime(doc.delivered_at)) p.push("delivered_at");
  if (!RUN_RE.test(String(doc.run))) p.push("run");
  return p;
}

const git = (root, args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8", env: cleanEnv() }).trim();

/** The commit on `main` that added a file, or null (the result of a record found already there). */
function commitAdding(root, rel) {
  try {
    const out = git(root, ["log", "--diff-filter=A", "--format=%H", "-1", "--", rel]);
    return /^[0-9a-f]{40}$/.test(out) ? out : null;
  } catch {
    return null;
  }
}

/**
 * Compose the report directories and the pending results.
 *
 * @param {{plans: object[], root: string, listingsDir: string, reportsDir: string,
 *   deliveredAt?: string|null, run: string}} opts
 * @returns {{pending: object[], reports: string[]}}
 */
export function composePublication({ plans, root, listingsDir, reportsDir, deliveredAt = null, run }) {
  if (!RUN_RE.test(String(run))) throw new Error(`--run ${JSON.stringify(run)} is not §0.7's run_id[/run_attempt]`);
  const existing = recordsOnMain(root);
  const pending = [];
  const reports = [];
  let n = 0;

  for (const plan of plans) {
    if (plan.shadow === true || plan.kind === "none") continue;
    const dir = path.join(reportsDir, `report-${n++}`);
    fs.mkdirSync(dir, { recursive: true });
    const landed = { decisionId: null, mainCommit: null, deliveredAt, recordPath: null, written: false };

    if (plan.kind === "state") {
      const { record } = plan;
      const out = writeDecisionRecord({
        key: submissionKey({ submission_id: record.submission_id, fingerprint: record.fingerprint ?? null, state: record.state }),
        record: { ...record, run },
        root: dir,
        existing,
      });
      landed.decisionId = out.decision_id;
      landed.recordPath = out.path;
      landed.written = out.written;
      if (!out.written) {
        // BOT-36: the record is already on `main`. The result names it and the
        // commit that added it, and nothing else of this plan is written: the
        // decision it records was made, and applied, by an earlier run.
        landed.mainCommit = commitAdding(root, out.path);
      } else {
        if (plan.queue_entry) {
          const entry = { ...plan.queue_entry, decision_id: out.decision_id };
          const rel = path.join("state", "queue", `${entry.id}@${entry.version}.json`);
          fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true });
          fs.writeFileSync(path.join(dir, rel), `${JSON.stringify(entry, null, 2)}\n`);
        }
        if (plan.listing) {
          const id = plan.listing.plugin.id;
          const pdir = path.join(dir, "plugins", id);
          fs.mkdirSync(path.join(pdir, "versions"), { recursive: true });
          fs.writeFileSync(path.join(pdir, "plugin.json"), `${JSON.stringify(plan.listing.plugin, null, 2)}\n`);
          fs.writeFileSync(path.join(pdir, "versions", `${plan.listing.version.version}.json`), `${JSON.stringify(plan.listing.version, null, 2)}\n`);
          // The card's pictures and README, as the check job derived them.
          // Only the presentation files: the JSON documents above are the
          // ones whose identity members `verify` overwrote (BOT-21).
          const src = path.join(listingsDir, "plugins", id);
          if (fs.existsSync(src)) {
            for (const name of fs.readdirSync(src)) {
              if (PRESENTATION.test(name)) fs.copyFileSync(path.join(src, name), path.join(pdir, name));
            }
          }
        }
        for (const { plugin_id: id, record: ident } of plan.identity_records ?? []) {
          const idir = path.join(dir, "plugins", id);
          fs.mkdirSync(idir, { recursive: true });
          fs.writeFileSync(path.join(idir, "identity.json"), `${JSON.stringify(ident, null, 2)}\n`);
        }
        if (plan.drop_queue && plan.derived) {
          const rel = `state/queue/${plan.derived.plugin_id}@${plan.derived.version}.json`;
          if (fs.existsSync(path.join(root, rel))) fs.writeFileSync(path.join(dir, "remove.txt"), `${rel}\n`);
        }
      }
    }

    if (plan.kind === "wait" && plan.alert && isTime(deliveredAt)) {
      // TRUST-14: the alert went out in this run and the channel reported
      // delivery, so the record TRUST-32's window counts from lands in this
      // run's commit (BOT-73).
      const doc = {
        schema: ALERT_SCHEMA,
        fingerprint: plan.alert.fingerprint,
        event: plan.alert.event,
        approval_decided_at: plan.alert.event === "approval" ? plan.alert.approval_decided_at : null,
        delivered_at: deliveredAt,
        run,
      };
      const problems = alertProblems(doc);
      if (problems.length) throw new Error(`an alert record this run composed is malformed: ${problems.join(", ")}`);
      const rel = path.join("state", "alerts", `${doc.fingerprint}.json`);
      fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), stableStringify(doc));
    }

    const body = resultBody(plan, { decisionId: landed.decisionId, mainCommit: landed.mainCommit, deliveredAt });
    if (plan.kind === "state") {
      const problems = recordAgreement(body, { ...plan.record, decision_id: landed.decisionId });
      if (problems.length) throw new Error(`BOT-23: ${plan.submission_id}'s result disagrees with its record: ${problems.join("; ")}`);
    }
    pending.push({
      submission_id: plan.submission_id,
      kind: plan.kind === "state" ? plan.state : plan.kind,
      report: path.basename(dir),
      record_path: landed.recordPath,
      // A result whose record is new names a commit this run has not made yet.
      needs_commit: plan.kind === "state" && landed.written,
      shadow: false,
      body,
    });
    reports.push(dir);
  }
  return { pending, reports };
}

/**
 * BOT-37's trailer block for the run's one commit: `Run:`, then a
 * `Submission:` and a `Decision:` for every record this commit adds. Every
 * line goes through `trailerLine`, the one place a trailer name becomes a
 * line and its value is held to the grammar that keeps a login out of it.
 */
export function commitTrailers({ pending, run }) {
  const lines = [trailerLine("Run", run)];
  for (const r of pending) {
    if (!r.needs_commit) continue;
    lines.push(trailerLine("Submission", r.submission_id));
    if (r.body?.decision_id) lines.push(trailerLine("Decision", r.body.decision_id));
  }
  return lines.join("\n");
}

/**
 * Finish the results once `publish-apply` has run: name the commit, and hold
 * back what cannot be posted.
 *
 * `applied` is what publish-apply reported: its outcome, the reports it
 * refused, and whether it pushed. A result for a refused report is not posted
 * — its record never landed, and a result naming a record that is not on
 * `main` is the lost publish BOT-6 exists to prevent. Under `DRY_RUN` nothing
 * was pushed, so a result naming this run's commit is held back too.
 */
export function finalizeResults({ pending, applied, mainCommit }) {
  const refused = new Set((applied?.refused ?? []).filter(Boolean));
  const pushed = applied?.pushed === true && applied?.outcome === "committed";
  return pending.map((r) => {
    if (refused.has(r.report)) return { ...r, unposted: "refused" };
    if (!r.needs_commit) return { ...r, unposted: null };
    if (!pushed) return { ...r, unposted: applied?.dry_run ? "dry_run" : "not_committed" };
    if (!/^[0-9a-f]{40}$/.test(String(mainCommit))) return { ...r, unposted: "no_commit" };
    return { ...r, unposted: null, body: { ...r.body, main_commit: mainCommit } };
  });
}

// ── CLI ─────────────────────────────────────────────────────────────────────

async function main(argv) {
  const args = { mode: null, root: process.cwd(), decisions: "decisions", listings: "listings", reports: "reports", results: null, applied: null, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--compose") args.mode = "compose";
    else if (a === "--finalize") args.mode = "finalize";
    else if (a === "--registry-dir") args.root = path.resolve(argv[++i]);
    else if (a === "--decisions") args.decisions = path.resolve(argv[++i]);
    else if (a === "--listings") args.listings = path.resolve(argv[++i]);
    else if (a === "--reports") args.reports = path.resolve(argv[++i]);
    else if (a === "--results") args.results = path.resolve(argv[++i]);
    else if (a === "--applied") args.applied = path.resolve(argv[++i]);
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${a}`);
  }
  if (args.mode === "compose") {
    const { plans } = JSON.parse(fs.readFileSync(path.join(args.decisions, "plan.json"), "utf8"));
    const delivered = String(process.env.ASTRA_DELIVERED_AT ?? "").trim();
    const run = `${process.env.GITHUB_RUN_ID}/${process.env.GITHUB_RUN_ATTEMPT ?? "1"}`;
    const { pending, reports } = composePublication({
      plans, root: args.root, listingsDir: args.listings, reportsDir: args.reports,
      deliveredAt: isTime(delivered) ? delivered : null, run,
    });
    fs.mkdirSync(path.dirname(args.results), { recursive: true });
    fs.writeFileSync(args.results, `${JSON.stringify({ pending }, null, 2)}\n`);
    fs.writeFileSync(path.join(path.dirname(args.results), "trailer.txt"), `${commitTrailers({ pending, run })}\n`);
    // The path list, which is what a `DRY_RUN` publish prints instead of
    // pushing (registry plan B-T3.6 step 1).
    for (const dir of reports) {
      for (const f of fs.readdirSync(dir, { recursive: true })) {
        if (fs.statSync(path.join(dir, f)).isFile()) console.log(`${path.basename(dir)}  ${f}`);
      }
    }
    console.log(`composed ${pending.length} result(s) in ${reports.length} report(s); operator window ${OPERATOR_WINDOW_HOURS} h`);
    return 0;
  }
  if (args.mode === "finalize") {
    const { pending } = JSON.parse(fs.readFileSync(args.results, "utf8"));
    // What publish-apply reported, from the step outputs the workflow hands
    // on: its outcome, the reports it refused, and whether this run pushed.
    const dryRun = String(process.env.DRY_RUN ?? "true") !== "false";
    const outcome = String(process.env.ASTRA_APPLY_OUTCOME ?? "");
    const applied = args.applied && fs.existsSync(args.applied)
      ? JSON.parse(fs.readFileSync(args.applied, "utf8"))
      : {
        outcome,
        refused: String(process.env.ASTRA_APPLY_REFUSED ?? "").split(/\s+/).filter(Boolean),
        pushed: outcome === "committed",
        dry_run: outcome === "dry-run" || dryRun,
      };
    const mainCommit = applied.pushed ? git(args.root, ["rev-parse", "HEAD"]) : null;
    const results = finalizeResults({ pending, applied, mainCommit });
    fs.mkdirSync(path.dirname(args.out), { recursive: true });
    fs.writeFileSync(args.out, `${JSON.stringify({ results }, null, 2)}\n`);
    for (const r of results) {
      if (r.unposted === "refused") console.error(`::error::${r.submission_id}: publish-apply refused its report; no result is posted, and the lease expires under BOT-15`);
      console.log(`${r.submission_id}  ${r.kind}${r.unposted ? `  held (${r.unposted})` : ""}`);
    }
    return results.some((r) => r.unposted === "refused") ? 1 : 0;
  }
  throw new Error("--compose or --finalize");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`::error::${String(e?.stack ?? e)}`);
      process.exit(2);
    });
}
