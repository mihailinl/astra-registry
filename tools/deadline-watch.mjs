#!/usr/bin/env node
// ROLL-63's deadline watch (registry plan M-T5.4): the binding deadline, the
// migration-notice markers and the listing banner, compared daily.
//
//     node tools/deadline-watch.mjs [--root <tree>] [--now <time>] [--out verdict.json]
//          [--banner-body <file> --banner-status <n> | --no-banner]
//
// It gathers and `tools/lib/deadline-watch.mjs` judges. It writes one
// `astra.registry.alert-verdict/1` for check `deadline-watch`, prints every
// line of detail, and exits 0 on a red verdict as on a green one — the verdict
// is the signal, and `.github/workflows/deadline-watch.yml` turns a red one
// into a red run. It exits 1 only when it could not judge at all.
//
// The banner is read from `https://astra.minice.ai/plugins/<id>`, with no
// credential, for the first listing of the first MIG-13 recipient on the tree
// (a `grandfathered` listing, which is where MIG-13's banner is rendered),
// once the tree has anything the banner shows: the deadline, which it carries
// in its `binding-deadline` hook from M-T5.2's commit on, or any marker, whose
// round it carries from round 1 (contract 2.7.0's hooks). `--banner-body`/
// `--banner-status` stand in for the read, which is how the fixtures run.
//
// **Whether R4b has opened is whether `log/rollout/R4b-open.json` is on the
// tree** — the registry marker R4b opens with (registry plan §2.7, landing
// order 3), and the one the R6 preflight and the redirects' armed-set check
// already read, so the constant is imported from the preflight rather than
// spelled a third time. MIG-13 (2.7.0) reads the plugins zone's `404` as the
// zone not being open until R4b opens, so before the marker a 404 is a line of
// detail and from it BANNER_UNREACHABLE. Existence decides, and not a parse as
// the preflight's does: the preflight is a GATE, where "not opened" is the safe
// reading of a marker it cannot read, and this is an ALARM, where "opened" is.
// `log/cutover.json` would be the wrong record: it is R6's, and between R4b and
// R6 — when rounds 1 and 2 go out and the banner is how they reach an author —
// it would have read every 404 as a zone not yet open.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { cleanEnv } from "./lib/git-env.mjs";
import { CHECK, judge } from "./lib/deadline-watch.mjs";
import { LISTING_PAGE, readMarkers, recipients } from "./lib/migration-notice.mjs";
import { CUTOVER_FILE, readMarkers as readRecords } from "../bot/lib/listing-state.mjs";
import { VERDICT_SCHEMA, runUrl, verdictProblems } from "../bot/lib/alert-verdict.mjs";
import { R4B_MARKER } from "./cutover-preflight.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USER_AGENT = "astra-registry-lane (+https://github.com/mihailinl/astra-registry)";

function parseArgs(argv) {
  const args = { root: REPO, now: null, out: null, bannerBody: null, bannerStatus: null, noBanner: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--root") args.root = path.resolve(argv[++i]);
    else if (a === "--now") args.now = argv[++i];
    else if (a === "--out") args.out = path.resolve(argv[++i]);
    else if (a === "--banner-body") args.bannerBody = path.resolve(argv[++i]);
    else if (a === "--banner-status") args.bannerStatus = Number(argv[++i]);
    else if (a === "--no-banner") args.noBanner = true;
    else throw new Error(`unknown argument ${JSON.stringify(a)}`);
  }
  return args;
}

/**
 * Every committed version of one marker file, oldest first, read from git —
 * the history guard n22 needs. A tree that is not a repository has none, and
 * the guard then sees only the current version, which it says.
 */
function history(root, file) {
  const git = (args) => execFileSync("git", ["-C", root, ...args], {
    encoding: "utf8", env: cleanEnv(), stdio: ["ignore", "pipe", "ignore"], maxBuffer: 16 * 1024 * 1024,
  });
  let shas;
  try {
    shas = git(["log", "--format=%H", "--reverse", "--", file]).split("\n").filter(Boolean);
  } catch {
    return null;
  }
  const out = [];
  for (const sha of shas) {
    try { out.push(JSON.parse(git(["show", `${sha}:${file}`]))); } catch { /* deleted or unreadable at that commit */ }
  }
  return out;
}

async function readBanner(id) {
  const url = LISTING_PAGE(id);
  try {
    const r = await fetch(url, { headers: { "User-Agent": USER_AGENT }, redirect: "follow", signal: AbortSignal.timeout(20_000) });
    return { id, url, status: r.status, body: r.status === 200 ? await r.text() : null };
  } catch {
    return { id, url, status: null, body: null };
  }
}

export async function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    return 2;
  }
  const now = args.now ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  let verdict;
  try {
    const { deadline } = readRecords(args.root);
    const cutoverOnMain = fs.existsSync(path.join(args.root, CUTOVER_FILE));
    const markers = readMarkers(args.root);
    const histories = {};
    let noHistory = false;
    for (const m of markers) {
      const h = history(args.root, m.file);
      if (h === null || h.length === 0) { noHistory = true; continue; }
      histories[m.file] = h;
    }
    let banner = null;
    const r4bOpen = fs.existsSync(path.join(args.root, R4B_MARKER));
    const shown = markers.length > 0 || deadline !== null;
    if (shown && !args.noBanner) {
      const first = recipients(args.root)[0]?.listings[0]?.id ?? null;
      if (args.bannerBody || args.bannerStatus !== null) {
        const body = args.bannerBody ? fs.readFileSync(args.bannerBody, "utf8") : null;
        banner = { id: first ?? "unknown", url: LISTING_PAGE(first ?? "unknown"), status: args.bannerStatus ?? 200, body };
      } else if (first) {
        banner = await readBanner(first);
      }
    }
    const result = judge({ deadline, cutoverOnMain, markers, histories, now, banner, r4bOpen });
    if (banner) result.detail.push(`R4b ${r4bOpen ? "has opened" : "has not opened"}: ${R4B_MARKER} is ${r4bOpen ? "" : "not "}on this tree`);
    if (noHistory) result.detail.push("a marker's git history could not be read, so guard n22 saw only its current version");
    for (const line of result.detail) console.log(`${result.status === "red" ? "red  " : "     "} ${line}`);
    verdict = { schema: VERDICT_SCHEMA, check: CHECK, status: result.status, codes: [...new Set(result.codes)] };
    if (result.ids.length) verdict.ids = [...new Set(result.ids)];
  } catch (e) {
    // A record the bot itself cannot read is a red, not a skipped day.
    console.error(`red   the watch could not read the tree: ${e.message}`);
    verdict = { schema: VERDICT_SCHEMA, check: CHECK, status: "red", codes: ["DEADLINE_UNREADABLE"] };
  }
  const run = runUrl();
  if (run) verdict.run = run;
  const problems = verdictProblems(verdict);
  if (problems.length) {
    console.error(`FAIL  the verdict this composed is one the alarm channel refuses: ${problems.join("; ")}`);
    return 1;
  }
  const text = `${JSON.stringify(verdict)}\n`;
  if (args.out) fs.writeFileSync(args.out, text);
  process.stdout.write(`verdict ${text}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
