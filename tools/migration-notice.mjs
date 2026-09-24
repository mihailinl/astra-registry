#!/usr/bin/env node
// MIG-13's rounds at the desk (registry plan M-T5.3). Nothing here sends a
// notice or opens an issue: those are owner-approved acts. It says who is
// told, whether each can be reached, what each round says, and what marker
// the round or re-send commits — and it refuses the procedure's known wrong
// turns before a person commits them.
//
//     node tools/migration-notice.mjs recipients
//     node tools/migration-notice.mjs issue-paths [--readings <file.json>]
//     node tools/migration-notice.mjs render --round <n> [--cutover <time>] [--account <login>]
//     node tools/migration-notice.mjs round --round <n> --sent-at <time> [--cutover <time>] [--write]
//     node tools/migration-notice.mjs resend --cutover <time> --at <time> [--write]
//     node tools/migration-notice.mjs authoritative
//
// Every subcommand takes `--root <tree>` (default: this repository).
//
// `issue-paths` reads `https://api.github.com/repos/<owner>/<name>` for each
// account's target repository, with no credential unless GITHUB_TOKEN is set,
// under the User-Agent below. `--readings` takes a recorded reading instead —
// `{ "<owner/name>": { "has_issues": true, "archived": false, "private": false } }`
// — which is how the fixtures run. It exits 1 when any account has no issue
// path: the round stops for that account and the item goes to the owner
// before the round is sent (attack m-6).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  NOTICE_DOC, RECOMMIT_TRAILER, authoritative, judgeIssuePaths, planResend, planRound, readMarkers, recipients,
  renderRound,
} from "./lib/migration-notice.mjs";
import { readMarkers as readRecords } from "../bot/lib/listing-state.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USER_AGENT = "astra-registry-lane (+https://github.com/mihailinl/astra-registry)";

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const args = { command, root: REPO, write: false };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const take = () => {
      if (i + 1 >= rest.length) throw new Error(`${a} needs a value`);
      return rest[++i];
    };
    if (a === "--root") args.root = path.resolve(take());
    else if (a === "--round") args.round = Number(take());
    else if (a === "--sent-at") args.sentAt = take();
    else if (a === "--cutover") args.cutover = take();
    else if (a === "--at") args.at = take();
    else if (a === "--account") args.account = take();
    else if (a === "--readings") args.readings = path.resolve(take());
    else if (a === "--write") args.write = true;
    else throw new Error(`unknown argument ${JSON.stringify(a)}`);
  }
  return args;
}

function printPlan(plan, args) {
  for (const n of plan.notes) console.log(`note  ${n}`);
  for (const p of plan.problems) console.error(`FAIL  ${p}`);
  if (plan.problems.length) return 1;
  if (plan.branch) console.log(`branch ${plan.branch} (read from the dates)`);
  if (!plan.writes.length) {
    console.log("writes no marker");
    return 0;
  }
  const recommit = plan.writes.some((w) => fs.existsSync(path.join(args.root, w.file)));
  for (const w of plan.writes) {
    if (args.write) fs.writeFileSync(path.join(args.root, w.file), w.text);
    console.log(`${args.write ? "wrote" : "would write"} ${w.file}\n${w.text}`);
  }
  // Only with the sends: the marker is the record of a round that went out.
  console.log("Commit these WITH the round's sends, never before them.");
  if (recommit) {
    console.log("This re-commits a marker already on main, so the commit's message ends with this trailer, or the " +
      "coverage canary refuses it as an edit under log/ (MOD-34):\n\n" + RECOMMIT_TRAILER);
  }
  if (!args.write) console.log("Re-run with --write to write the files.");
  return 0;
}

async function readRepository(repo) {
  const headers = { "User-Agent": USER_AGENT, Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  try {
    const r = await fetch(`https://api.github.com/repos/${repo}`, { headers });
    if (r.status !== 200) return null;
    const body = await r.json();
    return { has_issues: body.has_issues, archived: body.archived, private: body.private, visibility: body.visibility };
  } catch {
    return null;
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
  try {
    switch (args.command) {
      case "recipients": {
        for (const a of recipients(args.root)) {
          console.log(`${a.account}  issue in ${a.target}  listings: ${a.listings.map((l) => l.id).join(", ")}`);
        }
        return 0;
      }
      case "issue-paths": {
        const accounts = recipients(args.root);
        const readings = {};
        if (args.readings) Object.assign(readings, JSON.parse(fs.readFileSync(args.readings, "utf8")));
        else for (const a of accounts) readings[a.target] = await readRepository(a.target);
        const at = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
        console.log(JSON.stringify({ read_at: at, source: args.readings ? "recorded" : "api.github.com", readings }, null, 2));
        const { reachable, ownerItems } = judgeIssuePaths(accounts, readings);
        for (const a of reachable) console.log(`ok    ${a.account}: an issue in ${a.target} reaches it`);
        for (const o of ownerItems) {
          console.log(`OWNER ITEM  ${o.account} has no issue path (${o.target}: ${o.why}); listings ${o.listings.join(", ")}. ` +
            "This round does not go out to it until the owner decides: direct contact, a commit comment, or accepting the freeze.");
        }
        return ownerItems.length ? 1 : 0;
      }
      case "render": {
        const { deadline } = readRecords(args.root);
        const doc = fs.readFileSync(path.join(args.root, NOTICE_DOC), "utf8");
        const account = args.account ? recipients(args.root).find((a) => a.account.toLowerCase() === args.account.toLowerCase()) : null;
        if (args.account && !account) throw new Error(`${args.account} is not a MIG-13 recipient on this tree`);
        const cutover = args.cutover ?? authoritative(readMarkers(args.root)).marker?.doc?.cutover_planned_at ?? null;
        console.log(renderRound(doc, args.round, { deadline, cutover, listings: account ? account.listings.map((l) => l.id) : [] }));
        return 0;
      }
      case "round":
        return printPlan(planRound({ markers: readMarkers(args.root), round: args.round, sentAt: args.sentAt, cutover: args.cutover ?? null }), args);
      case "resend":
        return printPlan(planResend({ markers: readMarkers(args.root), cutover: args.cutover, at: args.at }), args);
      case "authoritative": {
        const { marker, problems } = authoritative(readMarkers(args.root));
        for (const p of problems) console.error(`FAIL  ${p}`);
        if (problems.length) return 1;
        console.log(marker ? `${marker.file}: round ${marker.doc.round}, sent_at ${marker.doc.sent_at}` +
          (marker.doc.cutover_planned_at ? `, cutover_planned_at ${marker.doc.cutover_planned_at}` : "") : "no marker on this tree");
        return 0;
      }
      default:
        console.error("FAIL  the subcommand is one of recipients, issue-paths, render, round, resend, authoritative");
        return 2;
    }
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
