#!/usr/bin/env node
// The half of task 3.4 that runs when nobody pings, and the half of task 3.5
// that runs when a delay ends.
//
//   node bot/watch.mjs --watch --out out     poll the quiet listings
//   node bot/watch.mjs --drain --out out     which delayed releases are ripe
//   node bot/watch.mjs --sla issues.json     how late is the review queue
//
// All three produce `out/dispatch.json` — a list of `{repo, tag, submitter}`
// the workflow turns into ingest runs — and nothing else. **This program never
// decides anything.** It cannot: it has not downloaded a bundle, checked an
// attestation or read a manifest. It answers one question, "is there something
// here that has not been ingested", and hands the answer to the pipeline that
// verifies from scratch. A backstop that took a shortcut because "we already
// know this repository" would be a second, weaker path into the catalogue.

import fs from "node:fs";
import path from "node:path";

import { loadSources, REPO_ROOT } from "../tools/lib/sources.mjs";

import { fetchRelease } from "./lib/github.mjs";
import {
  SEEN_FILE,
  newReleases,
  parseReleasesAtom,
  readSeen,
  resolveSubmitter,
  serialiseSeen,
  watchPlan,
} from "./lib/notify.mjs";
import { readQueue, ripeQueueEntries, slaReport } from "./lib/policy.mjs";

/** At most this many ingests are started by one cron run. */
const MAX_DISPATCH = 20;

const iso = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;

/**
 * One conditional GET of a repository's releases feed.
 *
 * `If-None-Match` is the entire economy of the backstop: GitHub answers 304
 * with no body, which is what makes "a repo with no new release costs one
 * conditional request" true rather than aspirational.
 */
export async function pollFeed(repo, etag, fetchImpl = fetch) {
  const url = `https://github.com/${repo}/releases.atom`;
  const headers = { Accept: "application/atom+xml", "User-Agent": "astra-registry-bot" };
  if (etag) headers["If-None-Match"] = etag;
  const res = await fetchImpl(url, { headers, redirect: "follow" });
  if (res.status === 304) return { changed: false, etag, entries: [] };
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const body = await res.text();
  return {
    changed: true,
    etag: res.headers.get("etag") ?? null,
    entries: parseReleasesAtom(body, repo),
  };
}

/**
 * Poll every listing that has been quiet, and report what is new.
 *
 * @param {object} deps injection seam; production passes nothing
 */
export async function runWatch({ root = REPO_ROOT, now = new Date(), deps = {} } = {}) {
  const doFetch = deps.fetchImpl ?? fetch;
  const release = deps.fetchRelease ?? fetchRelease;
  const sources = loadSources(root);
  const seen = readSeen(root);
  const plan = watchPlan(sources, seen, now, deps.planOpts);

  const dispatch = [];
  const log = [];
  for (const entry of plan.poll) {
    const key = entry.repo.toLowerCase();
    const row = { ...(seen.repos[key] ?? {}) };
    row.last_checked = iso(now);
    try {
      const feed = await pollFeed(entry.repo, entry.etag, doFetch);
      if (!feed.changed) {
        log.push(`  304  ${entry.repo} — unchanged since ${entry.last_checked ?? "the first poll"}`);
        seen.repos[key] = row;
        continue;
      }
      row.etag = feed.etag;
      const fresh = newReleases(entry, feed.entries, row);
      if (fresh.length === 0) {
        log.push(`  200  ${entry.repo} — ${feed.entries.length} release(s), all of them already known`);
      } else {
        const newest = fresh[0];
        row.last_seen_tag = newest.tag;
        row.last_seen_at = newest.updated ?? iso(now);
        // Every tag the feed showed is recorded, so a release this registry
        // refuses is not re-dispatched tomorrow and every day after.
        row.checked_tags = [...new Set([...(row.checked_tags ?? []), ...fresh.map((f) => f.tag)])].slice(-20);
        if (dispatch.length < MAX_DISPATCH) {
          try {
            const submitter = await resolveSubmitter(entry.repo, newest.tag, release);
            dispatch.push({ repo: entry.repo, tag: newest.tag, submitter, source: "backstop" });
            log.push(`  NEW  ${entry.repo}@${newest.tag} — published by @${submitter}, ingesting`);
          } catch (e) {
            log.push(`  ??   ${entry.repo}@${newest.tag} — ${e.message}`);
          }
        } else {
          log.push(`  NEW  ${entry.repo}@${newest.tag} — over this run's dispatch cap, next run takes it`);
        }
      }
      seen.repos[key] = row;
    } catch (e) {
      // A repository that has been deleted, renamed or made private must not
      // stop the walk. It is recorded and reported; the listing itself is a
      // maintainer's problem, not the backstop's.
      row.last_error = String(e.message).slice(0, 200);
      seen.repos[key] = row;
      log.push(`  ERR  ${entry.repo} — ${e.message}`);
    }
  }

  seen.updated_at = iso(now);
  return { plan, dispatch, seen, log };
}

/** Which delayed releases have served their time. */
export function runDrain({ root = REPO_ROOT, now = new Date() } = {}) {
  const queue = readQueue(root);
  const ripe = ripeQueueEntries(queue, now);
  return {
    queue,
    dispatch: ripe.slice(0, MAX_DISPATCH).map((e) => ({
      repo: e.repo,
      tag: e.tag,
      submitter: e.submitter ?? null,
      source: "queue",
      queued_at: e.queued_at,
    })),
    log: queue.map((e) =>
      `  ${new Date(e.publish_after) <= now ? "RIPE" : "wait"}  ${e.id} ${e.version} — publishes at ${e.publish_after} (${e.reason})`,
    ),
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function writeDispatch(out, dispatch) {
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, "dispatch.json"), `${JSON.stringify(dispatch, null, 2)}\n`);
}

async function main(argv) {
  const opts = { mode: null, out: null, root: REPO_ROOT, sla: null, now: new Date() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--watch") opts.mode = "watch";
    else if (a === "--drain") opts.mode = "drain";
    else if (a === "--sla") { opts.mode = "sla"; opts.sla = argv[++i]; }
    else if (a === "--out") opts.out = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--now") opts.now = new Date(argv[++i]);
    else throw new Error(`unknown argument: ${a}`);
  }

  if (opts.mode === "watch") {
    const { plan, dispatch, seen, log } = await runWatch({ root: opts.root, now: opts.now });
    console.log(
      `release backstop: ${plan.poll.length} polled, ${plan.quiet.length} skipped as recently released, ` +
      `${plan.deferred.length} deferred to the next run`,
    );
    for (const line of log) console.log(line);
    console.log(`${dispatch.length} ingest(s) to start`);
    if (opts.out) {
      writeDispatch(opts.out, dispatch);
      const dest = path.join(opts.out, SEEN_FILE);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, serialiseSeen(seen));
    }
    return 0;
  }

  if (opts.mode === "drain") {
    const { queue, dispatch, log } = runDrain({ root: opts.root, now: opts.now });
    console.log(`publication queue: ${queue.length} waiting, ${dispatch.length} ripe`);
    for (const line of log) console.log(line);
    if (opts.out) writeDispatch(opts.out, dispatch);
    return 0;
  }

  if (opts.mode === "sla") {
    const text = opts.sla === "-" ? fs.readFileSync(0, "utf8") : fs.readFileSync(opts.sla, "utf8");
    const report = slaReport(JSON.parse(text), opts.now);
    console.log(`review queue: ${report.open} open, ${report.late} past SLA, ${report.breached} badly late — ${report.verdict}`);
    for (const i of report.items) console.log(`  ${String(i.age_hours).padStart(5)} h  #${i.number}  ${i.title}`);
    // A breach is reported, never thrown: a workflow step that failed here
    // would page somebody for a decision that is not a decision to make at
    // 3 a.m., and POLICY.md's answer to a breach is a policy change.
    return 0;
  }

  throw new Error("one of --watch, --drain or --sla <file> is required");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`watch: ${e.message}`);
      process.exit(2);
    });
}
