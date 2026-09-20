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

// ── BOT-74's filters, applied before anything is dispatched (B-T3.9) ───────
//
// A monorepo publishes tags this registry has no opinion about.
// `mihailinl/AstraPlugins` alone tags `cli-v…`, `plugin-release/v…` and the
// plugin's own `v…`, and the backstop's releases feed shows all of them. Every
// one it dispatches costs a full ingest — a clone, an archive walk, an
// attestation verification — and from R3 it also costs a decision RECORD, a
// durable public statement that this registry refused `cli-v1.4.0` as a plugin
// release. It never was one.
//
// Written as a property over the tags the listing has ALREADY recorded, and
// not as a list of the prefixes this repository happens to use. A list is
// wrong for the first monorepo that names its tags differently, and the way it
// is wrong is silent: the tag passes the filter, the ingest runs, and the
// refusal is recorded.

/** Everything before the first digit: `cli-v1.4.0` → `cli-v`, `v0.2.0` → `v`. */
const tagPrefix = (tag) => /^([^0-9]*)/.exec(String(tag ?? ""))?.[1] ?? "";

/**
 * Should this tag be ingested at all?
 *
 * @param {{tag: string, listedTags: string[]}} opts `listedTags` are the tags
 *   the listing's own version documents record — the registry's evidence of
 *   what a release tag looks like for THIS plugin.
 * @returns {{pass: boolean, why: string}}
 */
export function bot74Filter({ tag, listedTags = [] }) {
  const recorded = listedTags.filter(Boolean).map(String);
  if (recorded.some((t) => t === tag)) {
    return { pass: false, why: `${tag} is already recorded on this listing, so there is nothing new to ingest` };
  }
  const prefixes = new Set(recorded.map(tagPrefix));
  if (prefixes.size === 0) {
    // A listing with no recorded tag has no evidence to filter by, and
    // inventing one here would be this module deciding what a release tag
    // looks like. It passes, and says why — a first listing is exactly the
    // case a human reads anyway (R_FIRST_LISTING).
    return { pass: true, why: `${tag}: this listing records no tag yet, so there is no prefix to compare against` };
  }
  const mine = tagPrefix(tag);
  if (!prefixes.has(mine)) {
    return {
      pass: false,
      why:
        `${tag} has the prefix ${JSON.stringify(mine)} and every tag this listing records has one of ` +
        `${[...prefixes].map((p) => JSON.stringify(p)).join(", ")}. A monorepo tags more than one thing, and ` +
        "an ingest of the wrong one records a public refusal of a release that was never a plugin release",
    };
  }
  return { pass: true, why: `${tag} matches the prefix this listing's recorded tags use` };
}

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

  // Every tag each listing has recorded, for BOT-74's prefix filter. Read
  // from `sources` here rather than added to `watchPlan`'s entry, because the
  // plan's entry carries the NEWEST tag and the filter needs the set: one tag
  // yields one prefix, and a listing that has ever changed its tag shape would
  // then filter out its own releases.
  const recordedTags = new Map(
    (sources.plugins ?? [])
      .filter((p) => p.doc?.source?.repo)
      .map((p) => [
        String(p.doc.source.repo).toLowerCase(),
        (p.versions ?? []).map((v) => v.doc?.release?.tag).filter(Boolean).map(String),
      ]),
  );

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
        // BOT-74's filters, before a single ingest is started. A tag this
        // listing would never have published is recorded as seen — so the
        // backstop does not re-offer it tomorrow and every day after — and
        // dispatched to nothing.
        const listedTags = recordedTags.get(key) ?? [];
        const wanted = [];
        for (const f of fresh) {
          const verdict = bot74Filter({ tag: f.tag, listedTags });
          if (verdict.pass) wanted.push(f);
          else log.push(`  skip ${entry.repo} — ${verdict.why}`);
        }
        // Every tag the feed showed is recorded — the filtered ones included,
        // so a `cli-v` tag is skipped once rather than skipped daily for ever
        // — and so a release this registry refuses is not re-dispatched
        // tomorrow and every day after.
        row.checked_tags = [...new Set([...(row.checked_tags ?? []), ...fresh.map((f) => f.tag)])].slice(-20);
        if (wanted.length === 0) {
          seen.repos[key] = row;
          continue;
        }
        const newest = wanted[0];
        row.last_seen_tag = newest.tag;
        row.last_seen_at = newest.updated ?? iso(now);
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
