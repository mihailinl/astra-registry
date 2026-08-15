// How this registry hears that a release happened.
//
// PRODUCTION_PLAN task 3.4, both layers. The task exists because of one line in
// §3.5: *"After the first listing, releases are zero-touch."* A registry where
// the author has to come back and ask is a registry whose catalogue is a
// snapshot of the day each plugin was submitted, and the difference between
// those two things is entirely this file plus a cron entry in
// `.github/workflows/ingest.yml`.
//
// ── layer 1: the ping (minutes, and costs nothing when nobody releases) ─────
//
// A line of text on an issue in this repository:
//
//     /release v0.2.0                       (on the plugin's listing issue)
//     /release you/dice-roller v0.2.0       (as a new issue)
//
// **It carries no authority and needs no token.** That is the whole design, and
// it is what makes the ping implementable today: a GitHub App would need the
// maintainer's account to create and install it, and a `repository_dispatch`
// needs a PAT with write access to this repository, which is precisely the
// credential no plugin author should ever hold. Commenting on a public issue
// needs a GitHub account and nothing else.
//
// It is safe for the reason the plan gives: the bot verifies everything from
// scratch on every run, so a ping is a *request to re-check*, never a claim.
// Two rules keep the blast radius at zero:
//
//   1. An unlabelled ping may only name a repository that is **already listed**
//      (`findListingByRepo`). A stranger can therefore cause a re-check of a
//      listing that is already pinned to a repository identity — the exact
//      worst case §3.4 describes — and nothing else. A *first* listing still
//      goes through the labelled issue template and a human.
//   2. The ownership that gets proved is the **release author's**, not the
//      pinger's (`resolveSubmitter`). Whoever typed the ping is not part of the
//      decision; the account that published the bytes is. This is also what
//      lets layer 2 work with no human anywhere in the loop.
//
// The upgrade, when the maintainer's account can create one, is a **GitHub App**
// with `metadata: read` on the author's repository, subscribed to `release`,
// which posts the same line. Same payload, same verification, same blast
// radius — it just removes the copy-and-paste. Nothing downstream changes, and
// `astra-plugin publish --notify` (AstraPlugins) is the manual escape hatch
// either way: it prints the prefilled URL and opens a browser.
//
// ── layer 2: the backstop (days, and costs one 304 per repository) ─────────
//
// A ping that never arrives is indistinguishable from a plugin that never
// released, so a cron walks the listings that have been quiet. Two economies,
// both required by the acceptance criterion "a repo with no new release costs
// one conditional request":
//
//   * only listings whose newest known release is older than `watch_after_days`
//     are polled at all. A plugin that released yesterday either pinged or will
//     be caught next week; a plugin nobody has heard from in a month is where a
//     missed ping actually hides.
//   * `releases.atom` with `If-None-Match`. GitHub answers 304 with no body for
//     an unchanged feed, and `state/releases-seen.json` remembers the etag.
//
// The feed is used rather than the REST releases API for one reason worth
// stating: it is unauthenticated, cached at the edge, and not billed against
// the API rate limit, so the backstop's cost does not grow into the budget the
// actual ingest needs.

import fs from "node:fs";
import path from "node:path";

import { compareSemver, parseSemver } from "../../tools/lib/semver.mjs";
import { STATE_DIR } from "./policy.mjs";

/** `state/releases-seen.json` — one row per watched repository. */
export const SEEN_FILE = path.join(STATE_DIR, "releases-seen.json");

/** Listings quiet for this long are polled; the rest are free. */
export const WATCH_AFTER_DAYS = 7;

/** How many repositories one cron run will poll, oldest-checked first. */
export const WATCH_BATCH = 100;

const REPO_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const TAG_RE = /^[A-Za-z0-9._/-]{1,128}$/;
const DAY_MS = 86400 * 1000;

/**
 * `bot/ingest.mjs`'s tag charset, minus the shapes that only ever appear in an
 * attack.
 *
 * Git permits a slash in a tag (`release/2026-08`), so the charset has to, and
 * `..` is then the obvious thing to try: `../../evil` satisfies the charset and
 * is a path. It reaches nothing here — the ingest URL-encodes it and `git`
 * refuses it — but a notification that carries a traversal is worth refusing at
 * the door rather than relying on three downstream encoders staying correct.
 */
function isUsableTag(tag) {
  if (!TAG_RE.test(tag)) return false;
  if (tag.includes("..")) return false;
  return !tag.startsWith("/") && !tag.endsWith("/") && !tag.startsWith("-");
}

// ── layer 1: the ping ───────────────────────────────────────────────────────

/**
 * The first line of a body that a person actually wrote.
 *
 * Leading blank lines and markdown headings are skipped, and **nothing else
 * is**. That is not a convenience: `.github/ISSUE_TEMPLATE/config.yml` turned
 * blank issues off, so the ping-as-a-new-issue path that `docs/POLICY.md` §5
 * promises now goes through a form — and GitHub renders every issue form as
 * `### <label>`, a blank line, then the value. Under the old rule the command
 * was never on line 1 again and the whole path silently stopped working.
 *
 * A heading and a blank line are the two things GitHub's own renderer inserts.
 * Prose is not skipped, so "any news? maybe /release it" is still not a
 * command, and neither is a quoted reply — `> ` is neither blank nor a heading.
 */
export function firstWrittenLine(text) {
  for (const raw of String(text ?? "").replace(/\r/g, "").split("\n")) {
    const line = raw.trim();
    if (line === "" || /^#{1,6}\s/.test(line)) continue;
    return line;
  }
  return "";
}

/**
 * `/release [owner/repo] <tag>`, and nothing else.
 *
 * Deliberately shaped like `/recheck` (`bot/lib/issue.mjs`): the whole line,
 * case-insensitive, and the first line anybody wrote. A sentence that mentions
 * the command does not run it, because a bot that reacts to prose is a bot that
 * reacts to a quoted reply.
 *
 * @param {string} text an issue body or a comment body
 * @returns {{repo: string|null, tag: string|null}|null}
 */
export function parseReleasePing(text) {
  const first = firstWrittenLine(text);
  const m = /^\/release\s+(\S+)(?:\s+(\S+))?$/i.exec(first);
  if (!m) return null;

  // The same decorations `bot/lib/issue.mjs` strips off a form field, in the
  // same order: trailing slashes first, because somebody who pastes the address
  // bar produces `…/dice-roller.git/` and stripping `.git` first would leave it.
  const clean = (s) =>
    String(s ?? "")
      .replace(/^`+|`+$/g, "")
      .replace(/^@/, "")
      .replace(/^https?:\/\/github\.com\//i, "")
      .replace(/\/+$/, "")
      .replace(/\.git$/, "")
      .replace(/\/+$/, "")
      .trim();

  const a = clean(m[1]);
  const b = clean(m[2]);
  // One argument is a tag on a listing issue; two are a repository and a tag.
  const repo = b ? a : null;
  const tag = b || a;
  if (repo !== null && !REPO_RE.test(repo)) return null;
  if (!isUsableTag(tag)) return null;
  return { repo, tag };
}

/**
 * The listing that already names this repository, if there is one.
 *
 * The lookup is exact and case-insensitive on both halves: `You/Dice-Roller` is
 * the same GitHub repository as `you/dice-roller`, and a ping that did not
 * match on case would silently fall through to "not listed" — which reads to
 * the author as the registry ignoring them.
 *
 * @param {{plugins: {doc: object, versions: {doc: object}[]}[]}} sources loadSources() output
 */
export function findListingByRepo(sources, repo) {
  const want = String(repo ?? "").toLowerCase();
  if (!REPO_RE.test(repo ?? "")) return null;
  for (const p of sources.plugins ?? []) {
    if (String(p.doc?.source?.repo ?? "").toLowerCase() !== want) continue;
    const versions = (p.versions ?? [])
      .map((v) => v.doc)
      .filter((d) => d?.version && parseSemver(d.version))
      .sort((a, b) => compareSemver(a.version, b.version));
    const newest = versions.at(-1) ?? null;
    return {
      id: p.doc.id,
      repo: p.doc.source.repo,
      newest_version: newest?.version ?? null,
      newest_tag: newest?.release?.tag ?? null,
      newest_published_at: newest?.published_at ?? null,
      unlisted: Boolean(p.doc.unlisted),
    };
  }
  return null;
}

/**
 * Who the ownership check should be run against for a ping or a poll.
 *
 * Not the pinger. The account that published the release — which required push
 * access to the repository the listing is pinned to, and which is the narrowest
 * true statement available: *the person who published these exact bytes*.
 *
 * This is weaker than the admin/maintain answer a first listing gets, and the
 * weakening is bounded by the two events that always block on a human anyway: a
 * first listing (there is no pin yet) and a repository change (the pin moved).
 * Inside those bounds it is the correct check — asking whether the *pinger* has
 * admin would mean the cron backstop, which has no human at all, could never
 * publish anything.
 *
 * @param {(repo: string, tag: string) => Promise<{author?: {login?: string}}>} fetchRelease
 */
export async function resolveSubmitter(repo, tag, fetchRelease) {
  const release = await fetchRelease(repo, tag);
  const login = release?.author?.login ?? null;
  if (!login) throw new Error(`the release ${repo}@${tag} names no author, so there is nobody to check`);
  return login;
}

// ── layer 2: the backstop ───────────────────────────────────────────────────

/** Read `state/releases-seen.json`, or an empty memory. */
export function readSeen(root) {
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(root, SEEN_FILE), "utf8"));
    return doc?.repos && typeof doc.repos === "object" ? doc : { repos: {} };
  } catch {
    return { repos: {} };
  }
}

export function serialiseSeen(seen) {
  const repos = {};
  for (const key of Object.keys(seen.repos ?? {}).sort()) repos[key] = seen.repos[key];
  return `${JSON.stringify(
    {
      $comment:
        "What the release backstop last saw, per listed repository (PRODUCTION_PLAN task 3.4). " +
        "Cache only: deleting this file costs one full poll of every listing and nothing else. " +
        "`etag` is fed back as If-None-Match so an unchanged repository costs a 304.",
      updated_at: seen.updated_at ?? null,
      repos,
    },
    null,
    2,
  )}\n`;
}

/**
 * Which listings this run should poll, and why the rest are free.
 *
 * @param {{plugins: object[]}} sources
 * @param {{repos: Record<string, {etag?: string, last_checked?: string, last_seen_tag?: string}>}} seen
 */
export function watchPlan(sources, seen, now = new Date(), opts = {}) {
  const watchAfter = (opts.watchAfterDays ?? WATCH_AFTER_DAYS) * DAY_MS;
  const batch = opts.batch ?? WATCH_BATCH;
  const poll = [];
  const quiet = [];

  for (const p of sources.plugins ?? []) {
    const repo = p.doc?.source?.repo;
    if (!repo || !REPO_RE.test(repo) || p.doc?.unlisted) continue;
    if ((p.doc?.source?.kind ?? "github") !== "github") continue;

    const versions = (p.versions ?? [])
      .map((v) => v.doc)
      .filter((d) => d?.version && parseSemver(d.version))
      .sort((a, b) => compareSemver(a.version, b.version));
    const newest = versions.at(-1);
    const row = seen.repos?.[repo.toLowerCase()] ?? {};

    // "Last-seen release" is the newer of what the catalogue holds and what the
    // last poll saw — a repository that released something this registry
    // *refused* has still been heard from, and polling it again tomorrow would
    // re-refuse it every day.
    const lastSeen = [newest?.published_at, row.last_seen_at]
      .filter(Boolean)
      .map((t) => new Date(t).getTime())
      .filter((t) => Number.isFinite(t))
      .sort((a, b) => a - b)
      .at(-1) ?? 0;

    const ageMs = now.getTime() - lastSeen;
    const entry = {
      repo,
      id: p.doc.id,
      listed_version: newest?.version ?? null,
      listed_tag: newest?.release?.tag ?? null,
      etag: row.etag ?? null,
      last_checked: row.last_checked ?? null,
      quiet_days: Math.floor(ageMs / DAY_MS),
    };
    if (ageMs < watchAfter) {
      quiet.push({ ...entry, why: `released ${entry.quiet_days} day(s) ago; the ping path owns it` });
    } else {
      poll.push(entry);
    }
  }

  // Oldest check first, so a catalogue larger than one batch rotates instead of
  // polling the same first hundred for ever.
  poll.sort((a, b) => String(a.last_checked ?? "").localeCompare(String(b.last_checked ?? "")));
  return { poll: poll.slice(0, batch), deferred: poll.slice(batch), quiet };
}

/**
 * The releases in `<owner>/<repo>/releases.atom`, newest first.
 *
 * A hand-rolled parse of four fields, because this repository has no
 * dependencies on purpose (see `.github/workflows/build-index.yml`) and an XML
 * parser is a large attack surface for `<link href>` and `<updated>`.
 *
 * Every entry is required to point back at the repository that was asked about:
 * the tag comes out of a URL, the URL is what a later ingest turns into an API
 * call, and a feed that answered with somebody else's releases would otherwise
 * choose which repository gets checked.
 */
export function parseReleasesAtom(xml, repo) {
  const text = String(xml ?? "");
  const want = `https://github.com/${repo}/releases/tag/`.toLowerCase();
  const out = [];
  for (const m of text.matchAll(/<entry>([\s\S]*?)<\/entry>/g)) {
    const entry = m[1];
    const href = /<link[^>]*\shref="([^"]+)"/i.exec(entry)?.[1] ?? "";
    if (!href.toLowerCase().startsWith(want)) continue;
    let tag;
    try {
      tag = decodeURIComponent(href.slice(want.length));
    } catch {
      continue;
    }
    if (!tag || !isUsableTag(tag)) continue;
    const updated = /<updated>([^<]+)<\/updated>/i.exec(entry)?.[1]?.trim() ?? null;
    const title = /<title>([^<]*)<\/title>/i.exec(entry)?.[1]?.trim() ?? null;
    out.push({ tag, updated, title });
  }
  return out;
}

/**
 * Given a listing and its feed, is there a release this registry has not seen?
 *
 * Answered by *tag*, not by version: the version lives inside the bundle, which
 * this layer has not downloaded and must not guess at. A tag that is neither
 * the listed one nor the last one polled is a candidate, and the ingest decides
 * what it actually is.
 */
export function newReleases(entry, feed, seenRow = {}) {
  const known = new Set(
    [entry.listed_tag, seenRow.last_seen_tag, ...(seenRow.checked_tags ?? [])].filter(Boolean),
  );
  return feed.filter((e) => !known.has(e.tag));
}
