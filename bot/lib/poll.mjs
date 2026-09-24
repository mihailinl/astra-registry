// The releases feed: one conditional GET, and the four fields an entry in it is
// allowed to contribute.
//
// Split out of `bot/watch.mjs` and `bot/lib/notify.mjs` on 2026-09-20 (registry
// plan B-T2.6). Not one byte of either function changed in the move, and that
// is deliberate: B-T2.6's remaining rules — the prefix filter's memory, the
// HMAC-signed Actions cache the poll reads and does not write, the `git
// ls-remote` sweep that alerts on a tag neither the poll registered nor a
// record names — are all written against this module, and writing them into
// `notify.mjs` would queue four more tasks behind a file three other modules
// import.
//
// ── what the two sides of the cut kept ─────────────────────────────────────
//
// `notify.mjs` re-exports `parseReleasesAtom`, so its twelve-name surface is
// exactly what it was and its five importers did not change. `watch.mjs`
// imports `pollFeed` and does not re-export it: the only reader outside that
// file was `bot/tests/policy.test.mjs`, whose import moved with the function.
//
// `bot/tests/poll.test.mjs` pins all three surfaces BY NAME — an ordered list
// identical across the cut — for the reason `tools/selftest/repo-rules.mjs`
// pins `bot/lib/policy.mjs`'s 26: **a function that stops being imported is
// behaviour that stopped running with nobody deciding that it should**, and no
// count can see it. One version of that guard let a copy-paste delete a module
// while the number a reader checks went UP.
//
// ── why `isUsableTag` is here, where it was not ────────────────────────────
//
// It was private to `notify.mjs` and both parsers need it: the ping grammar
// there, and this feed parse. `notify.mjs` re-exports from this file, so the
// only arrangement that is acyclic AND keeps one copy is for this module to own
// the predicate and for `notify.mjs` to import it. A second copy is the shape
// `dev/couplings.md` exists to refuse, and `bot/tests/poll.test.mjs` scans the
// tree for one.
//
// ── what came after the move (B-T2.6's rules, 2026-09-24) ──────────────────
//
// The rest of this file is the poll and sweep of registry plan B-T2.6: which
// listings are read (BOT-41, MIG-30), which of their tags register (BOT-74),
// the memory that lives in the Actions cache and never in git, HMAC-signed
// (BOT-42), and the daily `git ls-remote` sweep with its alarm (BOT-87). It is
// DARK: nothing in a workflow calls it until B-T5.0 turns `plugins-ingest.yml`'s
// `load`, `poll`, `remember` and a `sweep` job on at R5, in shadow, and B-T5.1
// makes the register step live at R6. Everything a job needs is here, so that
// those two tasks are workflow edits and not design.
//
// **Three jobs, three kinds of function, and the key is in two of them.** The
// plan's job table gives `load` and `remember` the `bot-state` key and `poll`
// none, because `poll` reads a stranger's feed. So:
//
//   * `loadMemory` and `rememberMemory` are the only functions that take the
//     key, and they take it from `stateKey()`, which reads exactly one
//     environment variable, `BOT_STATE_HMAC_KEY`, and refuses a short one;
//   * `runPoll`, `pollListing` and `runSweep` take an already-opened memory and
//     no key, and a test asserts none of them can reach one;
//   * `rememberPoll` and `sweepListing` are pure, and they are where the two
//     rules that lose a release silently live: a tag enters memory only once
//     `claim` said it was registered, and a feed's new ETag is kept only when
//     every tag it produced was — otherwise the next poll is answered 304 and
//     never offers the tag again.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { TAG_PATTERN } from "../../tools/lib/tags.mjs";
import { cleanEnv } from "../../tools/lib/git-env.mjs";
import { jcs } from "../../tools/lib/canonical.mjs";
import { compareSemver, parseSemver } from "../../tools/lib/semver.mjs";
import { isTime } from "../../tools/lib/time.mjs";
import { LISTING_STATES } from "./listing-state.mjs";
import { VERDICT_SCHEMA, verdictProblems } from "./alert-verdict.mjs";

// One place decides what a tag is: tools/lib/tags.mjs.
const TAG_RE = new RegExp(TAG_PATTERN);

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
export function isUsableTag(tag) {
  if (!TAG_RE.test(tag)) return false;
  if (tag.includes("..")) return false;
  return !tag.startsWith("/") && !tag.endsWith("/") && !tag.startsWith("-");
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

// ═══════════════════════════════════════════════════════════════════════════
// B-T2.6: which listings, which tags, the memory, the sweep, the alarm
// ═══════════════════════════════════════════════════════════════════════════

/** BOT-41: after cutover every pollable listing's feed is read every 30 minutes. */
export const POLL_INTERVAL_SECONDS = 1800;

/** BOT-87: a listing whose last successful poll is older than this many intervals alarms. */
export const POLL_STALE_INTERVALS = 3;

/**
 * The environment and the one variable the memory's key is read from.
 *
 * Named here, by B-T2.6, so that B-T5.0's job has one string to put in its
 * `env:` rather than a name to invent. The environment admits only `main`
 * (registry plan RC-R0-3(f), ext.12): a job on a branch that could read this
 * key could forge the sweep memory so that an unregistered tag reads as
 * seen, and `openMemory` would accept it, because the forgery carries the
 * real key.
 */
export const STATE_ENVIRONMENT = "bot-state";
export const STATE_KEY_ENV = "BOT_STATE_HMAC_KEY";

/** 32 bytes, written as 64 lowercase hex. `openssl rand -hex 32` makes one. */
export const STATE_KEY_MIN_BYTES = 32;

/** The memory, and the envelope it is carried in through the Actions cache. */
export const MEMORY_SCHEMA = "astra.registry.poll-memory/1";
export const SEAL_SCHEMA = "astra.registry.poll-memory-seal/1";

/** The file `load` restores and `remember` saves, relative to the job's workspace. */
export const MEMORY_FILE = path.posix.join(".poll-memory", "memory.json");

/** BOT-87's receiver check (`bot/lib/alert-checks.mjs`), and the four codes it pages with. */
export const SWEEP_CHECK = "poll-and-sweep";
export const BOT_87_CODES = Object.freeze({
  unregistered: "BOT_87_TAG_UNREGISTERED",
  stale: "BOT_87_POLL_STALE",
  discarded: "BOT_87_MEMORY_DISCARDED",
  sweepFailed: "BOT_87_SWEEP_FAILED",
});

/**
 * The decision states after which a tag's story is over (BOT-19).
 *
 * One set, read by `bot/decide.mjs`'s `terminalOnMain` for BOT-19's search and
 * here for BOT-74's "no tag with a terminal record for its `repository_id`".
 * It lives in this module and not in `bot/lib/decisions.mjs` because
 * `decisions.mjs` imports `intake.mjs`, which imports `notify.mjs`, which
 * imports this file: the other direction is a cycle.
 */
export const TERMINAL_STATES = Object.freeze(["refused", "revoked", "yanked", "withdrawn", "deprecated"]);

/** How many registered tags a repository's memory keeps. The feed shows 10. */
const REGISTERED_KEEP = 200;

const iso = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;
const HEX40 = /^[0-9a-f]{40}$/;
const repoKey = (repo) => String(repo ?? "").toLowerCase();

// ── BOT-74: the prefix, and which tags register ────────────────────────────

/**
 * BOT-74's prefix: the newest listed version's recorded `release.tag` with
 * that version removed from its end, or `null` — "every tag matches" — when
 * the tag does not end in its version.
 *
 * `null` is not `""`. A listing whose tags are bare versions (`0.2.0`) has the
 * prefix `""`, which every tag also starts with; the two agree on what they
 * admit and differ on what they say, and a caller printing why a tag passed
 * should be able to tell them apart.
 *
 * @param {{version: string, tag: string}|null} newest
 * @returns {string|null}
 */
export function bot74Prefix(newest) {
  if (!newest || typeof newest.tag !== "string" || typeof newest.version !== "string") return null;
  if (!newest.tag.endsWith(newest.version)) return null;
  return newest.tag.slice(0, newest.tag.length - newest.version.length);
}

/**
 * The version BOT-74 takes its prefix from: the newest by semver among the
 * listing's version records that are not yanked, or among all of them when
 * every one is. A yanked version's tag is still evidence of the tag shape;
 * it is only not the newest LISTED one while another is.
 */
export function newestListedVersion(versions) {
  const usable = (versions ?? []).filter((v) => parseSemver(v?.version) && typeof v?.tag === "string");
  const listed = usable.filter((v) => v.yanked !== true);
  const pool = listed.length ? listed : usable;
  if (pool.length === 0) return null;
  return pool.reduce((a, b) => (compareSemver(b.version, a.version) > 0 ? b : a));
}

/** Does this tag start with the prefix? `null` admits every tag. */
export function matchesPrefix(prefix, tag) {
  return prefix === null || String(tag).startsWith(prefix);
}

/**
 * The listings the poll reads, each with what BOT-74 needs to judge a tag.
 *
 * `listed`, `grandfathered` and `frozen`, read through M-T5.1's
 * `bot/lib/listing-state.mjs` (BOT-41). An unlisted listing is never polled
 * (MIG-30), whatever its state, and a listing whose state cannot be decided is
 * not polled either: `stateOf` throws for a shallow clone or an unreadable
 * identity record, and that is reported, never guessed around.
 *
 * @param {{sources: {plugins: object[]}, records?: {identities?: object[], decisions?: object[]},
 *   stateOf: (pluginId: string) => {state: string, unlisted: boolean}}} opts
 * @returns {{listings: object[], skipped: {id: string, why: string}[]}}
 */
export function pollableListings({ sources, records = {}, stateOf }) {
  if (typeof stateOf !== "function") {
    throw new Error("pollableListings needs stateOf(pluginId): which listings are polled is MIG-1's answer, never a default");
  }
  const identities = new Map((records.identities ?? [])
    .map((r) => [String(r.file ?? "").split("/")[1], r.doc]));
  const decisions = (records.decisions ?? []).map((r) => r.doc ?? r).filter((d) => d && typeof d === "object");
  const listings = [];
  const skipped = [];
  for (const p of sources?.plugins ?? []) {
    const id = p.doc?.id ?? p.id;
    const repo = p.doc?.source?.repo;
    if (typeof id !== "string" || typeof repo !== "string") {
      skipped.push({ id: String(id), why: "the listing names no id or no source.repo, so there is no feed to read" });
      continue;
    }
    if (p.doc?.unlisted === true) {
      skipped.push({ id, why: "unlisted, and an unlisted listing is never polled (MIG-30)" });
      continue;
    }
    let st;
    try {
      st = stateOf(id);
    } catch (e) {
      skipped.push({ id, why: `its state could not be decided, so it is not polled: ${e.message}` });
      continue;
    }
    if (st?.unlisted === true) {
      skipped.push({ id, why: "unlisted, and an unlisted listing is never polled (MIG-30)" });
      continue;
    }
    if (!LISTING_STATES.includes(st?.state)) {
      skipped.push({ id, why: `its state is ${JSON.stringify(st?.state)}, which is not one BOT-41 polls` });
      continue;
    }
    const versions = (p.versions ?? []).map((v) => ({
      version: v.doc?.version, tag: v.doc?.release?.tag, yanked: v.doc?.yanked === true,
    }));
    const newest = newestListedVersion(versions);
    const identity = identities.get(p.dir ?? id) ?? null;
    const repositoryId = typeof identity?.repository_id === "string" ? identity.repository_id : null;
    const mine = decisions.filter((d) => decisionIsFor(d, { repo, repositoryId }));
    listings.push({
      id,
      repo,
      repository_id: repositoryId,
      state: st.state,
      prefix: bot74Prefix(newest),
      prefix_from: newest ? { version: newest.version, tag: newest.tag } : null,
      recorded_tags: versions.map((v) => v.tag).filter((t) => typeof t === "string"),
      terminal_tags: mine.filter((d) => TERMINAL_STATES.includes(String(d.state)) && typeof d.tag === "string").map((d) => d.tag),
      named_tags: mine.filter((d) => typeof d.tag === "string").map((d) => d.tag),
    });
  }
  return { listings, skipped };
}

/**
 * A decision record is about this listing's repository when it names the same
 * `repository_id`, or — for a record or a listing that has none, which every
 * grandfathered one is — the same `repo`, case-blind.
 */
function decisionIsFor(d, { repo, repositoryId }) {
  if (repositoryId && typeof d.repository_id === "string") return d.repository_id === repositoryId;
  return typeof d.repo === "string" && repoKey(d.repo) === repoKey(repo);
}

/**
 * BOT-74, for one tag: register it or not, and why.
 *
 * @param {object} listing one of `pollableListings`'s
 * @param {string} tag
 * @param {string[]} memoryTags the tags this repository's memory already holds as registered
 * @returns {{register: boolean, why: string}}
 */
export function tagVerdict(listing, tag, memoryTags = []) {
  if (!isUsableTag(tag)) return { register: false, why: `${JSON.stringify(tag)} is not a usable tag` };
  if (!matchesPrefix(listing.prefix, tag)) {
    return {
      register: false,
      why: `${tag} does not start with ${JSON.stringify(listing.prefix)}, the prefix of ${listing.prefix_from?.tag} ` +
        "(BOT-74). A monorepo tags more than one thing",
    };
  }
  if (listing.recorded_tags.includes(tag)) return { register: false, why: `${tag} is recorded by a listed version (BOT-74)` };
  if (listing.terminal_tags.includes(tag)) {
    return { register: false, why: `${tag} has a terminal decision record for this repository (BOT-74, BOT-19)` };
  }
  if (memoryTags.includes(tag)) return { register: false, why: `${tag} was registered already, by an earlier poll` };
  return {
    register: true,
    why: listing.prefix === null
      ? `${tag}: the newest listed tag does not end in its version, so every tag matches (BOT-74)`
      : `${tag} starts with ${JSON.stringify(listing.prefix)} and nothing records it`,
  };
}

// ── the memory, and its key ────────────────────────────────────────────────

/** A memory that has seen nothing, started now. */
export function newMemory(now) {
  return { schema: MEMORY_SCHEMA, started_at: iso(now), repos: {}, sweep: { count: 0, last_at: null, repos: {} } };
}

/** Why a memory is not one this module wrote, or null. Checked after the signature, never instead of it. */
export function memoryProblem(m) {
  if (!m || typeof m !== "object" || Array.isArray(m)) return "the memory is not an object";
  if (m.schema !== MEMORY_SCHEMA) return `schema is ${JSON.stringify(m.schema)}, not ${MEMORY_SCHEMA}`;
  if (!isTime(m.started_at)) return "started_at is not a §0.7 time";
  if (!m.repos || typeof m.repos !== "object" || Array.isArray(m.repos)) return "repos is not an object";
  for (const [k, row] of Object.entries(m.repos)) {
    if (k !== repoKey(k)) return `repos key ${JSON.stringify(k)} is not lowercase`;
    if (!row || typeof row !== "object") return `repos.${k} is not an object`;
    if (row.etag !== null && typeof row.etag !== "string") return `repos.${k}.etag is neither null nor a string`;
    if (row.last_success_at !== null && !isTime(row.last_success_at)) return `repos.${k}.last_success_at is not a time`;
    if (!Array.isArray(row.registered) || !row.registered.every(isUsableTag)) return `repos.${k}.registered is not a list of tags`;
  }
  const s = m.sweep;
  if (!s || typeof s !== "object" || !Number.isSafeInteger(s.count) || s.count < 0) return "sweep.count is not a count";
  if (s.last_at !== null && !isTime(s.last_at)) return "sweep.last_at is not a time";
  if (!s.repos || typeof s.repos !== "object" || Array.isArray(s.repos)) return "sweep.repos is not an object";
  for (const [k, tags] of Object.entries(s.repos)) {
    if (!tags || typeof tags !== "object" || Array.isArray(tags)) return `sweep.repos.${k} is not an object`;
    for (const [t, v] of Object.entries(tags)) {
      if (!isUsableTag(t)) return `sweep.repos.${k} holds ${JSON.stringify(t)}, which is not a tag`;
      if (!v || !HEX40.test(v.sha) || !Number.isSafeInteger(v.first_seen) || typeof v.seeded !== "boolean") {
        return `sweep.repos.${k}.${t} is not {sha, first_seen, seeded}`;
      }
    }
  }
  return null;
}

/**
 * The key, from `BOT_STATE_HMAC_KEY` and nowhere else.
 *
 * Refused when absent, when not hex, and when shorter than 32 bytes, because
 * a short key is a forgeable one and a job that "signed" with it would report
 * success.
 */
export function stateKey(env = process.env) {
  const raw = env[STATE_KEY_ENV];
  if (typeof raw !== "string" || raw === "") {
    throw new Error(
      `${STATE_KEY_ENV} is not set. Only the \`load\` and \`remember\` jobs hold it, in environment ` +
      `\`${STATE_ENVIRONMENT}\`, which admits only main (registry plan B-T2.6, B-T5.0)`,
    );
  }
  const hex = raw.trim();
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`${STATE_KEY_ENV} is not hex; it is ${STATE_KEY_MIN_BYTES} bytes written as lowercase hex`);
  }
  const key = Buffer.from(hex, "hex");
  if (key.length < STATE_KEY_MIN_BYTES) {
    throw new Error(`${STATE_KEY_ENV} is ${key.length} bytes, and the floor is ${STATE_KEY_MIN_BYTES}`);
  }
  return key;
}

/** HMAC-SHA256 over a domain-separated canonical form, so the tag cannot be lifted onto another document. */
function mac(memory, key) {
  return crypto.createHmac("sha256", key).update(`${SEAL_SCHEMA}\n`).update(jcs(memory)).digest("hex");
}

/** The envelope `remember` saves. */
export function sealMemory(memory, key) {
  const why = memoryProblem(memory);
  if (why) throw new Error(`refusing to seal a memory this module would not open: ${why}`);
  return { schema: SEAL_SCHEMA, hmac: mac(memory, key), memory };
}

/**
 * The memory inside an envelope, or why there is none.
 *
 * `{memory: null, discarded: null}` means there was no envelope at all — the
 * first run. `{memory: null, discarded: <why>}` means there was one and it was
 * refused: unsigned, signed by another key, altered, or of another shape. A
 * refused envelope is DISCARDED, never repaired, and the caller alarms
 * (`BOT_87_MEMORY_DISCARDED`): starting again re-seeds the sweep, and a tag
 * that arrived in the gap would be seeded rather than alarmed on.
 */
export function openMemory(envelope, key) {
  if (envelope === undefined || envelope === null) return { memory: null, discarded: null };
  const refuse = (why) => ({ memory: null, discarded: why });
  if (typeof envelope !== "object" || Array.isArray(envelope)) return refuse("the cache entry is not an object");
  if (envelope.schema !== SEAL_SCHEMA) return refuse(`the cache entry's schema is ${JSON.stringify(envelope.schema)}, not ${SEAL_SCHEMA}`);
  if (typeof envelope.hmac !== "string" || !/^[0-9a-f]{64}$/.test(envelope.hmac)) {
    return refuse("the cache entry carries no signature, so anything could have written it");
  }
  let want;
  try {
    want = mac(envelope.memory, key);
  } catch (e) {
    return refuse(`the cache entry's memory cannot be canonicalised: ${e.message}`);
  }
  const a = Buffer.from(want, "hex");
  const b = Buffer.from(envelope.hmac, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return refuse("the cache entry's signature does not verify under this key");
  }
  const why = memoryProblem(envelope.memory);
  if (why) return refuse(`the signed memory is malformed: ${why}`);
  return { memory: envelope.memory, discarded: null };
}

/**
 * `load`: the memory the Actions cache restored to `file`, verified.
 *
 * The one reader of the key besides `rememberMemory`. A missing file is the
 * first run; an unreadable one is discarded, like a bad signature.
 */
export function loadMemory({ file = MEMORY_FILE, env = process.env, now = new Date() } = {}) {
  const key = stateKey(env);
  let envelope = null;
  if (fs.existsSync(file)) {
    try {
      envelope = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
      return { memory: newMemory(now), discarded: `the cache entry is not JSON: ${e.message}`, fresh: true };
    }
  }
  const { memory, discarded } = openMemory(envelope, key);
  if (memory) return { memory, discarded: null, fresh: false };
  return { memory: newMemory(now), discarded, fresh: true };
}

/** `remember`: seal and write, for the Actions cache to save. */
export function rememberMemory({ memory, file = MEMORY_FILE, env = process.env }) {
  const key = stateKey(env);
  const sealed = sealMemory(memory, key);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(sealed)}\n`);
  return { file, hmac: sealed.hmac };
}

/**
 * MIG-23: seed the poll's tag memory from `state/releases-seen.json` at cutover,
 * before the file is retired (BOT-42). Tags only: the legacy ETag is not
 * carried, so the first live poll reads every feed in full rather than trusting
 * a cache key written by the backstop it replaces.
 */
export function seedFromReleasesSeen(memory, seen) {
  const out = structuredClone(memory);
  for (const [k, row] of Object.entries(seen?.repos ?? {})) {
    const tags = [...(row?.checked_tags ?? []), row?.last_seen_tag].filter((t) => typeof t === "string" && isUsableTag(t));
    if (tags.length === 0) continue;
    const key = repoKey(k);
    const mine = out.repos[key] ?? { etag: null, last_success_at: null, registered: [] };
    mine.registered = [...new Set([...mine.registered, ...tags])].slice(-REGISTERED_KEEP);
    out.repos[key] = mine;
  }
  return out;
}

// ── poll: a stranger's feed, and no key ────────────────────────────────────

/**
 * One listing's feed, judged. Pure.
 *
 * @param {{listing: object, row: object|undefined, feed: {changed: boolean, etag: string|null, entries: {tag: string}[]}}} opts
 * @returns {{candidates: string[], skipped: {tag: string, why: string}[], etag: string|null}}
 */
export function pollListing({ listing, row, feed }) {
  if (!feed.changed) return { candidates: [], skipped: [], etag: row?.etag ?? null };
  const memoryTags = row?.registered ?? [];
  const candidates = [];
  const skipped = [];
  for (const { tag } of feed.entries) {
    const v = tagVerdict(listing, tag, memoryTags);
    if (v.register) {
      if (!candidates.includes(tag)) candidates.push(tag);
    } else {
      skipped.push({ tag, why: v.why });
    }
  }
  return { candidates, skipped, etag: feed.etag };
}

/**
 * `poll`: every pollable listing's feed, with no quiet filter (BOT-41).
 *
 * Takes an opened memory and never a key. What it returns is what `claim`
 * registers and what `remember` saves; nothing here writes memory.
 */
export async function runPoll({ listings, memory, now = new Date(), fetchImpl = fetch }) {
  const out = { at: iso(now), repos: {} };
  for (const listing of listings) {
    const key = repoKey(listing.repo);
    const row = memory.repos[key];
    try {
      const feed = await pollFeed(listing.repo, row?.etag ?? null, fetchImpl);
      const judged = pollListing({ listing, row, feed });
      out.repos[key] = { id: listing.id, ok: true, changed: feed.changed, ...judged };
    } catch (e) {
      // One repository that 404s must not stop the walk; BOT-87's staleness
      // alarm is what notices it keeps failing.
      out.repos[key] = { id: listing.id, ok: false, error: String(e.message).slice(0, 200), candidates: [], skipped: [], etag: row?.etag ?? null };
    }
  }
  return out;
}

/**
 * `remember`'s rule, pure: the memory after a poll whose tags `claim` answered.
 *
 * `registered` is `claim`'s answer, `{repo, tag}` pairs. Two rules, and each is
 * the difference between a release that reaches the service and one that
 * never does, with nothing red:
 *
 *   * a tag enters memory only if `claim` said it was registered. Saved before
 *     that answer, a tag whose register failed is a tag every later poll
 *     believes was handled [U, OPEN-OPS-14];
 *   * a feed's new ETag is kept only when EVERY tag that feed produced was
 *     registered. Otherwise the old ETag stays, and the next poll reads the
 *     body again and offers the tag again. Saving it would get a 304 next
 *     time — "nothing changed" — and the unregistered tag would never be
 *     offered again.
 *
 * `last_success_at` moves whenever the feed answered, registered or not: it
 * is BOT-87's "last successful poll", and a failed register is claim's
 * failure, not the poll's.
 */
export function rememberPoll(memory, pollOutput, registered = []) {
  const out = structuredClone(memory);
  const reg = new Set((registered ?? []).map((r) => `${repoKey(r.repo)}\n${r.tag}`));
  for (const [key, res] of Object.entries(pollOutput.repos ?? {})) {
    if (!res.ok) continue;
    const row = out.repos[key] ?? { etag: null, last_success_at: null, registered: [] };
    const done = res.candidates.filter((t) => reg.has(`${key}\n${t}`));
    row.registered = [...new Set([...row.registered, ...done])].slice(-REGISTERED_KEEP);
    if (done.length === res.candidates.length) row.etag = res.etag ?? null;
    row.last_success_at = pollOutput.at;
    out.repos[key] = row;
  }
  return out;
}

/** BOT-87's first half: listings whose last successful poll is older than 3 intervals. */
export function staleListings(memory, listings, now = new Date()) {
  const bound = POLL_STALE_INTERVALS * POLL_INTERVAL_SECONDS * 1000;
  const t = new Date(now).getTime();
  const out = [];
  for (const l of listings) {
    const last = memory.repos[repoKey(l.repo)]?.last_success_at ?? null;
    const since = last ?? memory.started_at;
    if (t - new Date(since).getTime() > bound) out.push({ id: l.id, repo: l.repo, last_success_at: last });
  }
  return out;
}

// ── sweep: `git ls-remote`, counted in sweeps ──────────────────────────────

/**
 * `git ls-remote --tags --refs` output, as `{tag, sha}`. A line this cannot
 * read is refused rather than skipped: a sweep that silently read fewer tags
 * than the remote holds is a sweep that alarms on nothing.
 */
export function parseLsRemoteTags(text) {
  const out = [];
  for (const line of String(text ?? "").split("\n")) {
    if (line.trim() === "") continue;
    const m = /^([0-9a-f]{40})\trefs\/tags\/(.+)$/.exec(line);
    if (!m) throw new Error(`not a \`git ls-remote --tags --refs\` line: ${JSON.stringify(line.slice(0, 120))}`);
    const tag = m[2];
    if (tag.endsWith("^{}")) throw new Error(`a peeled line reached the parser; run with --refs: ${JSON.stringify(tag)}`);
    if (!isUsableTag(tag)) continue; // BOT-74 would never register it, so it can never be missed
    out.push({ tag, sha: m[1] });
  }
  return out;
}

/** The tags of `https://github.com/<repo>`, with no credential and no REST budget. */
export function lsRemoteTags(repo, run = execFileSync) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(repo))) throw new Error(`${JSON.stringify(repo)} is not owner/name`);
  const text = run("git", ["ls-remote", "--tags", "--refs", `https://github.com/${repo}.git`], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    env: { ...cleanEnv(), GIT_TERMINAL_PROMPT: "0" },
  });
  return parseLsRemoteTags(text);
}

/**
 * One listing at one sweep. Pure.
 *
 * A tag not seen before is recorded with the sweep it was first seen at, and
 * seeded — never alarmed on — when `seed` says so (MIG-23: the first sweep, or
 * the first sweep of a repository, records every tag that exists). A tag seen
 * at an EARLIER sweep that matches the prefix and that nothing handled alarms:
 * not the poll (its memory), not a version record, not any decision record.
 * `git ls-remote` gives names and SHAs with no dates, so age is counted in
 * sweeps (BOT-87's Why).
 *
 * @returns {{tags: object, alerts: {id: string, repo: string, tag: string, sha: string}[]}}
 */
export function sweepListing({ listing, known = {}, remote, sweepNo, seed, registered = [] }) {
  const tags = {};
  const alerts = [];
  for (const { tag, sha } of remote) {
    const was = known[tag];
    if (!was) {
      tags[tag] = { sha, first_seen: sweepNo, seeded: seed === true };
      continue;
    }
    tags[tag] = { ...was, sha };
    if (was.seeded || was.first_seen >= sweepNo) continue;
    if (!matchesPrefix(listing.prefix, tag)) continue;
    if (registered.includes(tag) || listing.recorded_tags.includes(tag) || listing.named_tags.includes(tag)) continue;
    alerts.push({ id: listing.id, repo: listing.repo, tag, sha });
  }
  return { tags, alerts };
}

/**
 * `sweep`: every pollable listing's remote tags, against the memory.
 *
 * Takes no key. Returns the memory to hand to `remember` and what to alarm on.
 * `seed: true` is B-T5.1's cutover run (MIG-23); a memory that has never swept
 * seeds on its own.
 */
export function runSweep({ memory, listings, lsRemote = lsRemoteTags, now = new Date(), seed = false }) {
  const out = structuredClone(memory);
  const sweepNo = out.sweep.count + 1;
  const seedAll = seed === true || out.sweep.count === 0;
  const alerts = [];
  const failed = [];
  for (const listing of listings) {
    const key = repoKey(listing.repo);
    let remote;
    try {
      remote = lsRemote(listing.repo);
    } catch (e) {
      failed.push({ id: listing.id, repo: listing.repo, error: String(e.message).slice(0, 200) });
      continue;
    }
    const known = out.sweep.repos[key];
    const r = sweepListing({
      listing,
      known: known ?? {},
      remote,
      sweepNo,
      // A repository swept for the first time records what it already holds:
      // a newly listed plugin's earlier releases were never this poll's to
      // register, and alarming on them tomorrow would page for history.
      seed: seedAll || known === undefined,
      registered: out.repos[key]?.registered ?? [],
    });
    out.sweep.repos[key] = r.tags;
    alerts.push(...r.alerts);
  }
  out.sweep.count = sweepNo;
  out.sweep.last_at = iso(now);
  return { memory: out, alerts, failed, sweep: sweepNo, seeded: seedAll };
}

// ── the alarm ──────────────────────────────────────────────────────────────

/**
 * BOT-87's alarm, as the verdict `bot/lib/alert-verdict.mjs` renders.
 *
 * Plugin ids and 40-hex SHAs only. A tag is a stranger's text and the channel
 * carries none; the SHA and the id find it.
 */
export function bot87Verdict({ unregistered = [], stale = [], discarded = null, failed = [], run } = {}) {
  const codes = [];
  if (unregistered.length) codes.push(BOT_87_CODES.unregistered);
  if (stale.length) codes.push(BOT_87_CODES.stale);
  if (discarded) codes.push(BOT_87_CODES.discarded);
  if (failed.length) codes.push(BOT_87_CODES.sweepFailed);
  const ids = [...new Set([...unregistered, ...stale, ...failed].map((x) => x.id))].sort().slice(0, 40);
  const hexes = [...new Set(unregistered.map((x) => x.sha))].sort().slice(0, 40);
  const verdict = {
    schema: VERDICT_SCHEMA,
    check: SWEEP_CHECK,
    status: codes.length ? "red" : "green",
    ...(codes.length ? { codes } : {}),
    ...(ids.length ? { ids } : {}),
    ...(hexes.length ? { hexes } : {}),
    ...(run ? { run } : {}),
  };
  const problems = verdictProblems(verdict);
  if (problems.length) throw new Error(`BOT-87's verdict would be refused by the channel:\n  - ${problems.join("\n  - ")}`);
  return verdict;
}
