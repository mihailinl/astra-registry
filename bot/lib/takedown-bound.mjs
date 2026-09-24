// The takedown bound: how much the estate has withdrawn in the trailing 24
// hours, counted out of git.
//
// Registry plan M-T3.2 (TRUST-26, BOT-32, MOD-9, FLOW-79, FLOW-42).
// `bot/moderation-run.mjs`'s `commit` job (M-T3.4) is its caller: it counts the
// window with `countWindow`, spends it entry by entry through `boundLedger` and
// `withdrawnBy` below, and hands each takedown's `overBound` to `holdKindFor`
// in `bot/lib/holds.mjs`, which is what turns a full bound into a `bound` hold
// waiting for an operator's MOD-52 confirmation. That job is dark until the
// R3-open commit uncomments its schedule.
//
// ── THE COUNT IS OF THE TREE, NOT OF A TRAILER ──────────────────────────────
//
// TRUST-26 names no commit trailer. It states two exclusions and only two: a
// MOD-52 revert, and MOD-16's staging listing by its reserved id. An earlier
// reading of this task counted only commits carrying `Service-Decision:`, and
// the attack that removed it (M-2) is worth keeping in front of the next
// person, because the scenario is one day and not an edge:
//
//     After a supply-chain report the operator hand-advises three listed
//     plugins. Each of those commits carries `Moderation-Exempt: <actor>:
//     <reason>` (RUNBOOK §7.1, §7.3) and no `Service-Decision:`, because no
//     service decided them. Within the same 24 hours a moderator issues
//     `M_REVOKE` with action `disable` on a fourth plugin. TRUST-26 puts the
//     estate at the bound, so MOD-9 should hold that decision — and the
//     trailer-filtered counter returns 0, the bot applies it at once, and
//     four withdrawals reach installed copies inside 24 h. The bound did not
//     apply on the one day the registry was withdrawing by hand, which is the
//     day it was written for.
//
// So: whatever trailer a commit carries. The count is over what the tree says
// happened, which is also the only reading under which an author's yank and a
// moderator's yank cost the same — and TRUST-26 says they do (FLOW-79).
//
// ── THE UNIT IS A LISTED PLUGIN ID ──────────────────────────────────────────
//
// Not an action and not a commit: TRUST-26 counts "listed plugin ids", and
// FLOW-42 caps an account at "one listed plugin id in any trailing 24 h". So
// two versions of one plugin yanked in one commit is 1, and one advisory that
// newly matches two listed siblings is 2. The set is deduplicated across the
// whole window, so a plugin withdrawn twice in a day still costs one — the
// bound is a cap on how much of the catalogue can be taken away, and taking
// the same plugin away twice takes away one plugin.
//
// ── WHAT A WITHDRAWAL LOOKS LIKE IN THE TREE ────────────────────────────────
//
// Each is read at a commit on HEAD's first-parent line against that commit's
// first parent — so a pull request merged with a merge commit is read at the
// merge, which is when `main` lost the plugin (`countWindow` says why, and
// what it measured when this read every non-merge commit instead).
//
//   delist        `plugins/<id>/plugin.json` turns `unlisted: true` for a
//                 listing that was listed at the parent commit.
//   yank          `plugins/<id>/versions/<v>.json` turns `yanked: true`.
//   advisory      an entry under `tools/revocations/**` NEWLY matches a listed
//                 id — newly, so that re-signing, reformatting or narrowing an
//                 advisory costs nothing, and only a match the estate did not
//                 have before is a withdrawal.
//
// The first two are read through `triggersOf` in `tools/moderation-coverage.mjs`
// rather than re-derived here. That is deliberate and it is not only tidiness:
// "turns `unlisted` on for an EXISTING listing" needs the parent's copy of the
// file to separate a delist from a listing created unlisted, MOD-16's staging
// id is exactly such a listing, and a second implementation of that comparison
// is a second one that can be wrong about it. Two rules disagreeing about
// "what did this commit withdraw" is the failure where one of them is quietly
// counting a smaller set than the other.
//
// **An `A_YANK` and a bound account's removal request need no separate source,
// and this is the part worth reading twice.** An applied author yank writes
// `yanked: true`, which is the `yank` trigger. An applied removal request
// delists, which is the `delist` trigger. An UNBOUND removal request or yank is
// held (`unbound_removal`, `unbound_yank`) and never reaches the tree at all —
// so the tree reading gets TRUST-26's "a BOUND account's removal request
// counts" exactly right, for free, without the bot ever learning which account
// acted. Which is as well, because it cannot: TRUST-37 forbids the service to
// reveal it, BOT-80's `A_*` entry carries no account, and DEC-7 forbids an
// account id in a record.
//
// ── FLOW-42'S PER-ACCOUNT CAP IS NOT IMPLEMENTED HERE, AND CANNOT BE ────────
//
// FLOW-42 caps each account at one listed plugin id in any trailing 24 h. That
// cap is the SERVICE's. For the reason in the paragraph above, a check here
// claiming to watch it would be watching a number the bot cannot see. The
// registry's half of TRUST-26 is the estate-wide count and nothing else.
//
// ── THE TWO EXCLUSIONS, AND THE ONE THE PLAN EXPECTED A TRAILER TO DECIDE ───
//
// **The staging listing, by id.** `policy/reserved-ids.json`'s
// `staging_listing_id` (M-T2.1, MOD-16), read through
// `tools/moderation-coverage.mjs`'s `stagingListingId` so there is one reader
// of that key. It was written against the ABSENCE of that key rather than
// waiting for a value, and the value arrived: M-T2.1 committed
// `staging_listing_id: "astra-withdrawal-canary"`, so the exclusion is live
// and excludes that id. What is still absent is the LISTING — M-T2.2
// publishes it — so nothing is excluded in practice yet, and the run's own
// detail line says which of the two states it is in rather than leaving a
// reader to infer it from here.
//
// (This paragraph said "the key is not on `main` today" until the day the key
// landed, which is the whole of the lesson: a comment that dates itself has to
// be read by the commit that makes it false, and this one was only because
// M-T2.1 went looking for every reader of the member.)
//
// **A MOD-52 revert.** M-T3.2 calls this "the one place a trailer test is
// kept". There is no trailer to test, and the exclusion does not need one:
//
//   * no revert trailer exists. `operator.yml` (M-T3.5, `tools/operator.mjs`)
//     commits a revert with `Service-Decision:` naming the reverted decision,
//     as MOD-52 requires — the same trailer a service takedown carries. A
//     filter on it would exclude every service takedown, which is the M-2
//     defect with the sign flipped;
//   * it is structural anyway. A revert's tree change is the REMOVAL of a
//     withdrawal — `unlisted` deleted, or the advisory file deleted — and
//     every rule above counts only additions. `advisory-deleted` is dropped
//     on the floor here for the same reason: a deletion gives something back.
//
// So a revert counts 0 because of what it does to the tree, not because of
// what its message says, and `bot/tests/takedown-bound.test.mjs` walks all
// three revert shapes to prove it. Raised for the plan rather than decided
// silently: if a revert is ever given a trailer of its own, the exclusion
// becomes a one-line filter and this paragraph is what it replaces.
//
// ── AN UNCOUNTABLE WITHDRAWAL IS NOT A COUNT OF ZERO ────────────────────────
//
// Three of the seven advisory kinds cannot be resolved to a listed plugin id
// from this repository's own records, and this was measured rather than
// assumed:
//
//   binary         a sha256 of a resolved `entry.command` binary. The registry
//                  records no such hash; grep for it returns the KINDS comment
//                  and nothing else.
//   publisher_key  matched against a trust record's `signer_key_id`, which
//                  lives on a user's machine. `signer_key_id` appears in this
//                  repository exactly once, in that same comment.
//   identity       `origin:<host>` — resolvable to zero only while every
//                  listing is a GitHub source, which `schema/plugin-v1.json`
//                  pins with `"kind": {"const": "github"}`. Checked against
//                  the listings actually in the tree, not against the schema,
//                  so a listing that ever stops being one makes this unknown
//                  instead of quietly making it zero.
//
// A withdrawal published under one of those is a real withdrawal that this
// counter cannot see, and reporting 0 for it is the M-2 failure again. So the
// count comes back `null` with a reason, and `overBound` reads an unknown
// count as OVER the bound: the direction that holds a takedown for an operator
// is the direction a counter that does not know must take. A shallow checkout
// is the same answer for the same reason — it cannot read the parent of the
// oldest commit in the window, so every withdrawal in it would read as a file
// created already withdrawn, which is not a trigger and would report green.

import { KINDS } from "../../tools/lib/revocations.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { commitMeta, firstParent, git, isShallow, jsonAt } from "../../tools/coverage/git.mjs";
import { stagingListingId, triggersOf } from "../../tools/moderation-coverage.mjs";

import { TAKEDOWN_BOUND } from "./moderation.mjs";

/**
 * TRUST-26's window. Trailing, from `now`, over HEAD's first-parent line, on
 * the committer date of the first-parent commit that brought a withdrawal onto
 * `main` — see `countWindow`.
 */
export const WINDOW_HOURS = 24;

/** `plugins/<id>/plugin.json`, out of a `git ls-tree` listing. */
const PLUGIN_JSON_RE = /^plugins\/([^/]+)\/plugin\.json$/;
/** `plugins/<id>/versions/<semver>.json`. */
const VERSION_JSON_RE = /^plugins\/([^/]+)\/versions\/([^/]+)\.json$/;

const iso = (d) => new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z");

// ── the tree at a commit ────────────────────────────────────────────────────

/**
 * Every path under `plugins/` at one commit.
 *
 * NUL-separated: a path with a newline in it is legal in git, and
 * line-splitting a tree somebody else can add files to is how a walk stops
 * seeing a file that is right there.
 */
function pluginPathsAt(sha, repo) {
  const out = git(["ls-tree", "-r", "-z", "--name-only", sha, "--", "plugins"], { cwd: repo, allowFailure: true });
  return out.split("\0").filter(Boolean);
}

/**
 * The LISTED plugins at one commit: id → `{repo, kind}` out of `source`.
 *
 * "Listed" is `unlisted !== true`, which is `tools/build-index.mjs`'s own rule
 * for what reaches the catalogue. A listing that is already unlisted has
 * nothing left to take away, so it is not in this map and nothing can withdraw
 * it a second time.
 */
function listedAt(sha, repo, cache) {
  const hit = cache.listed.get(sha);
  if (hit) return hit;
  const listed = new Map();
  for (const p of pluginPathsAt(sha, repo)) {
    const m = PLUGIN_JSON_RE.exec(p);
    if (!m) continue;
    const { value } = jsonAt(sha, p, repo);
    if (!value || value.unlisted === true) continue;
    listed.set(m[1], { repo: value.source?.repo ?? null, kind: value.source?.kind ?? null });
  }
  cache.listed.set(sha, listed);
  return listed;
}

/**
 * sha256 of a published artifact → the listed id that published it, at one
 * commit. Built only when a `digest` advisory is actually met, because it is a
 * `git show` per version file and most commits never need it.
 */
function digestsAt(sha, repo, cache) {
  const hit = cache.digests.get(sha);
  if (hit) return hit;
  const listed = listedAt(sha, repo, cache);
  const digests = new Map();
  for (const p of pluginPathsAt(sha, repo)) {
    const m = VERSION_JSON_RE.exec(p);
    if (!m || !listed.has(m[1])) continue;
    const { value } = jsonAt(sha, p, repo);
    for (const artifact of Object.values(value?.artifacts ?? {})) {
      if (typeof artifact?.sha256 === "string") digests.set(artifact.sha256.toLowerCase(), m[1]);
    }
  }
  cache.digests.set(sha, digests);
  return digests;
}

// ── one advisory entry → the listed ids it matches ──────────────────────────

/**
 * Which listed ids one advisory entry withdraws, at one commit.
 *
 * `unresolved` is the load-bearing half: a kind this cannot map is a
 * withdrawal the bound would otherwise under-count, and the caller turns it
 * into an unknown rather than into a zero.
 *
 * @returns {{ids: string[], unresolved: string|null}}
 */
export function idsMatchedBy(entry, { listed }, digests = null) {
  const kind = entry?.kind;
  const value = String(entry?.value ?? "");
  const has = (id) => (listed.has(id) ? [id] : []);

  switch (kind) {
    case "id":
      return { ids: has(value), unresolved: null };
    case "version_range":
      return { ids: has(value), unresolved: null };
    case "id_version":
      return { ids: has(value.split("@")[0]), unresolved: null };

    case "identity": {
      if (value.startsWith("github:")) {
        // The siblings case, and the one that makes "siblings included" worth
        // stating: one `identity` advisory against a monorepo withdraws every
        // listed plugin published from it, and TRUST-26 counts each.
        const slug = value.slice("github:".length).toLowerCase();
        const ids = [...listed]
          .filter(([, src]) => src.kind === "github" && String(src.repo ?? "").toLowerCase() === slug)
          .map(([id]) => id);
        return { ids, unresolved: null };
      }
      if (value.startsWith("origin:")) {
        const foreign = [...listed].filter(([, src]) => src.kind !== "github").map(([id]) => id);
        if (foreign.length === 0) return { ids: [], unresolved: null };
        return {
          ids: [],
          unresolved:
            `an identity advisory for ${value} cannot be resolved: ${foreign.length} listing(s) are not GitHub ` +
            `sources (${foreign.slice(0, 3).join(", ")}) and this registry records no origin host for them`,
        };
      }
      return { ids: [], unresolved: `identity advisory value ${JSON.stringify(value)} is neither github: nor origin:` };
    }

    case "digest": {
      const id = digests?.get(value.toLowerCase());
      return { ids: id ? [id] : [], unresolved: null };
    }

    case "binary":
      return {
        ids: [],
        unresolved:
          "a `binary` advisory names the sha256 of a resolved entry.command binary, which this registry does " +
          "not record for any listing, so the listed ids it withdraws cannot be counted from the tree",
      };

    case "publisher_key":
      return {
        ids: [],
        unresolved:
          "a `publisher_key` advisory is matched against a trust record's signer_key_id, which lives on a " +
          "user's machine; this registry records no signer key for any listing",
      };

    default:
      return {
        ids: [],
        unresolved:
          `advisory kind ${JSON.stringify(kind)} is not one this counter maps to listed ids ` +
          `(it knows ${Object.keys(KINDS).join(", ")}); an unmapped kind is a withdrawal counted as nothing`,
      };
  }
}

/** Every listed id one advisory file matches at one commit. */
function advisoryMatchesAt(sha, file, repo, cache) {
  const { value } = jsonAt(sha, file, repo);
  const entries = Array.isArray(value?.entries) ? value.entries : [];
  if (entries.length === 0) return { ids: new Set(), unresolved: [] };
  const listed = listedAt(sha, repo, cache);
  const needsDigests = entries.some((e) => e?.kind === "digest");
  const digests = needsDigests ? digestsAt(sha, repo, cache) : null;

  const ids = new Set();
  const unresolved = [];
  for (const entry of entries) {
    const got = idsMatchedBy(entry, { listed }, digests);
    for (const id of got.ids) ids.add(id);
    if (got.unresolved) unresolved.push(`${file}: ${got.unresolved}`);
  }
  return { ids, unresolved };
}

// ── the count ───────────────────────────────────────────────────────────────

function unknownWindow(since, why) {
  return { count: null, ids: [], since, head: null, examined: 0, unknown: why, detail: [why] };
}

/**
 * The listed plugin ids the estate withdrew in the trailing window.
 *
 * **A withdrawal is dated where `main` acquired it: at the commit on HEAD's
 * first-parent line that brought it, read against that commit's first
 * parent, on that commit's committer date.** TRUST-26 counts "the listed
 * plugin ids delisted, yanked or newly advised in the trailing 24 h", and
 * scopes "listed" to a plugin with a `plugins/` directory on `main`. A plugin
 * delisted on a branch is still listed on `main`, and still served, until the
 * branch lands; for a pull request merged with a merge commit that moment is
 * the merge, and the branch commit that wrote the change is not it. A bot
 * direct push, a squash merge and a rebase merge each land as single-parent
 * commits on the first-parent line, committed when they landed, and were
 * counted rightly before this and are counted the same after it.
 *
 * This walk was `rev-list --no-merges --since=…`, which dates the commit that
 * WROTE a change and never reads a merge. Measured 2026-09-22 at `aa0d08e`,
 * on fixtures, before the repair: a delist committed on a branch 37 h before
 * `now` and merged `--no-ff` 2 h before it counted **0**; so did the same
 * through a branch that had merged `main` in, and a delist a merge commit
 * carried itself (a conflict resolution). Beside a direct delist an hour old,
 * the first case counted 1 where 2 plugins had left the catalogue inside the
 * window. The error only ever ran one way — too permissive, a takedown
 * applied that MOD-9 would have held — and on the shape this repository's pull
 * requests merge with: HEAD's first-parent line held 86 merges in 303 commits
 * at `aa0d08e`, against this comment's old claim that "every commit that
 * reaches `main` here arrives as a squash". The other direction is real too
 * and is the correct one: a branch that delisted and relisted before merging
 * took nothing out of the catalogue, and costs 0 now where it cost 1.
 *
 * **The window is applied here, per commit, and not with `--since`.** Git
 * stops a `--since` walk at the first commit older than the cut, so one
 * first-parent commit dated before its parent — clock skew, or a
 * `rebase --committer-date-is-author-date` pushed as a fast-forward — would
 * hide every withdrawal behind it. Measured on a fixture: first-parent commits
 * dated −60 h, −7 h, −48 h and −1 h from `now`, and `--since` returned the
 * −1 h commit alone. Every first-parent commit dated before its parent at
 * `aa0d08e`: 0 of 303, so this has not happened here; the whole line is one
 * `rev-list` either way.
 *
 * **What this cannot date: a fast-forward of an old commit.** Git records no
 * time for a ref moving, so a commit written 37 h ago and fast-forwarded onto
 * `main` 2 h ago is dated 37 h ago and falls outside the window, before this
 * repair and after it. `main`'s ruleset forbids deletion and non-fast-forward
 * only, and direct pushes are allowed. It is gap 68's open limit, and
 * `tools/served-set/main-vs-signed.mjs` carries the same one.
 *
 * `tools/moderation-coverage.mjs` walks every commit that is not a merge
 * (`commitsAfter`, `--no-merges`) and, since gap 93 (astra-registry #221),
 * every merge on what its own resolution changed (`mergesAfter`,
 * `mergeOwnChanges`, `mergeView`) — never on a merge's first-parent diff,
 * which would judge each branch commit a second time. The two walks differ on
 * purpose: coverage asks who made each change and whether they left a record,
 * which is a question about the commit that made it; this asks when the
 * catalogue lost a plugin, which is a question about `main`, so a branch's
 * withdrawal counts here once, at the first-parent commit that brought it.
 * Both read a commit's withdrawals through the one `triggersOf` — this walk
 * with its first-parent view, coverage with the view of the change it is
 * judging — which is the part that must not have two implementations.
 *
 * **A history git cannot walk is an unknown count and not a zero.** The walk
 * used to run with `allowFailure`, under which a `rev-list` that fails — a
 * missing object, a spawn refused — is an empty list: a count of 0 with no
 * reason, and the takedown out unheld. Reading the whole first-parent line
 * reaches objects a `--since` walk stopped short of, so the repair would have
 * widened that hole had it kept the flag; it throws instead, and the throw
 * is an unknown.
 *
 * A zero is never bare. `head` and `examined` come back with it, so "nothing
 * was withdrawn today" can be told apart from "the walk looked at nothing",
 * which are the same number and not the same fact.
 *
 * @param {string} repo
 * @param {{now?: Date, windowHours?: number}} opts
 * @returns {{
 *   count: number|null,
 *   ids: {id: string, why: string[]}[],
 *   since: string,
 *   head: {sha: string, at: string}|null,
 *   examined: number,
 *   unknown: string|null,
 *   detail: string[],
 * }}
 */
export function countWindow(repo = REPO_ROOT, { now = new Date(), windowHours = WINDOW_HOURS } = {}) {
  const since = iso(new Date(now).getTime() - windowHours * 3600_000);

  if (isShallow(repo)) {
    return unknownWindow(
      since,
      "this checkout is shallow, so the oldest commit in the window has no parent here and every withdrawal " +
      "in it would read as a file created already withdrawn — which is not a trigger, and would report a " +
      "count of 0 for a day the registry spent taking plugins away. The job that reads this bound needs " +
      "`fetch-depth: 0`",
    );
  }

  let head;
  try {
    const meta = commitMeta("HEAD", repo);
    head = { sha: meta.sha, at: meta.date };
  } catch (err) {
    return unknownWindow(since, `HEAD is not readable here, so no window can be walked: ${err.message}`);
  }

  // `--timestamp` is the committer date, which `--since` compared; `rev-list`
  // is plumbing, so no `log.*` setting can add a line to what is parsed here.
  const sinceSeconds = Date.parse(since) / 1000;
  let line;
  try {
    line = git(["rev-list", "--first-parent", "--timestamp", "HEAD"], { cwd: repo });
  } catch (err) {
    return unknownWindow(
      since,
      `HEAD's first-parent line cannot be walked here, so the window is not a count: ${err.message}`,
    );
  }
  const shas = line
    .split("\n")
    .map((s) => s.trim().split(" "))
    .filter(([at, sha]) => sha && Number(at) >= sinceSeconds)
    .map(([, sha]) => sha)
    .reverse();

  const cache = { listed: new Map(), digests: new Map() };
  const staging = stagingListingId(repo);
  const withdrawn = new Map();
  const unresolved = [];
  const detail = [];
  const skipped = [];

  const add = (id, sha, why) => {
    if (staging && id === staging) {
      skipped.push(`${sha.slice(0, 8)} ${why}, and ${id} is policy/reserved-ids.json's staging_listing_id (MOD-16)`);
      return;
    }
    if (!withdrawn.has(id)) withdrawn.set(id, []);
    withdrawn.get(id).push(`${sha.slice(0, 8)} ${why}`);
  };

  for (const sha of shas) {
    const { triggers } = triggersOf(sha, repo);
    for (const t of triggers) {
      switch (t.kind) {
        case "delist":
          add(t.id, sha, `delisted ${t.id} (${t.path} turned unlisted)`);
          break;
        case "yank":
          add(t.id, sha, `yanked ${t.id}@${t.version}`);
          break;
        case "advisory-written": {
          // NEWLY matched, against the same file at the parent. Re-signing,
          // reformatting and narrowing an advisory all leave this empty, and
          // only a match the estate did not have a commit ago is a withdrawal.
          const parent = firstParent(sha, repo);
          const after = advisoryMatchesAt(sha, t.path, repo, cache);
          const before = parent ? advisoryMatchesAt(parent, t.path, repo, cache) : { ids: new Set(), unresolved: [] };
          unresolved.push(...after.unresolved);
          for (const id of after.ids) {
            if (before.ids.has(id)) continue;
            add(id, sha, `advisory ${t.advisory} newly withdraws ${id}`);
          }
          break;
        }
        case "advisory-deleted":
          // A deletion gives something back. Never a takedown, and the one
          // shape a MOD-52 revert of a deprecate or a revoke takes.
          skipped.push(`${sha.slice(0, 8)} deleted advisory ${t.advisory}, which gives a withdrawal back`);
          break;
        default:
          break;
      }
    }
  }

  detail.push(
    `examined ${shas.length} commit(s) on HEAD's first-parent line since ${since}; ` +
    `HEAD is ${head.sha.slice(0, 8)} dated ${head.at}`,
  );
  if (staging) detail.push(`the staging listing ${staging} is excluded by id (MOD-16)`);
  else detail.push("policy/reserved-ids.json carries no staging_listing_id, so nothing is excluded by id yet (M-T2.1)");
  detail.push(...skipped);
  for (const [id, whys] of [...withdrawn].sort()) detail.push(`${id}: ${whys.join("; ")}`);

  if (unresolved.length) {
    const why =
      `${unresolved.length} advisory entr${unresolved.length === 1 ? "y" : "ies"} in the window cannot be ` +
      `resolved to listed ids, so the count is not a count: ${unresolved.join(" | ")}`;
    return { count: null, ids: [], since, head, examined: shas.length, unknown: why, detail: [...detail, why] };
  }

  return {
    count: withdrawn.size,
    ids: [...withdrawn].sort().map(([id, why]) => ({ id, why })),
    since,
    head,
    examined: shas.length,
    unknown: null,
    detail,
  };
}

// ── the predicate MOD-9 reads ───────────────────────────────────────────────

/**
 * Is the estate at or above the bound, so that the next takedown is held?
 *
 * At the bound it applies and at bound + 1 it holds: with the bound at 3 and
 * two withdrawals already made today, the third is the third and goes through;
 * with three already made, the fourth waits for an operator. So the test is
 * `count >= bound`, which is also how `holdKindFor` in `bot/lib/holds.mjs`
 * words its `overBound` argument.
 *
 * **An unknown count is over the bound.** A counter that cannot see the window
 * must not be the reason a fourth withdrawal reaches installed copies; the cost
 * of the other direction is a takedown that waits for a confirmation, and the
 * cost of this one is the M-2 scenario in this file's header.
 *
 * @param {{count: number|null, unknown: string|null}|number|null} counted
 *        a `countWindow` result, or a bare count.
 * @returns {{over: boolean, reason: string}}
 */
export function overBound(counted, { bound = TAKEDOWN_BOUND } = {}) {
  const result = typeof counted === "number" || counted === null ? { count: counted, unknown: null } : counted;
  if (result.count === null) {
    return {
      over: true,
      reason:
        `the takedown bound cannot be counted, so every takedown is held for an operator: ` +
        `${result.unknown ?? "no count and no reason, which is itself the defect"}`,
    };
  }
  if (result.count >= bound) {
    return {
      over: true,
      reason:
        `${result.count} listed plugin id(s) were withdrawn in the trailing ${WINDOW_HOURS} h and the bound ` +
        `is ${bound}, so a takedown now waits for an operator's confirmation (TRUST-26, MOD-9)`,
    };
  }
  return {
    over: false,
    reason: `${result.count} of ${bound} withdrawals used in the trailing ${WINDOW_HOURS} h`,
  };
}

// ── the bound as a batch spends it (M-T3.4) ─────────────────────────────────
//
// `countWindow` answers for the tree as it stands. A moderation run compiles a
// whole list answer into ONE commit, and every takedown it compiles adds to
// the count before the next is asked — so the question MOD-9 asks is not "is
// the estate over the bound" but "is it over the bound after the takedowns
// this run has already admitted". A run that asked once and applied the answer
// to every entry let a batch of four through a bound of three, on the fixture
// that measured it, and the day the bound exists for is exactly the day that
// batch arrives.
//
// The ledger starts from the window's own set of ids, so a plugin already
// withdrawn today costs nothing a second time, and the staging listing costs
// nothing at all (MOD-16), both as `countWindow` counts them. An unknown count
// stays unknown for the rest of the run, and unknown is over.

/**
 * @param {{count: number|null, ids?: {id: string}[], unknown?: string|null}} counted a `countWindow` result
 * @param {{bound?: number, staging?: string|null}} [opts]
 */
export function boundLedger(counted, { bound = TAKEDOWN_BOUND, staging = null } = {}) {
  const spent = new Set((counted?.ids ?? []).map((x) => x.id));
  let count = typeof counted?.count === "number" ? counted.count : null;
  let unknown = count === null ? (counted?.unknown ?? "no count was made, and no reason was given for it") : null;
  const admitted = [];
  return {
    get count() { return count; },
    get unknown() { return unknown; },
    get admitted() { return [...admitted]; },
    /** Is the next takedown over the bound? */
    over() { return overBound({ count, unknown }, { bound }).over; },
    /** Why, in the words `overBound` uses. */
    reason() { return overBound({ count, unknown }, { bound }).reason; },
    /**
     * Spend what one compiled takedown withdraws. An unresolved entry makes the
     * rest of the run's count unknown, which holds every takedown after it.
     */
    spend({ ids = [], unresolved = [] } = {}) {
      if (unresolved.length) {
        count = null;
        unknown = `a takedown this run compiled cannot be counted: ${unresolved.join(" | ")}`;
      }
      for (const id of ids) {
        if (staging && id === staging) continue;
        if (spent.has(id)) continue;
        spent.add(id);
        admitted.push(id);
        if (count !== null) count += 1;
      }
    },
  };
}

/** The listed plugins, and their artifacts' digests, at `HEAD` — what a batch compiles against. */
export function headListing(repo = REPO_ROOT) {
  const cache = { listed: new Map(), digests: new Map() };
  const listed = listedAt("HEAD", repo, cache);
  return { listed, digests: digestsAt("HEAD", repo, cache) };
}

/**
 * The listed ids one compiled takedown withdraws: a listing turned `unlisted`
 * or a version turned `yanked` by its edits, and every listed id its
 * advisories' entries match, siblings included — the three triggers
 * `countWindow` reads out of a commit, read here out of the commit about to be
 * made.
 *
 * @param {{edits?: object[], advisories?: {entries?: object[]}[]}} result a `compileDecision` result
 * @param {{listed: Map<string, object>, digests: Map<string, string>|null}} head `headListing`'s answer
 */
export function withdrawnBy(result, { listed, digests }) {
  const ids = new Set();
  const unresolved = [];
  for (const e of result?.edits ?? []) {
    if (e?.op !== "set" || e.value !== true) continue;
    const plugin = PLUGIN_JSON_RE.exec(String(e.file ?? ""));
    const version = VERSION_JSON_RE.exec(String(e.file ?? ""));
    const id = e.member === "unlisted" && plugin ? plugin[1] : e.member === "yanked" && version ? version[1] : null;
    if (id && listed.has(id)) ids.add(id);
  }
  for (const advisory of result?.advisories ?? []) {
    for (const entry of advisory?.entries ?? []) {
      const got = idsMatchedBy(entry, { listed }, digests);
      for (const id of got.ids) ids.add(id);
      if (got.unresolved) unresolved.push(`${advisory.id ?? "<advisory>"}: ${got.unresolved}`);
    }
  }
  return { ids: [...ids].sort(), unresolved };
}
