// The takedown bound: how much the estate has withdrawn in the trailing 24
// hours, counted out of git.
//
// Registry plan M-T3.2 (TRUST-26, BOT-32, MOD-9, FLOW-79, FLOW-42). At R2 exit
// this is DARK: nothing imports it. `bot/moderation-run.mjs` (M-T3.4) is the
// first caller, and what it does with the answer is hand `overBound` to
// `holdKindFor` in `bot/lib/holds.mjs`, which is what turns a full bound into a
// `bound` hold waiting for an operator's MOD-52 confirmation.
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
// of that key. The key is not on `main` today, so the exclusion currently
// excludes nothing and is live the moment M-T2.1 lands it — written against
// the absence rather than waiting for the value.
//
// **A MOD-52 revert.** M-T3.2 calls this "the one place a trailer test is
// kept". There is no trailer to test, and the exclusion does not need one:
//
//   * no revert trailer exists on `main`. `operator.yml` is not written
//     (M-T3.5), and the revert commit that task specifies carries
//     `Service-Decision:` — the same trailer a service takedown carries. A
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

/** TRUST-26's window. Trailing, from `now`, on committer date — see `countWindow`. */
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
 * `--since` filters on COMMITTER date, which is what "the estate withdrew it"
 * means: a commit authored last week and pushed to `main` an hour ago took the
 * plugin away an hour ago, and the bound is about what reached installed
 * copies. `--no-merges` matches `tools/moderation-coverage.mjs`'s walk, and
 * every commit that reaches `main` here arrives as a squash.
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

  const shas = git(["rev-list", "--no-merges", `--since=${since}`, "HEAD"], { cwd: repo, allowFailure: true })
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
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
    `examined ${shas.length} commit(s) since ${since}; HEAD is ${head.sha.slice(0, 8)} dated ${head.at}`,
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
