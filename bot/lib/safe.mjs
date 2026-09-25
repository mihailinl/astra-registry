// `owner/name` and a release tag, re-checked against their charsets before
// they are echoed back or written into a record.
//
// Moved here from `bot/lib/intake.mjs` by cutover commit D (registry plan
// B-T5.2), which deletes that module with the rest of the issue path. These
// two functions were the only part of it that anything outside that path
// imported: the service path (`bot/lib/service-decide.mjs`,
// `bot/lib/service-jobs.mjs`), the decision writer (`bot/lib/decisions.mjs`),
// `bot/decide.mjs`, `bot/baseline.mjs`, and MIG-21's export of the issue
// history (`bot/export-issues.mjs`). They moved without a change in behaviour;
// `bot/tests/poll.test.mjs` still pins `safeTag` against `isUsableTag`.

import { TAG_PATTERN } from "../../tools/lib/tags.mjs";

const REPO_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
// One place decides what a tag is: tools/lib/tags.mjs.
const TAG_RE = new RegExp(TAG_PATTERN);

/**
 * Everything echoed back into a comment is re-checked against the charset it
 * claims to be, and dropped rather than printed when it is not.
 *
 * This is a stranger's issue body being quoted into a comment the bot posts
 * with `issues: write`. It reaches no shell — the workflow moves every body
 * through a file — but a value that failed its own validator has no business
 * being repeated as though the bot had understood it.
 */
const safe = (value, re) => (typeof value === "string" && re.test(value) ? value : null);

/** `owner/name`, or null. */
export const safeRepo = (v) => safe(v, REPO_RE);

/**
 * The tag, or null — charset only, and **deliberately looser than the other
 * tag predicate in this bot.**
 *
 * `bot/lib/poll.mjs`'s `isUsableTag` shares this exact charset
 * (`tools/lib/tags.mjs`'s `TAG_PATTERN`) and then refuses four more shapes on
 * top of it. Measured against both functions rather than read off either:
 * over 501,571 strings the two disagree on **exactly** the tags that
 *
 *   * contain `..`     (`../../evil`, `a..b`)
 *   * begin with `/`   (`/a`)
 *   * end with `/`     (`a/`)
 *   * begin with `-`   (`-rf`)
 *
 * and on nothing else. Each of the four is load-bearing on its own — none is
 * implied by the other three — and in that direction only: no tag this
 * function refuses is one `isUsableTag` accepts.
 *
 * **The difference is intended, and it is not that one of them is wrong.**
 * `isUsableTag` guards a notification path, where a tag arrives unasked from a
 * stranger's feed and the cheapest refusal is at the door. This function was
 * written for a line a maintainer with `admin` or `maintain` typed —
 * `/approve owner/repo@tag`, until cutover commit D removed the command — where
 * refusing a legal-but-ugly git tag would refuse a real release, and what
 * stands behind it is `bot/ingest.mjs` URL-encoding the tag and git refusing a
 * traversal. So `../../evil` is dropped by the feed and accepted here, on
 * purpose.
 *
 * Tightening this function now changes what the decision writer, the service
 * path and MIG-21's export accept as a tag they already hold, which is a
 * decision about records and not a tidy-up.
 *
 * One asymmetry is NOT a strictness difference and is worth knowing before
 * copying either into a new call site: on a non-string this returns `null`,
 * while `isUsableTag` throws a `TypeError` (its charset test coerces, its
 * `.includes` does not). Neither call site can reach it today — both pass a
 * string — and making `isUsableTag` return `false` there would be an
 * improvement, not a regression.
 *
 * `bot/tests/poll.test.mjs` imports both and pins all of the above, so that
 * whichever one somebody moves, the test names the other.
 */
export const safeTag = (v) => safe(v, TAG_RE);
