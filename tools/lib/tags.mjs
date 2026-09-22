// What a release tag is, in one place.
//
// A tag arrives from a stranger and is used in four different ways: as the
// thing the bot fetches a release by, as a component of the queue and decision
// records, as text echoed back into a public comment, and as half of the
// `owner/repo@tag` binding a maintainer types to approve a specific release. It
// was written out five times — `bot/ingest.mjs`, `bot/lib/notify.mjs`,
// `bot/lib/intake.mjs` twice (once inside the approval grammar), and again as a
// `pattern` in `schema/version-v1.json` — with nothing comparing them. All five
// agreed, which is what a coupling looks like on the day before it stops
// agreeing.
//
// ── what it accepts, and the two things it refuses on purpose ──────────────
//
// `A-Za-z0-9`, dot, underscore, slash and hyphen, 1 to 128 characters.
//
// **No `@`.** That is not a charset opinion, it is the cost of the approval
// grammar: `/approve owner/repo@tag <fingerprint>` splits on `@`, and a tag
// containing one makes the split ambiguous. The cost is real and is worth
// naming rather than discovering — `pkg@1.2.3` and `@scope/pkg@1.2.3` are the
// standard release-tag shapes of a monorepo, and this registry refuses them at
// intake. An author with a monorepo has to tag differently to list here.
//
// **No non-ASCII.** `релиз-1.2.0` is refused. A tag becomes part of a URL the
// bot fetches, text in a public comment, and a filename in a record, and the
// homoglyph work in `tools/lib/ids.mjs` exists because those three are where a
// lookalike pays. Worth knowing that the rest of this estate went the other way
// for its own storage layer after measuring the same refusal, so this is a
// divergence somebody chose, not a rule everybody shares.
//
// Both refusals are deliberate and neither is written down anywhere else, which
// is the whole reason this file has prose in it.

/** The one pattern, as a string, so a schema can carry the same source. */
export const TAG_PATTERN = "^[A-Za-z0-9._/-]{1,128}$";

/** The charset alone, for grammars that embed a tag in a larger expression. */
export const TAG_CHARSET = "[A-Za-z0-9._/-]";

/** The greatest length a tag may have; the schema states it separately. */
export const TAG_MAX = 128;

const TAG_RE = new RegExp(TAG_PATTERN);

/** True when `v` is a tag this registry will act on. */
export function isTag(v) {
  return typeof v === "string" && TAG_RE.test(v);
}
