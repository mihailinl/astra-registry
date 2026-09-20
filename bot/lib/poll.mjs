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

import { TAG_PATTERN } from "../../tools/lib/tags.mjs";

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
