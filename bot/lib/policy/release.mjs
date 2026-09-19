// What a release asks for, and the bytes it is made of.
//
// Split out of `bot/lib/policy.mjs` on 2026-09-19.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { compareSemver, parseSemver } from "../../../tools/lib/semver.mjs";

import { HIGH_RISK } from "./constants.mjs";

// ── reading a release's requested authority ─────────────────────────────────

/**
 * Every name a version document asks for, capabilities and permissions alike,
 * as one sorted set.
 *
 * The two sections answer different questions for the daemon (what I implement
 * vs what I may call), but for this decision they are the same question: what
 * authority is this release asking a user to grant that the last one did not?
 *
 * A listing that predates capability recording carries neither key, and reads
 * here as "asks for nothing". That makes its next release look like a widening:
 * one 24 h delay per legacy listing, once, after which the recorded set is
 * right. Deliberately not special-cased — the alternative is a "we could not
 * tell" branch that silently skips the comparison, and an unknown baseline is
 * the one case where waiting is obviously correct.
 */
export function requestedAuthority(versionDoc) {
  if (!versionDoc) return [];
  const caps = Array.isArray(versionDoc.capabilities) ? versionDoc.capabilities : [];
  const perms = versionDoc.permissions && typeof versionDoc.permissions === "object"
    ? Object.keys(versionDoc.permissions)
    : [];
  return [...new Set([...caps, ...perms].map(String))].sort();
}

/** The high-risk members of a requested set. */
export const highRiskIn = (names) => names.filter((n) => HIGH_RISK.includes(n));

/**
 * The newest version already listed for a plugin, by semver rather than by
 * filename.
 *
 * A listing's newest version is the one a widening is measured against: an
 * author who published 0.3.0 with `dom_access` and then backports 0.2.9 has not
 * newly requested anything.
 */
export function newestListedVersion(existing) {
  const docs = (existing?.versions ?? []).map((v) => v.doc).filter((d) => d && parseSemver(d.version));
  if (docs.length === 0) return null;
  return docs.sort((a, b) => compareSemver(a.version, b.version)).at(-1);
}

export function artifactDigests(versionDoc) {
  const artifacts = versionDoc?.artifacts ?? {};
  return Object.keys(artifacts)
    .sort()
    .map((k) => `${k}:${artifacts[k].sha256 ?? ""}`);
}

/** How long a fingerprint is, in hex characters. */
export const FINGERPRINT_CHARS = 16;

/**
 * The name of one submission: what an `/approve` has to say out loud.
 *
 * Six facts, in one order, hashed: the repository, the tag, the plugin id, the
 * version, the RELEASE COMMIT, and every artifact digest this run computed. It
 * is not a secret and it authorises nothing — the permission is still GitHub's
 * answer about the commenter. It is an *identity*, and its only job is to make
 * "the thing I read" and "the thing you are about to publish" comparable by a
 * string.
 *
 * Why these six and not the issue body: the body is prose that gets edited for
 * good reasons, and a binding that refuses an approval because somebody fixed a
 * typo is a binding maintainers learn to route around. These six change only
 * when what would be published changes.
 *
 * The commit was added after it was pointed out that the design's one
 * post-approval immutability claim rested on the one field the approval did not
 * bind. `bot/lib/assets.mjs` pins every relative README image to
 * `raw.githubusercontent.com/<repo>/<commit>/…` precisely so the picture cannot
 * change after a human approved the listing — and the commit came from
 * `release.target_commitish`, which the author controls. Delete the release and
 * the tag, push a new commit whose `banner.png` is different, re-create both at
 * that commit and re-upload byte-identical assets, and repo, tag, id, version
 * and every digest were unchanged: the fingerprint matched, the hold's
 * `/approve` was still binding, and the store rendered a tree no maintainer had
 * seen. Hashing the commit is what makes that approval refuse.
 *
 * 16 hex characters — 64 bits of a SHA-256. A maintainer copies it out of a
 * comment rather than typing it, so length costs nothing, and 64 bits puts a
 * deliberate collision (rebuild a bundle until its fingerprint matches the one
 * the maintainer read) far past the effort of simply asking for a second
 * approval. Truncation is safe here for the same reason it would not be in a
 * signature: the full digests are recorded beside it in `decision.json`, and
 * this string is a label on them, not a substitute for them.
 */
export function submissionFingerprint({ repo, tag, id, version, commit, digests } = {}) {
  const canonical = [repo ?? "", tag ?? "", id ?? "", version ?? "", commit ?? "", ...(digests ?? [])].join("\n");
  return crypto.createHash("sha256").update(canonical).digest("hex").slice(0, FINGERPRINT_CHARS);
}

// ── the decision ────────────────────────────────────────────────────────────
