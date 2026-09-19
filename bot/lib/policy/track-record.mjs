// The author's track record, and the withdrawal list it is read against.
//
// Split out of `bot/lib/policy.mjs` on 2026-09-19.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { parseSemver } from "../../../tools/lib/semver.mjs";
import { CLEAN_RELEASES_FOR_TRUSTED, DELAY_HOURS, TRUSTED_DELAY_HOURS } from "./constants.mjs";

// ── the author's track record ───────────────────────────────────────────────

/**
 * How many clean releases this author has published here, and whether anything
 * of theirs has ever been revoked.
 *
 * Counted per *account*, not per plugin: the thing being graduated is an
 * author's history with this registry, and an author's second plugin is not
 * their first rodeo. A revocation anywhere in that account's listings resets it
 * to zero — the counter is a statement about a track record, and a revoked
 * plugin is the definition of not having one.
 *
 * Yanked versions are not counted and do not reset: yanking is the author's own
 * "do not use this one" (POLICY.md §6), not a fault signal.
 */
export function trackRecord(root, repo, { plugins, revocations } = {}) {
  const owner = String(repo ?? "").split("/")[0].toLowerCase();
  const list = plugins ?? [];
  const revoked = revocations ?? loadRevocations(root);

  let clean = 0;
  let revokedHere = false;
  for (const p of list) {
    const pRepo = p.doc?.source?.repo;
    if (!pRepo || String(pRepo).split("/")[0].toLowerCase() !== owner) continue;
    for (const v of p.versions ?? []) {
      const doc = v.doc;
      if (!doc?.version || !parseSemver(doc.version)) continue;
      if (doc.yanked) continue;
      // A staging entry is a listing whose artifact nobody could verify. It is
      // not evidence of a clean release; it is evidence of a bootstrap.
      if (doc.staging) continue;
      if (isRevoked(revoked, p.doc?.id, doc.version)) {
        revokedHere = true;
        continue;
      }
      clean++;
    }
  }

  const tier = !revokedHere && clean >= CLEAN_RELEASES_FOR_TRUSTED ? "established" : "new";
  return {
    owner,
    clean_releases: clean,
    revoked: revokedHere,
    tier,
    delay_hours: tier === "established" ? TRUSTED_DELAY_HOURS : DELAY_HOURS,
  };
}

/** `registry/v1/revocations.json` if task 3.9 has landed it, else nothing. */
export function loadRevocations(root) {
  const file = path.join(root ?? ".", "registry", "v1", "revocations.json");
  try {
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    return doc?.signed?.revocations ?? doc?.revocations ?? [];
  } catch {
    return [];
  }
}

function isRevoked(revocations, id, version) {
  if (!id) return false;
  return revocations.some((r) => {
    if (r.plugin_id && r.plugin_id !== id) return false;
    if (r.id && r.id !== id) return false;
    if (r.version && r.version !== version) return false;
    return Boolean(r.plugin_id || r.id);
  });
}
