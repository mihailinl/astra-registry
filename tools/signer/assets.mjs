// The asset files a catalogue names, and where the signer gets their bytes (BOT-109).
//
// A listing's `icon` and `readme_file` members (contract 6.28.0) name a file as
// `assets/<sha256>.<ext>`. The signer writes `registry/v1/assets/<sha256>.<ext>`
// into the same `signed` commit as the catalogue that names it: one file per
// path the catalogue references, and nothing it does not reference. A commit is
// built from nothing but the files it is given, so every commit carries every
// referenced asset again, also when the catalogue is carried from the head.
//
// Where the bytes come from, for each path the final catalogue names:
//   1. the listing's own committed icon or README at the Source-Commit, through
//      the generator's own derivation (`buildAssets`), when it digests to the
//      name (it does, for a catalogue this run generated);
//   2. otherwise the same path in `signed`'s head (a carried catalogue names
//      files the Source-Commit may no longer derive).
// Whichever it is, the bytes must digest to the name and to the member's
// `size`, and be within the cap; a path with no such bytes is a refusal that
// says so, never a catalogue that names a file nobody wrote.

import { createHash } from "node:crypto";

import { ASSET_ICON_MAX_BYTES, ASSET_README_MAX_BYTES, buildAssets } from "../build-index.mjs";
import { blobRawAt } from "./git.mjs";

/** Where, inside a `signed` commit, the assets live. */
export const ASSET_DIR = "registry/v1/";
export const ASSET_PATH = /^assets\/[0-9a-f]{64}\.(png|webp|jpg|md)$/;

/**
 * Every asset a catalogue's listings name: path -> {sha256, size, cap}. A member
 * whose path is not `assets/<its own sha256>.<ext>` is a problem, not an entry.
 */
export function referencedAssets(indexDoc) {
  const refs = new Map();
  const problems = [];
  for (const entry of indexDoc?.signed?.plugins ?? []) {
    for (const [member, cap] of [["icon", ASSET_ICON_MAX_BYTES], ["readme_file", ASSET_README_MAX_BYTES]]) {
      const m = entry?.[member];
      if (m === undefined) continue;
      const wantExt = member === "readme_file" ? "md" : null;
      const ok =
        typeof m.path === "string" && ASSET_PATH.test(m.path) &&
        m.path.slice("assets/".length, "assets/".length + 64) === m.sha256 &&
        (wantExt ? m.path.endsWith(".md") : !m.path.endsWith(".md"));
      if (!ok) {
        problems.push(`${entry.id}: ${member}.path ${JSON.stringify(m.path)} is not assets/<its sha256>.<ext>`);
        continue;
      }
      refs.set(m.path, { sha256: m.sha256, size: m.size, cap, id: entry.id });
    }
  }
  return { refs, problems };
}

/**
 * @param {{root: string, indexDoc: object, headRef: string|null}} o
 * @returns {{assets: Map<string, Buffer>, problems: string[]}}
 */
export function collectAssets({ root, indexDoc, headRef }) {
  const { refs, problems } = referencedAssets(indexDoc);
  const assets = new Map();
  if (refs.size === 0) return { assets, problems };

  let derived = new Map();
  try {
    derived = buildAssets({ root, serial: indexDoc.signed.serial });
  } catch {
    // Nothing derivable from this tree: a carry may still be satisfied from the head.
  }
  const digests = (b) => createHash("sha256").update(b).digest("hex");
  for (const [rel, ref] of refs) {
    let bytes = derived.get(rel) ?? null;
    if (bytes !== null && digests(bytes) !== ref.sha256) bytes = null;
    if (bytes === null && headRef) bytes = blobRawAt({ root, ref: headRef, path: `${ASSET_DIR}${rel}` });
    if (bytes === null) {
      problems.push(`${ref.id}: ${rel} is named by the catalogue and is neither derivable from plugins/ nor in signed's head`);
      continue;
    }
    if (digests(bytes) !== ref.sha256 || bytes.length !== ref.size) {
      problems.push(`${ref.id}: the bytes for ${rel} do not digest to its name or are not ${ref.size} bytes`);
      continue;
    }
    if (bytes.length > ref.cap) {
      problems.push(`${ref.id}: ${rel} is ${bytes.length} bytes, over the ${ref.cap} an asset file may be`);
      continue;
    }
    assets.set(rel, Buffer.from(bytes));
  }
  return { assets, problems };
}
