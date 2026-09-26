// The release desk lives in Astra now, and this tree keeps only what Astra
// still reads from it (registry plan RC-R3-4(b); client plan C2.1, ROLL-46).
//
// **What moved, and why the registry had it at all.** The desktop update
// manifest is Astra's, not the registry's: `scripts/release.sh` in Astra signs
// it, the daemon's `update.rs` verifies it, and the registry is not a party to
// it beyond sharing the root key's ceremony. It lived here because the signer
// was written here first. Its signer under `tools/`,
// the two test-key helpers beside it, their interop fixture, the release
// records under `releases/`, and the three selftest modules that tested the
// signer all moved into Astra in one commit (C2.1), and this commit deletes
// them here. Two copies of a signing tool are two tools, and the one nobody
// runs is the one that is quietly wrong on the day someone does.
//
// **What this module asks, each question its own test, because each can break
// without the others:**
//
//   * the moved paths are not on this tree — tracked, or on disk;
//   * nothing tracked here reads them: no file names the signer, its two
//     helpers, their fixture, or a release record under `releases/<version>/`;
//   * `tools/testkeys/regenerate.mjs` still exports `loadTestRoot` in the shape
//     Astra's moved rehearsal reads through the sibling checkout. That reader
//     is in ANOTHER repository, so nothing here would fail if the export were
//     renamed — this is the one place that can;
//   * `README.md` says where the desk went and names Astra's commit, so the
//     deletion cannot land naming nobody;
//   * the three libraries Astra vendored for the moved signer are still the
//     bytes it vendored. Astra keeps its copies at
//     `tools/update-manifest-signer/vendor/`, with `VENDORED-FROM` naming this
//     repository's commit; a change here does not reach them, and this is what
//     makes that a decision somebody takes rather than a drift nobody sees.
//
// **The needles are built from pieces**, so that this file does not contain
// the strings it forbids, and the scan needs no exception for itself. An
// exception list is where a check like this one quietly stops covering the
// file that matters.

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { cleanEnv } from "../lib/git-env.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual } from "./harness.mjs";

const j = (...parts) => parts.join("");

/** Every path the desk left behind. A directory ends in `/`. */
export const MOVED = Object.freeze([
  j("releases", "/"),
  j("tools/sign-update", "-manifest.mjs"),
  j("tools/testkeys/sign-update", "-manifest.mjs"),
  j("tools/testkeys/rehearse", "-manifest.mjs"),
  j("tools/testkeys/fixtures/update", "-manifest-interop.json"),
  j("tools/selftest/update", "-signing.mjs"),
  j("tools/selftest/update", "-notes.mjs"),
  j("tools/selftest/update", "-fixtures.mjs"),
]);

/** What a file that still reads the desk would say. */
export const READS_THE_DESK = Object.freeze([
  { what: "the manifest signer or its test-key twin", re: new RegExp(j("sign-update", "-manifest")) },
  { what: "the rehearsal helper", re: new RegExp(j("rehearse", "-manifest")) },
  { what: "the interop fixture", re: new RegExp(j("update-manifest", "-interop")) },
  { what: "the signer's selftest cases", re: new RegExp(j("update-(?:signing|notes|fixtures)", "\\.mjs")) },
  { what: "a release record", re: new RegExp(j("(?:^|[^A-Za-z0-9_./-])releases", "/\\d+\\.\\d+\\.\\d+")) },
]);

/**
 * The libraries Astra's moved signer vendors, at the bytes it vendored.
 *
 * `VENDORED_AT` is the registry commit Astra's `VENDORED-FROM` names. A change
 * to one of these files here is not wrong — `bot/lib/sign.mjs` is this
 * repository's own verifier and will move when it must — but it leaves Astra's
 * copy behind, and whoever makes it has to say which of three things is true:
 * Astra re-vendors, the two copies may differ from now on, or the change should
 * not be made. Updating the digest here, in the same commit, is saying it.
 */
// 7b09033 is #358's merge. Astra re-vendored all three files there: its
// VENDORED-FROM names that commit, with canonical.mjs at the digest below
// (Astra main 81b11f8, read 2026-09-26).
export const VENDORED_AT = "7b090339594b60b74056ff5cc1bba5b25ecb686a";
export const VENDORED_BY_ASTRA = Object.freeze({
  "bot/lib/sign.mjs": "7934b01b55ba76c9ba7249ded19c47cfcc5543fc2b55a66e13588a376ae83003",
  // Moved by contract 2.16.0 (lane S18): it refuses a string that is not
  // I-JSON instead of escaping it. Astra re-vendored it at VENDORED_AT.
  "tools/lib/canonical.mjs": "58debc90215fab34c9f8a6c3d7496345cb7931e65c953441a093ecca9abc98b8",
  // Moved by contract 2.16.0 (lane S21), and the answer is ASTRA RE-VENDORS:
  // a version is at most 256 characters, in parseSemver and in SEMVER_PATTERN.
  // Astra's moved signer orders its own desktop release versions with this
  // file, and they are nowhere near 256, so until it re-vendors its copy
  // answers every question it is asked the same way. Re-vendoring keeps one
  // grammar in both places. This digest is the new bytes; VENDORED_AT still
  // names the commit Astra vendored.
  "tools/lib/semver.mjs": "81aeadd6f2bbf8ecd9796c986e010077db63e9a8cf26f10317720aeb5e7aa0d7",
});

const tracked = () =>
  execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z"], { encoding: "utf8", env: cleanEnv(), maxBuffer: 64 * 1024 * 1024 })
    .split("\0").filter(Boolean);

const onPath = (files, p) => (p.endsWith("/") ? files.some((f) => f.startsWith(p)) : files.includes(p));

export async function run() {
  console.log("\nthe release desk, which lives in Astra now (RC-R3-4)");

  await test("(b) the desk's paths are gone from this tree, tracked and on disk", () => {
    // Two instruments, because each is blind where the other is not: `git
    // ls-files` does not see an untracked copy somebody restored by hand, and
    // the file system does not see a tracked path deleted from the working copy.
    const files = tracked();
    assert(files.length >= 500, `git ls-files listed ${files.length} files; a walk that short is not this tree`);
    const back = MOVED.filter((p) => onPath(files, p) || fs.existsSync(path.join(REPO_ROOT, ...p.split("/").filter(Boolean))));
    assertEqual(back.join(", "), "",
      "the release desk moved into Astra (client plan C2.1) and RC-R3-4(b) deleted it here; a path that is back " +
      "is a second copy of a signing tool, and the one nobody runs is the one that is wrong on the day somebody does");
  });

  await test("(b) nothing tracked here reads the moved desk", () => {
    // Read as BYTES by Node, never through `grep`: in this estate `grep` has
    // been a wrapper that skips any file with a NUL in it and exits 1, which is
    // exactly the silence a negative check must not rest on.
    const files = tracked();
    let read = 0;
    const hits = [];
    for (const rel of files) {
      const abs = path.join(REPO_ROOT, rel);
      let st;
      try { st = fs.lstatSync(abs); } catch { continue; }
      if (!st.isFile() || st.size > 8 * 1024 * 1024) continue;
      const text = fs.readFileSync(abs).toString("latin1");
      read += 1;
      for (const { what, re } of READS_THE_DESK) {
        const m = re.exec(text);
        if (m) hits.push(`${rel}:${text.slice(0, m.index).split("\n").length} names ${what}`);
      }
    }
    assert(read >= 500, `read ${read} tracked file(s); a scan that short proves nothing about this tree`);
    assertEqual(hits.join("\n"), "",
      "a tracked file still reads the release desk that moved into Astra. Point it at Astra's " +
      "`tools/update-manifest-signer/` or `release-records/`, or delete the reference with the thing it described");
  });

  await test("(b) tools/testkeys/regenerate.mjs still exports loadTestRoot in the shape Astra's rehearsal reads", async () => {
    // Astra's moved rehearsal (`tools/update-manifest-signer/testkeys/`) reads
    // the published TEST root through the sibling registry's
    // `tools/testkeys/regenerate.mjs`, and copies no key file. That reader is in
    // another repository, so a rename here breaks it with nothing here failing:
    // this test is the registry's half of that coupling, and it holds the
    // export, its arity and the members the rehearsal uses.
    const mod = await import("../testkeys/regenerate.mjs");
    const exported = Object.keys(mod).filter((k) => k === "loadTestRoot");
    assertEqual(exported.length, 1, "tools/testkeys/regenerate.mjs no longer exports `loadTestRoot`");
    assertEqual(typeof mod.loadTestRoot, "function", "`loadTestRoot` is exported and is not a function");
    assertEqual(mod.loadTestRoot.length, 1, "`loadTestRoot` no longer takes exactly one argument, the key id");
    assert(Array.isArray(mod.TEST_ROOTS) && mod.TEST_ROOTS.length >= 1, "no TEST root to load");
    const keyId = mod.TEST_ROOTS[0].key_id;
    const k = mod.loadTestRoot(keyId);
    assertEqual(k.key_id, keyId, "`loadTestRoot` returns a key that is not the one asked for");
    assert(k.privateKey instanceof crypto.KeyObject && k.privateKey.type === "private",
      "`loadTestRoot(...).privateKey` is not a private KeyObject, which is what the rehearsal signs with");
    assert(/^[A-Za-z0-9+/]{43}=$/.test(k.publicKeyB64 ?? ""),
      "`loadTestRoot(...).publicKeyB64` is not the base64 of a 32-byte ed25519 key");
    assert(/^[0-9a-f]{64}$/.test(k.fingerprint ?? ""), "`loadTestRoot(...).fingerprint` is not 64 hex characters");
    let refused = false;
    try { mod.loadTestRoot("no-such-test-key"); } catch { refused = true; }
    assert(refused, "`loadTestRoot` returned something for a key id it does not know");
  });

  await test("(b) README.md says where the desk went, and names Astra's commit", () => {
    // RC-R3-4(b): "adds a pointer in README.md, and names the Astra SHA". A
    // pointer that names no commit sends a reader to a tree that may not have
    // the files yet, and a placeholder left in it is a deletion that landed
    // before the thing it points at existed.
    const readme = fs.readFileSync(path.join(REPO_ROOT, "README.md"), "utf8");
    const para = readme.split(/\n\s*\n/).find((p) => /tools\/update-manifest-signer\//.test(p));
    assert(para, "README.md has no paragraph pointing at Astra's `tools/update-manifest-signer/`");
    assert(/release-records\//.test(para), "README.md's desk pointer does not say where the release records went");
    assert(/\bAstra@[0-9a-f]{40}\b/.test(para),
      "README.md's desk pointer names no 40-hex Astra commit. The deletion lands after Astra's C2.1 commit and " +
      "names it (RC-R3-4(b)); write `Astra@<sha>` there");
  });

  await test("the three libraries Astra vendored for the moved signer are the bytes it vendored", () => {
    for (const [rel, want] of Object.entries(VENDORED_BY_ASTRA)) {
      const got = crypto.createHash("sha256").update(fs.readFileSync(path.join(REPO_ROOT, rel))).digest("hex");
      assertEqual(got, want,
        `${rel} is not the file Astra vendored at registry ${VENDORED_AT.slice(0, 12)} for its moved update ` +
        "signer (tools/update-manifest-signer/vendor/, VENDORED-FROM). The change may be right; it leaves Astra's " +
        "copy behind. Say which it is in this commit: Astra re-vendors, the copies may differ from now on, or " +
        "the change should not be made — then set this digest to the new bytes");
    }
    assertEqual(Object.keys(VENDORED_BY_ASTRA).length, 3, "the vendored-library table lost a row");
  });
}
