// The bundle format, crypto-free: the two digest constructions as known-answer
// vectors, domain separation, the manifest read from byte zero versus a
// repointed central directory, MANIFEST.files catching a same-length swap, an
// extra file / symlink / shell entry, an id mismatch, every bundle-structure
// rule pinned by its own finding set — and then the 33 vendored shared vectors,
// which must stay at the END of run(), after everything this repository writes
// for itself and before the first catalogue-signature test. Anything new goes
// ABOVE that block and never after it.
//
// This is the only module that reads LIMITS.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { stableStringify } from "../lib/canonical.mjs";
import { readZip, readEntry, writeZip } from "../lib/zip.mjs";
import { makeFixtures } from "../make-fixtures.mjs";
import {
  checkBundle, manifestDigest, artifactDigest,
  manifestBytesFromLocalHeader, MANIFEST_DIGEST_DOMAIN,
} from "../../bot/lib/bundle.mjs";
import { registerSharedVectorTests, loadVectors, VECTOR_DIR } from "../../tests/shared-vectors.mjs";
import { test, assert, assertEqual, tmp, LIMITS } from "./harness.mjs";

export async function run() {
  console.log("\nthe two digest constructions");
  // Known-answer vectors. The expected hex below was NOT produced by any of the
  // three implementations — it comes from `python3 -c 'hashlib.sha256(...)'` run
  // by hand against the written-down rule. That is the whole value of a KAT here:
  // the packer (AstraPlugins CLI) and the reader (Astra daemon) were written from
  // the same notes, so a mistake in the notes reproduces in both and they agree
  // with each other forever. These numbers agree with the notes.
  await test("manifest digest is SHA256(\"astra.bundle/2\\0\" || bytes), pinned by known answer", () => {
    assert(MANIFEST_DIGEST_DOMAIN.length === 15, `domain is ${MANIFEST_DIGEST_DOMAIN.length} bytes, expected 15`);
    assert(MANIFEST_DIGEST_DOMAIN[14] === 0, "the domain prefix does not end in NUL");
    assert(MANIFEST_DIGEST_DOMAIN.toString("latin1", 0, 14) === "astra.bundle/2", "wrong domain string");
    assert(manifestDigest(Buffer.from("{}")) === "e2bc471671c92f3b3fb3aed14b43c64ff19bea7985f3099b851dc4ddb46d3438",
      `manifestDigest("{}") = ${manifestDigest(Buffer.from("{}"))}`);
    assert(manifestDigest(Buffer.alloc(0)) === "abebd3e98bc7858e29d047998a939a39ffee25b42d0cfb940479c5dd2cdd7de3",
      `manifestDigest("") = ${manifestDigest(Buffer.alloc(0))}`);
  });
  await test("a manifest digest can never be mistaken for a file digest", () => {
    // The property the domain prefix exists for. Without it the two constructions
    // are the same function, and a value computed over one thing can be presented
    // as a value computed over another.
    for (const s of ["{}", "", '{"schema":"astra.bundle/2"}']) {
      const b = Buffer.from(s);
      assert(manifestDigest(b) !== artifactDigest(b), `the two digests collide on ${JSON.stringify(s)}`);
    }
    assert(artifactDigest(Buffer.from("{}")) === "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      "bare sha256 is not bare sha256");
  });
  // The subject here is `manifestBytesFromLocalHeader`'s SOURCE, and a sound
  // bundle cannot show it. This check used to assert `local.equals(central)` on
  // a bundle the fixture generator had just written, where the two readings are
  // equal by construction — so a `manifestBytesFromLocalHeader` rewritten to
  // resolve MANIFEST.json through `readZip`/`readEntry`, i.e. through the
  // central directory, passed it unchanged (measured 2026-09-22: the whole
  // suite stayed at 300 passed under exactly that mutation, and the two checks
  // that did go red were other checks). A comparison of two readings can only
  // see which one it took on a bundle where they DISAGREE. So the subject is a
  // forged bundle, and the sound one is kept only as the precondition it is.
  await test("the manifest is read from byte zero, not from the central directory — where they disagree", () => {
    const { bundle } = makeFixtures(path.join(tmp, "digest-localhdr"));
    const local = manifestBytesFromLocalHeader(bundle);
    const zip = readZip(bundle);
    const entry = zip.entries.find((e) => e.name === "MANIFEST.json");
    assert(entry.index === 0, "the fixture does not put MANIFEST.json first");
    assert(local.equals(readEntry(bundle, entry)),
      "the local header and the central directory disagree on a bundle this repo just wrote");

    // The bundle that can tell the two readings apart: byte zero holds the real
    // manifest, the central directory resolves to a same-length decoy.
    const { forged, realId, evilId } = repointedCentralDirectory();
    const viaCentral = readEntry(forged, readZip(forged).entries.find((e) => e.name === "MANIFEST.json"));
    assertEqual(JSON.parse(viaCentral.toString("utf8")).plugin_id, evilId,
      "the forgery did not take: the central directory still resolves to the real manifest, so the two " +
      "readings agree and nothing below can tell which one was taken");
    const viaByteZero = manifestBytesFromLocalHeader(forged);
    assert(!viaByteZero.equals(viaCentral),
      "manifestBytesFromLocalHeader returned the bytes the CENTRAL DIRECTORY points at. It is the daemon's " +
      "reading this function stands in for, and the daemon starts at byte zero — a reader that consults the " +
      "index hashes, displays and approves a manifest no daemon will ever enforce");
    assertEqual(JSON.parse(viaByteZero.toString("utf8")).plugin_id, realId,
      "byte zero does not hold the real manifest, so the forgery is not the one this check is about");

    // And it refuses an archive that does not begin with one.
    const notAZip = Buffer.from("this is not a zip file, not even close");
    let threw = false;
    try { manifestBytesFromLocalHeader(notAZip); } catch { threw = true; }
    assert(threw, "a non-ZIP was accepted as a manifest source");
  });
  await test("a central directory pointing away from byte zero is caught", () => {
    const { forged, realId, evilId } = repointedCentralDirectory();

    // Sanity: the forgery reads cleanly through the central directory, i.e. it is
    // NOT caught by a length check. Without this the test could pass for the
    // wrong reason and nobody would know the comparison had stopped working.
    const viaCentral = readEntry(forged, readZip(forged).entries.find((e) => e.name === "MANIFEST.json"));
    assert(JSON.parse(viaCentral.toString("utf8")).plugin_id === evilId,
      "the forgery did not take: the central directory still resolves to the real manifest");
    assert(JSON.parse(manifestBytesFromLocalHeader(forged).toString("utf8")).plugin_id === realId,
      "byte zero no longer holds the real manifest");

    const findings = checkBundle(forged, { id: realId, version: "1.0.0", platformKey: "linux-x64" }, LIMITS);
    assert(findings.some((f) => f.code === "E_MANIFEST_HEADER_DISAGREE"),
      `a repointed central directory was accepted:\n${findings.map((f) => `${f.code} ${f.message}`).join("\n")}`);
  });

  console.log("\nbundle structure (the bot's crypto-free half)");
  await test("a sound bundle produces no findings", () => {
    const { bundle } = makeFixtures(path.join(tmp, "bundle-ok"));
    const findings = checkBundle(bundle, { id: "fixture-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS);
    assert(findings.length === 0, findings.map((x) => `${x.code} ${x.message}`).join("\n"));
  });
  await test("a file swapped inside the bundle is caught by MANIFEST.files", () => {
    const { bundle } = makeFixtures(path.join(tmp, "bundle-tamper"));
    // Same length, different bytes: the archive stays structurally perfect and
    // only the per-file hash disagrees. That is the shape of a real supply-chain
    // edit, and the whole reason MANIFEST.files carries digests at all.
    const i = bundle.indexOf(Buffer.from("echo fixture"));
    assert(i > 0, "fixture payload not found in the archive");
    const tampered = Buffer.from(bundle);
    tampered.write("echo pwned!!", i);
    const findings = checkBundle(tampered, { id: "fixture-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS);
    assert(findings.some((x) => x.code === "E_MANIFEST_HASH_MISMATCH"),
      `expected E_MANIFEST_HASH_MISMATCH, got: ${findings.map((x) => x.code).join(", ") || "nothing"}`);
  });
  await test("an unlisted extra file, a symlink and a shell entry are each rejected", () => {
    const binary = Buffer.from("#!/bin/sh\necho fixture\n", "utf8");
    const manifest = {
      schema: "astra.bundle/2",
      plugin_id: "evil", version: "1.0.0", platform: { os: "linux", arch: "x86_64" },
      entry: { command: "/bin/sh", args: [] },
      files: [{
        path: "bin/x",
        sha256: crypto.createHash("sha256").update(binary).digest("hex"),
        size: binary.length, mode: "0755",
      }],
    };
    const zip = writeZip([
      { name: "MANIFEST.json", data: stableStringify(manifest) },
      { name: "bin/x", data: binary, mode: 0o755 },
      { name: "bin/stowaway", data: "not in the manifest" },
      { name: "bin/link", data: "../../../etc/passwd", mode: 0o120777 },
    ]);
    const codes = checkBundle(zip, { id: "evil", version: "1.0.0", platformKey: "linux-x64" }, LIMITS).map((x) => x.code);
    for (const want of ["E_MANIFEST_EXTRA_FILE", "E_BUNDLE_SYMLINK", "E_ENTRY_ABSOLUTE"]) {
      assert(codes.includes(want), `${want} not reported; got ${codes.join(", ")}`);
    }
  });
  await test("a bundle whose manifest names another plugin is rejected", () => {
    const { bundle } = makeFixtures(path.join(tmp, "bundle-idswap"));
    const codes = checkBundle(bundle, { id: "some-other-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS)
      .map((x) => x.code);
    assert(codes.includes("E_MANIFEST_ID_MISMATCH"),
      "a listing for one id served an archive for another — the confusion §5.3 D closes");
  });

  // ── each rule on its own terms ──────────────────────────────────────────────
  //
  // Every `<name> — rejects (bundle-structure)` in the vendored block below
  // asserts a VERDICT: something refused this vector. Six rules were measured on
  // 2026-09-22 to be asserted by nothing at all — short-circuit the `err()` that
  // raises any one of them in bot/lib/bundle.mjs and the whole suite stayed at
  // `300 passed, 0 failed`, because the vector is still rejected BY A DIFFERENT
  // RULE:
  //
  //   E_MANIFEST_NOT_FIRST        left E_MANIFEST_LOCAL_HEADER
  //   E_MANIFEST_COMPRESSED       left E_MANIFEST_LOCAL_HEADER
  //   E_MANIFEST_HEADER_DISAGREE  left E_MANIFEST_INVALID — the decoy does not parse
  //   E_BUNDLE_TRAVERSAL          left E_MANIFEST_EXTRA_FILE
  //   E_BUNDLE_ADS                left E_MANIFEST_EXTRA_FILE
  //   E_BUNDLE_TRAILING_DOT       left E_MANIFEST_EXTRA_FILE
  //
  // A verdict passes for as long as ANY rule fires, and stops testing its
  // subject the moment a different one does. These assert the FINDING SET,
  // exactly, so a rule going missing is the difference between green and red.
  //
  // The last three are the urgent ones, and they share one accidental guardian:
  // `MANIFEST.files` exhaustiveness. In the corpus a `..` component, an NTFS
  // alternate data stream and a trailing-dot name are all caught because they
  // are UNLISTED, not because they are malformed — so anything that lists them,
  // a generator change or a wider manifest or a tool that adds entries, removes
  // all three at once and nothing says so. Each of the three therefore carries a
  // second leg: the same offending name LISTED in MANIFEST.files with the right
  // digest, size and mode, where exhaustiveness is satisfied and the rule about
  // the NAME is the only thing left standing.
  //
  // Plugins are not sandboxed and will not be. That is settled, and it is
  // exactly why this reader's path rules are asserted on their own terms: it is
  // one of the few things between a published archive and somebody's filesystem.
  console.log("\neach bundle-structure rule, on its own terms");
  const RULE_PINS = [
    {
      rule: "E_MANIFEST_NOT_FIRST", vector: "manifest-not-first",
      rest: ["E_MANIFEST_LOCAL_HEADER"],
      otherwise: "the byte-zero reader throwing, because entry zero is not MANIFEST.json",
    },
    {
      rule: "E_MANIFEST_COMPRESSED", vector: "manifest-compressed",
      rest: ["E_MANIFEST_LOCAL_HEADER"],
      otherwise: "the byte-zero reader throwing on `method !== 0`, which is the same rule said twice",
    },
    {
      rule: "E_MANIFEST_HEADER_DISAGREE", vector: "header-disagree",
      rest: ["E_MANIFEST_INVALID"],
      otherwise: "the decoy manifest failing to parse, which is a property of that decoy and not of the comparison",
    },
    {
      rule: "E_BUNDLE_TRAVERSAL", vector: "path-traversal",
      rest: ["E_MANIFEST_EXTRA_FILE"], listed: "bin/../../../etc/passwd",
      otherwise: "MANIFEST.files exhaustiveness, because the traversal entry happens to be unlisted",
    },
    {
      rule: "E_BUNDLE_ADS", vector: "path-ads",
      rest: ["E_MANIFEST_EXTRA_FILE"], listed: "bin/run:Zone.Identifier",
      otherwise: "MANIFEST.files exhaustiveness, because the stream entry happens to be unlisted",
    },
    {
      rule: "E_BUNDLE_TRAILING_DOT", vector: "path-trailing-dot",
      rest: ["E_MANIFEST_EXTRA_FILE"], listed: "bin/run.",
      otherwise: "MANIFEST.files exhaustiveness, because the trailing-dot entry happens to be unlisted",
    },
  ];
  for (const pin of RULE_PINS) {
    await test(`${pin.rule} — asserted, not merely implied (${pin.vector})`, () => {
      const v = loadVectors().find((x) => x.name === pin.vector);
      assert(v, `${pin.vector} is no longer in the vendored corpus, so ${pin.rule} is pinned by nothing here`);
      const codes = errorCodes(
        fs.readFileSync(path.join(VECTOR_DIR, v.file)),
        { id: v.plugin_id, version: v.version, platformKey: v.platform_key },
      );
      assert(codes.includes(pin.rule),
        `${pin.rule} is not raised for the ${pin.vector} vector any more.\n` +
        `        The vector is STILL REJECTED — by ${codes.join(", ") || "nothing at all"} — so ` +
        `\`${pin.vector} — rejects (bundle-structure)\` is still green and NOTHING in this suite asserts ` +
        `${pin.rule}.\n        What rejects it instead: ${pin.otherwise}.`);
      assertEqual(codes.join(", "), [pin.rule, ...pin.rest].sort().join(", "),
        `the finding set for ${pin.vector} moved. tests/vectors/ is a VENDORED copy refreshed from ` +
        "AstraPlugins/testdata/bundles — if the bytes changed there, read them and correct this table; " +
        "if they did not, bot/lib/bundle.mjs changed what it says about them");

      if (!pin.listed) return;
      // Exhaustiveness satisfied: the offending name is in MANIFEST.files with a
      // correct digest, so E_MANIFEST_EXTRA_FILE cannot fire and only a rule
      // about the name can reject this archive.
      const alone = errorCodes(bundleListing(pin.listed), FIXTURE_LISTING);
      assertEqual(alone.join(", "), pin.rule,
        `${JSON.stringify(pin.listed)} is LISTED in MANIFEST.files with the right digest, so exhaustiveness ` +
        `is satisfied and ${pin.rule} is the only thing between this entry name and a filesystem — and the ` +
        `reader raised ${alone.join(", ") || "nothing"}. This is the shape the accidental guardian hides: a ` +
        "wider manifest, and the name rule is all that is left.");
    });
  }

  // ── the shared vectors ──────────────────────────────────────────────────────
  //
  // Everything above this line is a fixture this repo builds for itself, which is
  // precisely the arrangement that lets three implementations of one format drift
  // apart while all three suites stay green: each proves it agrees with itself.
  // `tests/vectors/` is a vendored copy of AstraPlugins/testdata/bundles, and the
  // CLI's reader and the daemon's reader answer the same questions about the same
  // bytes with the same expected answers written down beside them.
  //
  // See tests/shared-vectors.mjs, and testdata/bundles/README.md upstream.
  console.log("\nshared bundle vectors (AstraPlugins/testdata/bundles, vendored)");
  await registerSharedVectorTests({ test, assert, limits: LIMITS });
}

/** The error codes `checkBundle` raises for these bytes, sorted. Warnings are not verdicts. */
function errorCodes(buf, expected) {
  return checkBundle(buf, expected, LIMITS)
    .filter((f) => f.level === "error")
    .map((f) => f.code)
    .sort();
}

/** The listing the `bundleListing` fixtures are built against. */
const FIXTURE_LISTING = { id: "fixture-plugin", version: "1.0.0", platformKey: "linux-x64" };

/**
 * A structurally perfect bundle carrying one extra entry named `name`, and
 * naming it in MANIFEST.files with the right digest, size and mode.
 *
 * What it takes away is the point. `E_MANIFEST_EXTRA_FILE` cannot fire on an
 * entry that is listed, and everything else about this archive is sound, so the
 * only finding that can come back is a rule about the NAME. That is the test
 * the shared corpus cannot run: its path vectors leave the offending entry out
 * of the manifest, so all three are held up by exhaustiveness and none of them
 * by the rule in its name.
 */
function bundleListing(name) {
  const payload = Buffer.from("#!/usr/bin/env node\nprocess.exit(0);\n", "utf8");
  const sha256 = crypto.createHash("sha256").update(payload).digest("hex");
  const files = [
    { path: "bin/run", sha256, size: payload.length, mode: "0755" },
    { path: name, sha256, size: payload.length, mode: "0644" },
  ].sort((a, b) => (a.path < b.path ? -1 : 1)); // E_MANIFEST_UNSORTED is not the subject
  return writeZip([
    {
      name: "MANIFEST.json",
      data: stableStringify({
        schema: "astra.bundle/2",
        plugin_id: FIXTURE_LISTING.id,
        version: FIXTURE_LISTING.version,
        platform: { os: "linux", arch: "x86_64" },
        entry: { command: "./bin/run", args: [] },
        files,
      }),
    },
    { name: "bin/run", data: payload, mode: 0o755 },
    { name, data: payload, mode: 0o644 },
  ]);
}

/**
 * A bundle whose central directory points MANIFEST.json at a DIFFERENT local
 * header: byte zero holds the real manifest, the index resolves to a decoy.
 *
 * The attack the two readings exist to catch — an index reader sees one manifest
 * and a byte-zero reader (the daemon) sees another — and the only fixture on
 * which the two readings differ, which is why both the byte-zero check and the
 * repointed-central-directory check are built on this one rather than on a sound
 * bundle where they agree by construction.
 *
 * The decoy is the SAME BYTE LENGTH as the real manifest on purpose. A length
 * mismatch is caught for free — readEntry runs off the end of the file and the
 * bundle is refused as unreadable — and catching it that way proves nothing
 * about the comparison. Equal lengths make the forgery read cleanly, so only
 * comparing the two readings can tell them apart. The decoy id is padded to the
 * real id's length rather than hand-counted, so no arithmetic can drift and
 * quietly turn this back into the length check.
 */
function repointedCentralDirectory() {
  const real = JSON.stringify({
    schema: "astra.bundle/2", plugin_id: "fixture-plugin", version: "1.0.0",
    platform: { os: "linux", arch: "x86_64" }, entry: { command: "./bin/fixture", args: [] }, files: [],
  });
  const realId = JSON.parse(real).plugin_id;
  const evilId = "attacker".slice(0, realId.length).padEnd(realId.length, "-");
  const decoy = JSON.stringify({ ...JSON.parse(real), plugin_id: evilId });
  assert(decoy.length === real.length, `decoy ${decoy.length} vs real ${real.length}`);

  const bundle = writeZip([
    { name: "MANIFEST.json", data: Buffer.from(real), mode: 0o644 },
    { name: "decoy.json", data: Buffer.from(decoy), mode: 0o644 },
  ]);
  const zip = readZip(bundle);
  const man = zip.entries.find((e) => e.name === "MANIFEST.json");
  const other = zip.entries.find((e) => e.name === "decoy.json");
  assert(man && other && other.offset !== man.offset, "fixture has nothing to repoint at");
  const forged = Buffer.from(bundle);
  // Rewrite the offset field of MANIFEST.json's CENTRAL directory record only.
  const cd = forged.indexOf(Buffer.from("PK\x01\x02", "latin1"));
  assert(cd > 0, "no central directory found");
  let p = cd, patched = false;
  while (p > 0 && forged.readUInt32LE(p) === 0x02014b50) {
    const nameLen = forged.readUInt16LE(p + 28);
    const name = forged.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    if (name === "MANIFEST.json") { forged.writeUInt32LE(other.offset, p + 42); patched = true; break; }
    p += 46 + nameLen + forged.readUInt16LE(p + 30) + forged.readUInt16LE(p + 32);
  }
  assert(patched, "could not repoint the central directory entry");
  return { forged, realId, evilId };
}
