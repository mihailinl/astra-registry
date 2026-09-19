// The bundle format, crypto-free: the two digest constructions as known-answer
// vectors, domain separation, the manifest read from byte zero versus a
// repointed central directory, MANIFEST.files catching a same-length swap, an
// extra file / symlink / shell entry, an id mismatch — and then the 33 vendored
// shared vectors, which must stay at the END of run(): their names sit between
// "a bundle whose manifest names another plugin is rejected" and the first
// catalogue-signature test.
//
// This is the only module that reads LIMITS.

import crypto from "node:crypto";
import path from "node:path";

import { stableStringify } from "../lib/canonical.mjs";
import { readZip, readEntry, writeZip } from "../lib/zip.mjs";
import { makeFixtures } from "../make-fixtures.mjs";
import {
  checkBundle, manifestDigest, artifactDigest,
  manifestBytesFromLocalHeader, MANIFEST_DIGEST_DOMAIN,
} from "../../bot/lib/bundle.mjs";
import { registerSharedVectorTests } from "../../tests/shared-vectors.mjs";
import { test, assert, tmp, LIMITS } from "./harness.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 41;

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
  await test("the manifest is read from byte zero, not from the central directory", () => {
    const { bundle } = makeFixtures(path.join(tmp, "digest-localhdr"));
    const local = manifestBytesFromLocalHeader(bundle);
    const zip = readZip(bundle);
    const entry = zip.entries.find((e) => e.name === "MANIFEST.json");
    assert(entry.index === 0, "the fixture does not put MANIFEST.json first");
    assert(local.equals(readEntry(bundle, entry)),
      "the local header and the central directory disagree on a bundle this repo just wrote");
    // And it refuses an archive that does not begin with one.
    const notAZip = Buffer.from("this is not a zip file, not even close");
    let threw = false;
    try { manifestBytesFromLocalHeader(notAZip); } catch { threw = true; }
    assert(threw, "a non-ZIP was accepted as a manifest source");
  });
  await test("a central directory pointing away from byte zero is caught", () => {
    // The attack the two readings exist to catch: the central directory's entry
    // for MANIFEST.json is repointed at a DIFFERENT local header, so an index
    // reader sees one manifest and a byte-zero reader (the daemon) sees another.
    //
    // The decoy is built to the SAME BYTE LENGTH as the real manifest on purpose.
    // A length mismatch is caught for free — readEntry runs off the end of the
    // file and the bundle is refused as unreadable — and catching it that way
    // proves nothing about the comparison. Equal lengths make the forgery read
    // cleanly, so only comparing the two readings can tell them apart.
    const real = JSON.stringify({
      schema: "astra.bundle/2", plugin_id: "fixture-plugin", version: "1.0.0",
      platform: { os: "linux", arch: "x86_64" }, entry: { command: "./bin/fixture", args: [] }, files: [],
    });
    // Same length by construction — the decoy id is padded to the real id's
    // length rather than hand-counted, so no arithmetic can drift and quietly
    // turn this back into the length check.
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

    // Sanity: the forgery reads cleanly through the central directory, i.e. it is
    // NOT caught by a length check. Without this the test could pass for the
    // wrong reason and nobody would know the comparison had stopped working.
    const viaCentral = readEntry(forged, readZip(forged).entries.find((e) => e.name === "MANIFEST.json"));
    assert(JSON.parse(viaCentral.toString("utf8")).plugin_id === evilId,
      "the forgery did not take: the central directory still resolves to the real manifest");
    assert(JSON.parse(manifestBytesFromLocalHeader(forged).toString("utf8")).plugin_id === "fixture-plugin",
      "byte zero no longer holds the real manifest");

    const findings = checkBundle(forged, { id: "fixture-plugin", version: "1.0.0", platformKey: "linux-x64" }, LIMITS);
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
