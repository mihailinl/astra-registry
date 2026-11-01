// The bundle format, crypto-free: the two digest constructions as known-answer
// vectors, domain separation, the manifest read from byte zero versus a
// repointed central directory, MANIFEST.files catching a same-length swap, an
// extra file / symlink / shell entry, an id mismatch, every bundle-structure
// rule pinned by its own finding set — and then the vendored shared vectors,
// which must stay at the END of run(), after everything this repository writes
// for itself and before the first catalogue-signature test. Anything new goes
// ABOVE that block and never after it.
//
// How many vendored vectors there are is AstraPlugins' number, not this file's:
// it changes on an ordinary re-vendor, in a file whose author never opened this
// one. It used to be written here as 33, and a count in a comment is a sentence
// the next re-vendor falsifies with nothing to catch it.
//
// This is the only module that reads LIMITS.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

import { stableStringify } from "../lib/canonical.mjs";
import { readZip, readEntry, writeZip } from "../lib/zip.mjs";
import { makeFixtures } from "../make-fixtures.mjs";
import {
  checkBundle, manifestDigest, artifactDigest, readEntryOneWay,
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

  // ── one reading per entry ───────────────────────────────────────────────────
  //
  // astra-ce's ZIP cloaking shapes (2026-10-31), wrapped as bundles. On main
  // 05f8f70 each came back with ZERO findings while a streaming reader extracted
  // a payload no check here had read. Every rule in `readEntryOneWay` also has a
  // bundle on which it is the ONLY objection, so deleting any one of them is red
  // here instead of being covered for by a neighbour on the attack vector.
  console.log("\none reading per entry (ZIP cloaking shapes)");
  await test("an honest deflated bundle has one reading and no findings", () => {
    const z = cloakBundle([deflatedEntry("lib/a.txt", TEXT)]);
    assertEqual(streamingNames(z).join(","), "MANIFEST.json,bin/run,lib/a.txt", "the streaming walk of an honest bundle");
    const f = checkBundle(z, FIXTURE_LISTING, LIMITS);
    assert(f.length === 0, f.map((x) => `${x.code} ${x.message}`).join("\n"));
  });
  await test("deflate slack behind bit 3, hiding a second bin/run, is refused", () => {
    const z = cloakBundle([slackEntry({ bit3: true })]);
    // The fixture IS the attack: walked from byte zero, a.txt's slack yields a
    // second bin/run, extracted after the one the manifest describes.
    assertEqual(streamingNames(z).join(","), "MANIFEST.json,bin/run,a.txt,bin/run", "the streaming walk");
    const f = checkBundle(z, FIXTURE_LISTING, LIMITS).filter((x) => x.level === "error");
    assertEqual(f.map((x) => x.code).join(", "), "E_BUNDLE_UNREADABLE, E_BUNDLE_UNREADABLE", "the finding set");
    for (const says of ["general-purpose bit 3", "deflate stream ends after"]) {
      assert(f.some((x) => x.message.includes(says)), `no finding says ${JSON.stringify(says)}`);
    }
  });
  const ONE_READING_PINS = [
    { rule: "bit 3, every size right", says: "general-purpose bit 3", entry: () => bit3Entry() },
    {
      // Both headers declare the slack, so they agree and tile; only the deflate
      // stream's own end says otherwise, and a reader that trusts it over the
      // header walks into the hidden bin/run.
      rule: "deflate slack, no bit 3, both headers declaring it", says: "deflate stream ends after",
      entry: () => slackEntry({ bit3: false }), streams: "MANIFEST.json,bin/run,a.txt,bin/run",
      walk: { trustDeflateEnd: true },
    },
    { rule: "inflates short of its declared size", says: "inflates to", entry: () => deflatedEntry("a.txt", TEXT, { usz: TEXT.length + 1 }) },
    { rule: "inflates past its declared size", says: "does not inflate", entry: () => deflatedEntry("a.txt", TEXT, { usz: TEXT.length - 1 }) },
    {
      // Sync-flushed, never finished: every byte of TEXT comes out, every input
      // byte is consumed, size and CRC are right, and there is no final block.
      // Running out of input is not the end of the stream.
      rule: "a deflate stream that never ends", says: "does not inflate",
      entry: () => {
        const body = zlib.deflateRawSync(TEXT, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
        return deflatedEntry("a.txt", TEXT, { body, csz: body.length });
      },
    },
    { rule: "a CRC-32 its bytes do not have", says: "CRC-32", entry: () => deflatedEntry("a.txt", TEXT, { crc: crc32(TEXT) ^ 1 }) },
    { rule: "stored, with two sizes", says: "is stored, yet declares", entry: () => ({ ...storedEntry("a.txt", TEXT), usz: TEXT.length - 1 }) },
  ];
  for (const pin of ONE_READING_PINS) {
    await test(`one reading: ${pin.rule} — refused, and by that rule alone`, () => {
      const z = cloakBundle([pin.entry()]);
      if (pin.streams) assertEqual(streamingNames(z, pin.walk).join(","), pin.streams, "the streaming walk");
      assertSoleObjection(z, pin.says);
    });
  }
  await test("a 0x7075 Unicode Path field renaming notes.txt to bin/run is refused, in both headers", () => {
    // sec-probe's upath.zip, as a bundle: `unzip -l` lists this entry as
    // bin/run, so a reader honouring the field writes it over the bin/run the
    // manifest describes. Both headers carry it, as in the vector.
    const z = cloakBundle([{ ...storedEntry("notes.txt", EVIL), extra: unicodePath("notes.txt", "bin/run") }]);
    const f = checkBundle(z, FIXTURE_LISTING, LIMITS).filter((x) => x.level === "error");
    assertEqual(f.map((x) => x.code).join(", "), "E_BUNDLE_UNREADABLE, E_BUNDLE_UNREADABLE", "the finding set");
    for (const where of ["central", "local"]) {
      assert(f.some((x) => x.message.includes(`its ${where} header carries a 0x7075`)), `the ${where} header's field was not named`);
    }
  });
  const EXTRA_PINS = [
    {
      rule: "0x7075 in the central header only", says: "central header carries a 0x7075",
      entry: () => ({ ...storedEntry("notes.txt", EVIL), extra: unicodePath("notes.txt", "bin/run"), local: { extra: Buffer.alloc(0) } }),
    },
    {
      rule: "0x7075 in the local header only", says: "local header carries a 0x7075",
      entry: () => ({ ...storedEntry("notes.txt", EVIL), local: { extra: unicodePath("notes.txt", "bin/run") } }),
    },
    {
      // A field claiming 255 bytes in a 4-byte block: where it ends is up to the reader.
      rule: "an extra block that does not split into fields", says: "does not split into whole fields",
      entry: () => ({ ...storedEntry("notes.txt", EVIL), extra: Buffer.concat([u16(0x5455), u16(255)]), local: { extra: Buffer.alloc(0) } }),
    },
  ];
  for (const pin of EXTRA_PINS) {
    await test(`one reading: ${pin.rule} — refused, and by that rule alone`, () => {
      assertSoleObjection(cloakBundle([pin.entry()]), pin.says);
    });
  }
  await test("one reading: an ordinary extra field (0x5455, a timestamp) in both headers is not refused", () => {
    const stamp = Buffer.concat([u16(0x5455), u16(5), Buffer.from([1]), u32(0)]);
    const f = checkBundle(cloakBundle([{ ...storedEntry("notes.txt", EVIL), extra: stamp }]), FIXTURE_LISTING, LIMITS);
    assert(f.length === 0, f.map((x) => `${x.code} ${x.message}`).join("\n"));
  });
  // ZIP64: 0xffffffff in a size or offset means the real value is in a ZIP64
  // field. This reader follows none, and an entry it cannot measure must not be
  // one the deflate-end check skips. astra-plugin build never writes ZIP64.
  const ZIP64_PINS = [
    {
      // One byte of slack after the stream: only the real size could expose it.
      rule: "a compressed size of 0xffffffff", says: "compressed size as 0xffffffff",
      entry: () => {
        const e = deflatedEntry("a.txt", TEXT);
        return { ...e, body: Buffer.concat([e.body, Buffer.alloc(1)]), csz: 0xffffffff };
      },
    },
    { rule: "a local header offset of 0xffffffff", says: "local header offset as 0xffffffff", entry: () => ({ ...deflatedEntry("a.txt", TEXT), centralOffset: 0xffffffff }) },
    {
      // Honest 32-bit sizes, and a ZIP64 field claiming others: which is real
      // depends on the reader.
      rule: "a 0x0001 ZIP64 field beside honest sizes", says: "0x0001 ZIP64 extended-information",
      entry: () => {
        const sizes = Buffer.alloc(16);
        sizes.writeBigUInt64LE(BigInt(TEXT.length), 0);
        sizes.writeBigUInt64LE(BigInt(TEXT.length * 2), 8);
        return { ...deflatedEntry("a.txt", TEXT), extra: Buffer.concat([u16(0x0001), u16(16), sizes]), local: { extra: Buffer.alloc(0) } };
      },
    },
  ];
  for (const pin of ZIP64_PINS) {
    await test(`one reading: ${pin.rule} — refused, and by that rule alone`, () => {
      assertSoleObjection(cloakBundle([pin.entry()]), pin.says);
    });
  }
  await test("one reading: an uncompressed size of 0xffffffff is refused before anything is inflated, and the reader names it", () => {
    const z = cloakBundle([deflatedEntry("a.txt", TEXT, { usz: 0xffffffff })]);
    assertEqual(errorCodes(z, FIXTURE_LISTING).join(", "), "E_BUNDLE_TOO_LARGE_EXTRACTED", "the finding set");
    const { bytes, problems } = readEntryOneWay(z, readZip(z).entries.find((x) => x.name === "a.txt"));
    assert(bytes === null && problems.some((x) => x.includes("uncompressed size as 0xffffffff")),
      `the reader did not refuse the sentinel by name: ${problems.join("; ") || "no problems"}`);
  });
  await test("one reading: a bundle over the extraction cap is refused before any entry is inflated", () => {
    // Inflating is bounded by each entry's DECLARED size, so the cap on the sum
    // of those is what bounds the reading; past it nothing is read. Were this
    // entry inflated, its short stream would add a second finding.
    const z = cloakBundle([deflatedEntry("a.txt", TEXT, { usz: LIMITS.max_extract_bytes + 1 })]);
    assertEqual(errorCodes(z, FIXTURE_LISTING).join(", "), "E_BUNDLE_TOO_LARGE_EXTRACTED", "the finding set");
  });
  // Where the stream ends is read off the inflater after it has produced
  // everything, not off the input it was handed: `inflateRawSync` with `info`
  // runs the engine until it reports the end of the stream or fails, and
  // `bytesWritten` is what it had consumed by then. These are the sizes where a
  // reader that judges the end per output chunk, before draining, refuses honest
  // files: near-zero data just over a multiple of 16 KiB (Node's chunk) or of
  // 64 KiB (the window astra-ce named), where one input byte fills many chunks.
  await test("one reading: an honest deflated 1 MiB + 1 file of zeros passes", () => {
    const z = cloakBundle([deflatedEntry("lib/zeros.bin", Buffer.alloc((1 << 20) + 1))]);
    const f = checkBundle(z, FIXTURE_LISTING, LIMITS);
    assert(f.length === 0, f.map((x) => `${x.code} ${x.message}`).join("\n"));
  });
  await test("one reading: the deflate end is exact at every size around a 16 KiB and 64 KiB multiple, and slack after it is not", () => {
    const wrong = [];
    for (const unit of [16384, 65536]) for (const k of [1, 2, 3, 16]) for (const d of [-1, 0, 1]) {
      const size = k * unit + d;
      // Zeros, and bytes that barely compress.
      const noisy = Buffer.from(Array.from({ length: size }, (_, i) => (Math.imul(i, 2654435761) >>> 24) & 0xff));
      for (const data of [Buffer.alloc(size), noisy]) {
        for (const level of [1, 9]) {
          const body = zlib.deflateRawSync(data, { level });
          for (const slack of [0, 1]) {
            const e = { ...deflatedEntry("z.bin", data), body: Buffer.concat([body, Buffer.alloc(slack)]), csz: body.length + slack };
            const zip = assembleZip([e]);
            const { problems } = readEntryOneWay(zip, readZip(zip).entries[0]);
            const refused = problems.some((x) => x.includes("deflate stream ends after"));
            if (problems.length !== slack || refused !== (slack === 1)) {
              wrong.push(`${size} bytes, level ${level}, ${slack} slack: ${problems.join("; ") || "accepted"}`);
            }
          }
        }
      }
    }
    assert(wrong.length === 0, wrong.slice(0, 5).join("\n"));
  });
  // astra-ce's vectors themselves, byte for byte (sec-probe and sec-probe2,
  // 2026-10-31), pinned by sha256 and carried as bundles. Each draws exactly
  // the objections named, so losing any one of them is red here as well.
  for (const v of ASTRA_CE_VECTORS) {
    await test(`astra-ce's ${v.file}, byte for byte inside a bundle, is refused: ${v.shape}`, () => {
      const raw = Buffer.from(v.base64, "base64");
      assertEqual(crypto.createHash("sha256").update(raw).digest("hex"), v.sha256, "the vector's bytes");
      const f = checkBundle(wrapAsBundle(raw), FIXTURE_LISTING, LIMITS).filter((x) => x.level === "error");
      assertEqual(f.map((x) => x.code).join(", "), v.says.map(() => "E_BUNDLE_UNREADABLE").join(", "),
        `the finding set:\n${f.map((x) => `${x.code}: ${x.message}`).join("\n")}`);
      for (const says of v.says) {
        assert(f.some((x) => x.message.includes(says)), `no finding says ${JSON.stringify(says)}`);
      }
    });
  }
  // The entries must lie end to end from byte zero to the central directory.
  // Each fixture breaks that in one place and nowhere else.
  const TILING_PINS = [
    {
      // A byte-identical MANIFEST.json at byte zero that nothing indexes, so the
      // byte-zero reading still agrees and only the layout is wrong.
      rule: "leading bytes", says: "the first ", lead: (m) => [{ ...m, hidden: true }],
      streams: "MANIFEST.json,MANIFEST.json,bin/run,a.txt", rest: () => [storedEntry("a.txt", TEXT)],
    },
    {
      rule: "an unindexed local header between entries", says: `bytes between "bin/run" and "a.txt"`,
      streams: "MANIFEST.json,bin/run,bin/run,a.txt",
      rest: () => [{ ...storedEntry("bin/run", EVIL), hidden: true }, storedEntry("a.txt", TEXT)],
    },
    {
      rule: "an unindexed local header after the last entry", says: `bytes between "a.txt" and the central directory`,
      streams: "MANIFEST.json,bin/run,a.txt,bin/run",
      rest: () => [storedEntry("a.txt", TEXT), { ...storedEntry("bin/run", EVIL), hidden: true }],
    },
    {
      // lib/outer is stored, and its bytes ARE lib/inner's whole local record; the
      // central directory points into them. A streaming reader skips lib/inner.
      rule: "an entry inside another", says: `"lib/inner" begins`, streams: "MANIFEST.json,bin/run,lib/outer",
      rest: () => {
        const inner = storedEntry("lib/inner", EVIL);
        return [
          storedEntry("lib/outer", Buffer.concat([localHeader("lib/inner", inner), EVIL])),
          { ...inner, at: (o) => o["lib/outer"] + 30 + "lib/outer".length },
        ];
      },
    },
    {
      // a.txt's declared size takes in the first 16 bytes of the central
      // directory, which precede any CRC field, so its CRC can be right.
      rule: "an entry running into the central directory", says: "bytes into the central directory",
      rest: () => {
        const cdHead = Buffer.concat([u32(0x02014b50), u16(0x031e), u16(20), u16(0), u16(0), u16(0), u16(0x21)]);
        return [{ ...storedEntry("a.txt", Buffer.concat([TEXT, cdHead])), body: TEXT }];
      },
    },
  ];
  for (const pin of TILING_PINS) {
    await test(`one reading: ${pin.rule} — refused, and by that rule alone`, () => {
      const z = cloakBundle(pin.rest(), { lead: pin.lead });
      if (pin.streams) assertEqual(streamingNames(z).join(","), pin.streams, "the streaming walk");
      assertSoleObjection(z, pin.says);
    });
  }
  // Every entry's local header must agree with its central record, field by
  // field, as zip 9's validate_header_consistency requires on the daemon's side.
  // Each fixture changes one field of a.txt's local header and nothing else.
  const HEADER_PINS = [
    { field: "name", local: { name: "bin/run" }, streams: "MANIFEST.json,bin/run,bin/run" },
    {
      // 0xff and 0xfe are each malformed UTF-8 and both decode here to U+FFFD,
      // so only a comparison of bytes sees two names; CP437 reads "ÿ" and "■".
      field: "name", as: "bytes that decode to one string", name: "a\ufffd.txt",
      rawName: Buffer.from("a\xff.txt", "latin1"), local: { name: Buffer.from("a\xfe.txt", "latin1") },
    },
    { field: "method", local: { method: 8 } },
    { field: "flags", local: { flags: 0x0800 } },
    { field: "modification time", local: { time: 0x1234 } },
    { field: "CRC-32", local: { crc: crc32(TEXT) ^ 1 } },
    { field: "compressed size", local: { csz: TEXT.length + 1 } },
    { field: "uncompressed size", local: { usz: TEXT.length + 1 } },
  ];
  for (const pin of HEADER_PINS) {
    await test(`one reading: the local header disagreeing on ${pin.field}${pin.as ? `, as ${pin.as}` : ""} — refused, and by that rule alone`, () => {
      const z = cloakBundle([{ ...storedEntry(pin.name ?? "a.txt", TEXT), rawName: pin.rawName, local: pin.local }]);
      if (pin.streams) assertEqual(streamingNames(z).join(","), pin.streams, "the streaming walk");
      assertSoleObjection(z, `its local header says ${pin.field} `);
    });
  }

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
  //
  // ── and why E_MANIFEST_NOT_FIRST appears twice below ───────────────────────
  //
  // It reads the CENTRAL-DIRECTORY INDEX (`manifestEntry.index !== 0`).
  // `E_MANIFEST_LOCAL_HEADER` reads BYTE ZERO. Those are two properties of an
  // archive, not one, and nothing in the ZIP format ties them together — the
  // central directory is appended last and lists the local records in whatever
  // order it likes. `manifest-not-first` violates BOTH at once, which is why
  // its row has to carry the other rule in `rest`, and why neither rule was
  // ever the sole reason that bundle was refused.
  //
  // Upstream added the pair that separates them (AstraPlugins gap 52):
  //
  //   manifest-first-by-offset-only   MANIFEST.json at byte zero, central index 1
  //   manifest-first-by-index-only    central index 0, byte zero is plugin.toml
  //
  // Each comes back with exactly ONE code, so each rule now has a bundle where
  // it is the only thing between that archive and an approved listing. Delete
  // either `err()` and exactly one of those two vectors is ACCEPTED — which the
  // vendored verdict test sees as well, so the loss is red in two places rather
  // than silent in one. `manifest-not-first` alone could never give that,
  // because whichever rule you deleted, the other still fired.
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
      // E_BUNDLE_UNREADABLE six times, from three checks this set once lacked.
      // The CRC-32 check: the central record declares the real manifest's size
      // and CRC over the decoy at offset 1186, whose first 760 bytes fail it.
      // The tiling check, twice: the real manifest's 803 bytes at byte zero are
      // indexed by nothing, and neither are the decoy's last 165, past that size.
      // The header-consistency check, three times: the decoy's local header says
      // CRC-32, compressed and uncompressed size other than its central record.
      // The old set was incomplete because the only local-against-central
      // comparison here was E_MANIFEST_HEADER_DISAGREE's, of MANIFEST.json's
      // bytes, and nothing read the archive's layout; this vector was always the
      // forged archive those checks describe.
      rest: [
        "E_BUNDLE_UNREADABLE", "E_BUNDLE_UNREADABLE", "E_BUNDLE_UNREADABLE",
        "E_BUNDLE_UNREADABLE", "E_BUNDLE_UNREADABLE", "E_BUNDLE_UNREADABLE", "E_MANIFEST_INVALID",
      ],
      otherwise: "the decoy manifest failing to parse, which is a property of that decoy and not of the comparison, " +
        "and the decoy's bytes failing the CRC-32 and the layout the central directory declares for MANIFEST.json",
    },
    {
      rule: "E_MANIFEST_NOT_FIRST", vector: "manifest-first-by-offset-only",
      rest: [],
      otherwise:
        "nothing else in this bundle — the manifest IS at byte zero here, so the byte-zero reader " +
        "passes it and this rule is the only objection left",
    },
    {
      // Unchanged by the tiling and header-consistency checks, deliberately: in
      // offset order its entries lie end to end (plugin.toml at 0, MANIFEST.json
      // at 259, bin/fixture at 1062, the central directory at 1136) and every
      // local header agrees with its record. Index order is not offset order,
      // and neither check reads index order, so the rule stays alone here.
      rule: "E_MANIFEST_LOCAL_HEADER", vector: "manifest-first-by-index-only",
      rest: [],
      otherwise:
        "nothing else in this bundle — the manifest IS the central directory's entry 0 here, so " +
        "E_MANIFEST_NOT_FIRST cannot fire and this rule is the only objection left",
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
      // Two messages, because the two failures are different facts and the
      // wrong one sends a reader to the wrong place. Where another rule still
      // fires, the verdict test stays green and this is the ONLY thing that
      // noticed. Where nothing fires, the vector is accepted and the verdict
      // test is red beside this one — which is what a vector that isolates a
      // rule buys, and saying "still green" there would be false.
      assert(codes.includes(pin.rule),
        codes.length === 0
          ? `${pin.rule} is not raised for the ${pin.vector} vector any more, and NOTHING ELSE ` +
            `rejects it either.\n        That bundle is now ACCEPTED, so ` +
            `\`${pin.vector} — rejects (bundle-structure)\` is red beside this ` +
            "check rather than passing behind it. This vector exists to isolate one rule: it is the " +
            `only bundle in the corpus where ${pin.rule} is the sole objection, and ${pin.otherwise}.`
          : `${pin.rule} is not raised for the ${pin.vector} vector any more.\n` +
            `        The vector is STILL REJECTED — by ${codes.join(", ")} — so ` +
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

// ── ZIPs assembled field by field, for the one-reading tests ──────────────────
//
// `writeZip` cannot write a local header that disagrees with its central record,
// which is the whole subject of those tests, so they build their own.

const TEXT = Buffer.from("hello world\n".repeat(40));
const crc32 = (b) => zlib.crc32(b) >>> 0;
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };

function localHeader(name, h, extra = Buffer.alloc(0)) {
  return Buffer.concat([
    u32(0x04034b50), u16(20), u16(h.flags ?? 0), u16(h.method ?? 0), u16(h.time ?? 0), u16(0x21),
    u32(h.crc), u32(h.csz), u32(h.usz), u16(Buffer.byteLength(name)), u16(extra.length), Buffer.from(name), extra,
  ]);
}

/**
 * Entries in byte order. Each is the CENTRAL record's fields — `name`, `method`,
 * `flags`, `crc`, `csz`, `usz`, `mode`, `extra` — plus `body`, the bytes after
 * its local header, and `local`, any fields the local header says differently.
 * `rawName` is the name's bytes where they are not `name` in UTF-8.
 * `hidden` writes the local record and no central one; `at` writes no bytes and
 * a central record pointing at `at(offsets)`, offsets being where each written
 * entry's local header landed, by name; `centralOffset` writes the entry and
 * gives its central record that offset instead.
 */
function assembleZip(entries) {
  const parts = [];
  const offsets = {};
  let offset = 0;
  for (const e of entries.filter((x) => !x.at)) {
    const local = localHeader(e.local?.name ?? e.rawName ?? e.name, { ...e, ...(e.local ?? {}) }, e.local?.extra ?? e.extra);
    offsets[e.name] ??= offset;
    e.writtenAt = offset;
    parts.push(local, e.body);
    offset += local.length + e.body.length;
  }
  const indexed = entries.filter((x) => !x.hidden);
  const cd = Buffer.concat(indexed.map((e) => {
    const extra = e.extra ?? Buffer.alloc(0);
    const name = e.rawName ?? Buffer.from(e.name);
    return Buffer.concat([
      u32(0x02014b50), u16(0x031e), u16(20), u16(e.flags ?? 0), u16(e.method ?? 0), u16(0), u16(0x21),
      u32(e.crc), u32(e.csz), u32(e.usz), u16(name.length), u16(extra.length), u16(0), u16(0), u16(0),
      u32(((e.mode ?? 0o644) << 16) >>> 0), u32(e.centralOffset ?? (e.at ? e.at(offsets) : e.writtenAt)), name, extra,
    ]);
  }));
  return Buffer.concat([
    ...parts, cd,
    u32(0x06054b50), u16(0), u16(0), u16(indexed.length), u16(indexed.length), u32(cd.length), u32(offset), u16(0),
  ]);
}

/** `content` is what a central-directory reading of the entry yields; the manifest describes it. */
function storedEntry(name, data, mode = 0o644) {
  return { name, mode, crc: crc32(data), csz: data.length, usz: data.length, body: data, content: data };
}
function deflatedEntry(name, data, over = {}) {
  const body = zlib.deflateRawSync(data);
  return { name, mode: 0o644, method: 8, crc: crc32(data), csz: body.length, usz: data.length, body, content: data, ...over };
}

const EVIL = Buffer.from("#!/bin/sh\necho pwned\n");

/**
 * astra-ce's three ZIP vectors, as base64 of the exact files measured on
 * 2026-10-31 under /mnt/data/claude-scratch/astra-zip, and what each draws here.
 */
const ASTRA_CE_VECTORS = [
  {
    file: "sec-probe/slack.zip", sha256: "71511e42a17bb35af2db71c72f2a45fe95754ce73ddfcda417968a77a92fe6f3",
    shape: "deflate slack behind bit 3 hides a readme.txt that swallows launch.sh",
    says: [`"a.txt": it sets general-purpose bit 3`, `"a.txt": its deflate stream ends after`],
    base64:
      "UEsDBBQACAAIAAAAIQAAAAAAAAAAAAAAAAAFAAAAYS50eHTLSM3JyVcozy/KSeECAFBLBwgtOwivDgAAAAwAAABQSwMEFAAAAAAA" +
      "AAAhAKugAuE8AAAAPAAAAAoAAAByZWFkbWUudHh0UEsDBBQAAAAAAAAAIQCiurakFQAAABUAAAAJAAAAbGF1bmNoLnNoIyEvYmlu" +
      "L3NoCmVjaG8gcHduZWQKUEsBAhQAFAAIAAgAAAAhAC07CK9GAAAADAAAAAUAAAAAAAAAAAAAAAAAAAAAAGEudHh0UEsBAhQAFAAA" +
      "AAAAAAAhAKK6tqQVAAAAFQAAAAkAAAAAAAAAAAAAAAAAaQAAAGxhdW5jaC5zaFBLBQYAAAAAAgACAGoAAAClAAAAAAA=",
  },
  {
    file: "sec-probe/upath.zip", sha256: "4649643cdf69d4e2f650209d73b49c190ea8d9a7d80888d5c1c174af093fc59f",
    shape: "a 0x7075 field renames notes.txt to launch.sh",
    says: [`"notes.txt": its central header carries a 0x7075`, `"notes.txt": its local header carries a 0x7075`],
    base64:
      "UEsDBBQAAAAAAAAAIQAVaixCBwAAAAcAAAAJABIAbm90ZXMudHh0dXAOAAEbUpQmbGF1bmNoLnNocGF5bG9hZFBLAQIUABQAAAAA" +
      "AAAAIQAVaixCBwAAAAcAAAAJABIAAAAAAAAAAAAAAAAAAABub3Rlcy50eHR1cA4AARtSlCZsYXVuY2guc2hQSwUGAAAAAAEAAQBJ" +
      "AAAAQAAAAAAA",
  },
  {
    // A stored entry under bit 3 has no end a streaming reader can compute, so
    // it searches for the descriptor whose CRC and size match: the one astra-ce
    // put after launch.sh, which makes notes.txt swallow launch.sh whole.
    file: "sec-probe2/stored-dd.zip", sha256: "3841c473f7ade57d1efca72aa33847d9508773df2147797a8bdb873828f691fb",
    shape: "a stored bit-3 entry whose descriptor sits after the next entry",
    says: [`"notes.txt": it sets general-purpose bit 3`, `the 16 bytes between "launch.sh" and the central directory`],
    base64:
      "UEsDBBQACAAAAAAAIVAAAAAAAAAAAAAAAAAJAAAAbm90ZXMudHh0aGFybWxlc3Mgbm90ZXMKUEsDBBQAAAAAAAAAIVCiurakFQAA" +
      "ABUAAAAJAAAAbGF1bmNoLnNoIyEvYmluL3NoCmVjaG8gcHduZWQKUEsHCMXt08xLAAAASwAAAFBLAQIUABQACAAAAAAAIVBcqLUJ" +
      "DwAAAA8AAAAJAAAAAAAAAAAAAAAAAAAAAABub3Rlcy50eHRQSwECFAAUAAAAAAAAACFQorq2pBUAAAAVAAAACQAAAAAAAAAAAAAA" +
      "AAA2AAAAbGF1bmNoLnNoUEsFBgAAAAACAAIAbgAAAIIAAAAAAA==",
  },
];

/** Info-ZIP's Unicode Path extra field (0x7075): version 1, CRC-32 of the raw name, the name to use instead. */
function unicodePath(raw, target) {
  const body = Buffer.concat([Buffer.from([1]), u32(crc32(Buffer.from(raw))), Buffer.from(target)]);
  return Buffer.concat([u16(0x7075), u16(body.length), body]);
}

/**
 * A deflated a.txt flagged bit 3 in both headers, with every size and the CRC in
 * both and no data descriptor: bit 3 is all that is wrong. A real descriptor
 * would sit between the entry and the next header, where the tiling check
 * objects to it too.
 */
function bit3Entry() {
  return { ...deflatedEntry("a.txt", TEXT), flags: 0x08 };
}

/**
 * sec-probe's slack.zip, as a bundle entry: a.txt's central compressed size runs
 * past the end of its deflate stream, over a local header for a second bin/run.
 * With `bit3` the local header carries no sizes (sec-probe's shape) and a
 * streaming reader inflates into the slack; without it both headers declare the
 * long size, and only a reader that trusts the stream's end over it gets there.
 */
function slackEntry({ bit3 }) {
  const e = deflatedEntry("a.txt", TEXT);
  const evil = Buffer.from("#!/bin/sh\necho pwned\n");
  const hidden = Buffer.concat([localHeader("bin/run", { crc: crc32(evil), csz: evil.length, usz: evil.length }), evil]);
  const descriptor = bit3 ? Buffer.concat([u32(0x08074b50), u32(e.crc), u32(e.csz), u32(e.usz)]) : Buffer.alloc(0);
  const body = Buffer.concat([e.body, descriptor, hidden]);
  return {
    ...e, body, csz: body.length,
    flags: bit3 ? 0x08 : 0, local: bit3 ? { crc: 0, csz: 0, usz: 0 } : undefined,
  };
}

/**
 * MANIFEST.json, a stored bin/run, then `rest`; the manifest lists the central
 * reading of every entry the central directory indexes. `lead(manifestEntry)`
 * returns entries to write before MANIFEST.json.
 */
function cloakBundle(rest, { lead = () => [] } = {}) {
  const entries = [runEntry(), ...rest];
  const manifestEntry = manifestEntryFor(entries.filter((e) => !e.hidden));
  return assembleZip([...lead(manifestEntry), manifestEntry, ...entries]);
}

const runEntry = () => storedEntry("bin/run", Buffer.from("#!/usr/bin/env node\nprocess.exit(0);\n"), 0o755);

/** A stored MANIFEST.json listing each of `entries` by its `content`. */
function manifestEntryFor(entries) {
  const files = entries.map((e) => ({
    path: e.name,
    sha256: crypto.createHash("sha256").update(e.content).digest("hex"),
    size: e.content.length,
    mode: e.mode.toString(8).padStart(4, "0"),
  })).sort((a, b) => (a.path < b.path ? -1 : 1));
  return storedEntry("MANIFEST.json", Buffer.from(stableStringify({
    schema: "astra.bundle/2",
    plugin_id: FIXTURE_LISTING.id,
    version: FIXTURE_LISTING.version,
    platform: { os: "linux", arch: "x86_64" },
    entry: { command: "./bin/run", args: [] },
    files,
  })));
}

/**
 * A raw ZIP carried as a bundle, its own bytes untouched: MANIFEST.json and a
 * stored bin/run in front, then the vector's local records byte for byte, then
 * our central records and the vector's, its offsets moved by what went in
 * front. The manifest lists the vector's central-directory reading, so every
 * objection left is about the vector and none about the wrapping.
 */
function wrapAsBundle(raw) {
  const vector = readZip(raw);
  const listed = vector.entries.map((e) => ({ name: e.name, mode: 0o644, content: readEntry(raw, e) }));
  const run = runEntry();
  const front = assembleZip([manifestEntryFor([run, ...listed]), run]);
  const frontCd = readZip(front).centralDirectoryOffset;
  const records = [front.subarray(frontCd, front.length - 22)];
  let p = vector.centralDirectoryOffset;
  for (let i = 0; i < vector.entries.length; i++) {
    const record = Buffer.from(raw.subarray(p, p + 46 + raw.readUInt16LE(p + 28) + raw.readUInt16LE(p + 30) + raw.readUInt16LE(p + 32)));
    record.writeUInt32LE(record.readUInt32LE(42) + frontCd, 42);
    records.push(record);
    p += record.length;
  }
  const locals = Buffer.concat([front.subarray(0, frontCd), raw.subarray(0, vector.centralDirectoryOffset)]);
  const cd = Buffer.concat(records);
  const n = 2 + vector.entries.length;
  return Buffer.concat([locals, cd, u32(0x06054b50), u16(0), u16(0), u16(n), u16(n), u32(cd.length), u32(locals.length), u16(0)]);
}

/**
 * Entry names in the order a STREAMING extractor meets them: local headers from
 * byte zero, the central directory never read. A bit-3 entry has no sizes in its
 * header, so the walk inflates to the end of the stream and steps over the data
 * descriptor, as such a reader must; `trustDeflateEnd` does that for every
 * deflated entry, as a reader that never consults the header's size does.
 */
function streamingNames(buf, { trustDeflateEnd = false } = {}) {
  const names = [];
  let p = 0;
  while (p + 30 <= buf.length && buf.readUInt32LE(p) === 0x04034b50) {
    const nameLen = buf.readUInt16LE(p + 26);
    const start = p + 30 + nameLen + buf.readUInt16LE(p + 28);
    names.push(buf.toString("utf8", p + 30, p + 30 + nameLen));
    const bit3 = buf.readUInt16LE(p + 6) & 0x08;
    if (bit3 || (trustDeflateEnd && buf.readUInt16LE(p + 8) === 8)) {
      p = start + zlib.inflateRawSync(buf.subarray(start), { info: true }).engine.bytesWritten;
      if (bit3) p += (buf.readUInt32LE(p) === 0x08074b50 ? 4 : 0) + 12;
    } else {
      p = start + buf.readUInt32LE(p + 18);
    }
  }
  return names;
}

/** The bundle draws exactly one error, E_BUNDLE_UNREADABLE, and it says `says`. */
function assertSoleObjection(z, says) {
  const f = checkBundle(z, FIXTURE_LISTING, LIMITS).filter((x) => x.level === "error");
  assertEqual(f.length, 1,
    `expected exactly one finding, got:\n${f.map((x) => `${x.code}: ${x.message}`).join("\n") || "nothing"}`);
  assertEqual(f[0].code, "E_BUNDLE_UNREADABLE", "the code");
  assert(f[0].message.includes(says), `the finding does not say ${JSON.stringify(says)}: ${f[0].message}`);
}
