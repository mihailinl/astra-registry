// The cross-repo bundle vectors, as this repository reads them.
//
// `tests/vectors/` is a VENDORED copy of `AstraPlugins/testdata/bundles/`,
// refreshed by `AstraPlugins/tools/vendor-testdata.sh` and verified against
// `SHA256SUMS` — by that script, and again here before a single vector is read.
// Do not edit it. Change the canonical directory and re-vendor.
//
// ── why this file exists ──────────────────────────────────────────────────
//
// Three programs read the `.astraplugin` format:
//
//   packer   AstraPlugins/astra-plugin-cli/src/bundle.rs     (defines it)
//   reader   Astra/astra-daemon/src/plugins/bundle.rs        (decides what extracts)
//   this one astra-registry/bot/lib/bundle.mjs               (decides what publishes)
//
// They were written from the same notes, in three languages, in three
// repositories that release on three schedules. `bot/lib/bundle.mjs` says at
// the top that being the third implementation is the point — the other two were
// written from the same notes, so a mistake in the notes reproduces in both and
// the registry is the only party positioned to notice. That only holds if all
// three are actually asked the same questions about the same bytes, which is
// what this file does.
//
// Two things are asserted per vector:
//
//   1. the VERDICT — accept or reject — against what `vectors.json` records for
//      this implementation, never against whatever it happens to do today;
//   2. the two DIGESTS, recomputed here and compared against the recorded ones.
//      Those were not produced by any of the three readers:
//      `testdata/bundles/handcheck.sh` derives them with `dd`, `printf` and
//      `sha256sum`. Three programs that share a mistake can agree with each
//      other; they cannot agree with coreutils.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

import {
  checkBundle,
  manifestDigest,
  artifactDigest,
  manifestBytesFromLocalHeader,
} from "../bot/lib/bundle.mjs";
import { invalidId } from "../tools/lib/ids.mjs";
import { readZip } from "../tools/lib/zip.mjs";

export const VECTOR_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "vectors");

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

export function loadVectors() {
  const p = path.join(VECTOR_DIR, "vectors.json");
  if (!fs.existsSync(p)) {
    throw new Error(
      `${p} is missing. It is a vendored copy of AstraPlugins/testdata/bundles; refresh it with ` +
        "AstraPlugins/tools/vendor-testdata.sh. A suite that skipped when its fixtures were " +
        "absent would pass forever.",
    );
  }
  const doc = JSON.parse(fs.readFileSync(p, "utf8"));
  if (doc.schema !== "astra.testdata.bundles/1") {
    throw new Error(`unexpected vectors.json schema ${JSON.stringify(doc.schema)}`);
  }
  return doc.vectors;
}

const read = (file) => fs.readFileSync(path.join(VECTOR_DIR, file));

/**
 * Register every shared-vector test against the harness in tools/selftest.mjs.
 * @param {{test: Function, assert: Function, limits: object}} harness
 */
export async function registerSharedVectorTests({ test, assert, limits }) {
  // ── the copy itself ─────────────────────────────────────────────────────
  //
  // Nothing below means anything if the bytes have moved. A vendored fixture
  // that was edited in place produces a digest disagreement that looks exactly
  // like an implementation bug, and the two are diagnosed in completely
  // different places — so the copy is checked first, by name, with the fix in
  // the message.
  await test("the vendored vector directory matches its own SHA256SUMS", () => {
    const sums = fs.readFileSync(path.join(VECTOR_DIR, "SHA256SUMS"), "utf8");
    let checked = 0;
    for (const line of sums.split("\n").filter((l) => l.trim())) {
      const want = line.slice(0, 64);
      const file = line.slice(66);
      assert(fs.existsSync(path.join(VECTOR_DIR, file)), `SHA256SUMS lists ${file}, which is absent`);
      assert(
        sha256(read(file)) === want,
        `${file} does not match SHA256SUMS. This is a VENDORED copy — do not edit it here. ` +
          "Change AstraPlugins/testdata/bundles and re-run AstraPlugins/tools/vendor-testdata.sh.",
      );
      checked++;
    }
    assert(checked >= 20, `only ${checked} files in SHA256SUMS`);
  });

  const vectors = loadVectors();

  // ── verdicts ────────────────────────────────────────────────────────────
  //
  // One test per vector rather than one loop, so a failure names the case and
  // a reviewer reads the list as a specification of what this bot refuses.
  for (const v of vectors) {
    const want = v.expect.registry;
    const label = `${v.name} — ${want}s (${v.layer})`;
    await test(label, () => {
      const buf = read(v.file);
      const expected = { id: v.plugin_id, version: v.version, platformKey: v.platform_key };

      // `bundle-structure` is this file's `checkBundle`. `plugin-id` is the id
      // validator, which is the gate that stops a string becoming a directory
      // name on a stranger's disk — the structural reader deliberately does not
      // police it. Splitting the two is what lets a vector say WHERE it is
      // expected to be caught rather than only that something, somewhere, said
      // no.
      let rejected;
      let detail;
      if (v.layer === "plugin-id") {
        const reason = invalidId(v.plugin_id);
        rejected = reason !== null;
        detail = reason ?? "accepted";
        // The structural half is recorded as passing these: the manifest agrees
        // with the listing, and the listing is the thing that is wrong.
        const structural = checkBundle(buf, expected, limits).filter((f) => f.level === "error");
        assert(
          structural.length === 0,
          `${v.name}: the structural reader was expected to pass this and raised ` +
            structural.map((f) => f.code).join(", "),
        );
      } else {
        const errors = checkBundle(buf, expected, limits).filter((f) => f.level === "error");
        rejected = errors.length > 0;
        detail = errors.map((f) => `${f.code}: ${f.message}`).join("\n        ") || "no findings";
      }

      if (want === "reject") {
        assert(
          rejected,
          `${v.name} is recorded as REJECTED here and was accepted.\n` +
            `        why it matters: ${v.why_it_matters}\n` +
            "        If this implementation legitimately does not catch it, that is a divergence " +
            "and belongs in vectors.json with a reason — not a silently passing test.",
        );
      } else {
        assert(!rejected, `${v.name} is recorded as ACCEPTED here and was refused:\n        ${detail}`);
      }
    });
  }

  // ── digests ─────────────────────────────────────────────────────────────

  await test("every vector's artifact digest matches the recorded value", () => {
    let n = 0;
    for (const v of vectors) {
      const buf = read(v.file);
      assert(
        artifactDigest(buf) === v.artifact_sha256,
        `${v.name}: artifact digest ${artifactDigest(buf)} != recorded ${v.artifact_sha256}`,
      );
      assert(buf.length === v.artifact_size, `${v.name}: size ${buf.length} != ${v.artifact_size}`);
      n++;
    }
    assert(n >= 20, `only ${n} vectors`);
  });

  await test("every vector's manifest digest matches, and is domain-separated", () => {
    let n = 0;
    for (const v of vectors) {
      if (v.manifest_digest === null) continue; // no readable manifest at offset 0, by construction
      const buf = read(v.file);
      const bytes = manifestBytesFromLocalHeader(buf);
      assert(sha256(bytes) === v.manifest_sha256, `${v.name}: plain manifest sha256 differs`);
      assert(
        manifestDigest(bytes) === v.manifest_digest,
        `${v.name}: domain-separated manifest digest differs`,
      );
      // Invariant 3 on real bytes. Without the prefix this has the same shape
      // as every files[].sha256, and a value lifted from one context verifies
      // in the other.
      assert(manifestDigest(bytes) !== sha256(bytes), `${v.name}: the two digests collide`);
      n++;
    }
    assert(n >= 20, `only ${n} manifest digests checked`);
  });

  // ── the collision ───────────────────────────────────────────────────────

  await test('the retired concatenation digest collides on "ab"+"c" vs "a"+"bc"', () => {
    const honest = vectors.find((v) => v.name === "collision-a-bc");
    const attack = vectors.find((v) => v.name === "collision-ab-c");

    // `SHA256(name₀‖content₀‖name₁‖content₁‖…)` in ZIP index order, skipping
    // the signature pair — the construction PRODUCTION_PLAN §5.2 retires,
    // reimplemented here for one purpose: to show it maps two different
    // archives to one number.
    const legacy = (file) => {
      const buf = read(file);
      const { entries } = readZip(buf);
      const h = crypto.createHash("sha256");
      for (const e of entries) {
        if (e.name === "SIGNATURE" || e.name === "PUBKEY") continue;
        h.update(Buffer.from(e.name, "utf8"));
        h.update(readEntryBytes(buf, e));
      }
      return h.digest("hex");
    };

    const a = legacy(honest.file);
    const b = legacy(attack.file);
    assert(a === honest.legacy_concat_sha256, `recomputed ${a} != recorded ${honest.legacy_concat_sha256}`);
    assert(b === attack.legacy_concat_sha256, `recomputed ${b} != recorded ${attack.legacy_concat_sha256}`);
    assert(a === b, "the collision pair no longer collides, so it demonstrates nothing");

    // Same manifest bytes, same legacy digest, different archives — one legacy
    // SIGNATURE authenticates either one.
    assert(honest.manifest_digest === attack.manifest_digest, "the pair must share a manifest");
    assert(honest.artifact_sha256 !== attack.artifact_sha256, "the pair must be different files");

    // And v2 separates them, in both directions of the exhaustiveness check.
    const expected = (v) => ({ id: v.plugin_id, version: v.version, platformKey: v.platform_key });
    const ok = checkBundle(read(honest.file), expected(honest), limits).filter((f) => f.level === "error");
    assert(ok.length === 0, `the honest half was refused: ${ok.map((f) => f.code).join(", ")}`);
    const codes = checkBundle(read(attack.file), expected(attack), limits)
      .filter((f) => f.level === "error")
      .map((f) => f.code);
    assert(
      codes.includes("E_MANIFEST_EXTRA_FILE") && codes.includes("E_MANIFEST_MISSING_FILE"),
      `the swap should trip exhaustiveness in BOTH directions, got ${codes.join(", ")}`,
    );
  });

  // ── permissions ─────────────────────────────────────────────────────────

  await test("the permission hash is recomputed from the manifest's own permissions", () => {
    // `permissions_hash` is compared across a repository boundary — this repo
    // records one side, the daemon checks the other — so three independent RFC
    // 8785 implementations have to agree on the canonical bytes. For a value of
    // this shape (strings and objects only) JCS reduces to "sort the keys, drop
    // the whitespace"; the numeric rules that make JCS interesting never bite.
    const permissionsHash = (permissions) => {
      const sorted = {};
      for (const k of Object.keys(permissions).sort()) sorted[k] = permissions[k];
      return `sha256:${sha256(Buffer.from(JSON.stringify(sorted), "utf8"))}`;
    };
    const manifestOf = (v) => JSON.parse(manifestBytesFromLocalHeader(read(v.file)).toString("utf8"));

    const ok = vectors.find((v) => v.name === "ok-permissions");
    const m = manifestOf(ok);
    assert(Object.keys(m.permissions).length > 0, "ok-permissions must carry a non-empty map");
    assert(
      permissionsHash(m.permissions) === m.permissions_hash,
      `recomputed ${permissionsHash(m.permissions)} != manifest ${m.permissions_hash}`,
    );
    assert(m.permissions_hash === ok.permissions_hash, "vectors.json disagrees with the manifest");

    // The adversarial case exists to mismatch. Assert that it still does —
    // a fixture that quietly stopped mismatching would make divergence F5 look
    // closed while nothing had been fixed.
    const bad = vectors.find((v) => v.name === "permissions-hash-mismatch");
    const bm = manifestOf(bad);
    assert(permissionsHash(bm.permissions) === bad.correct_permissions_hash, "correct hash drifted");
    assert(bm.permissions_hash === bad.recorded_permissions_hash, "recorded hash drifted");
    assert(
      permissionsHash(bm.permissions) !== bm.permissions_hash,
      "the permissions-hash-mismatch vector no longer mismatches",
    );
  });

  // ── divergences ─────────────────────────────────────────────────────────

  await test("every recorded divergence still diverges", () => {
    for (const v of vectors) {
      if (!v.divergence) continue;
      if (v.expect.registry === v.verdict) continue; // about another implementation
      const errors = checkBundle(
        read(v.file),
        { id: v.plugin_id, version: v.version, platformKey: v.platform_key },
        limits,
      ).filter((f) => f.level === "error");
      const accepted = errors.length === 0;
      assert(
        accepted === (v.expect.registry === "accept"),
        `divergence ${v.divergence.finding} on ${v.name} no longer describes this reader.\n` +
          `        ${v.divergence.summary}\n` +
          `        If it has been closed, delete the divergence block and set expect.registry ` +
          `to "${v.verdict}".`,
      );
    }
  });
}

/** `readEntry` without importing it under a name that shadows the loop var. */
function readEntryBytes(buf, entry) {
  // Deliberately re-derived from the local header rather than reusing
  // tools/lib/zip.mjs's `readEntry`, which follows the CENTRAL DIRECTORY's
  // offset — for `header-disagree` those are two different byte ranges, and the
  // retired digest was computed by a reader that walked the archive.
  const sigOffset = entry.offset;
  if (buf.readUInt32LE(sigOffset) !== 0x04034b50) {
    throw new Error(`${entry.name}: bad local header signature`);
  }
  const nameLen = buf.readUInt16LE(sigOffset + 26);
  const extraLen = buf.readUInt16LE(sigOffset + 28);
  const start = sigOffset + 30 + nameLen + extraLen;
  const raw = buf.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return Buffer.from(raw);
  return zlib.inflateRawSync(raw);
}
