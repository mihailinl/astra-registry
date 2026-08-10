// Structural checks on a .astraplugin, with no crypto anywhere.
//
// Everything here is decidable from the archive alone: is MANIFEST.json where
// §5.2 says it is, does it describe this listing, and does its file table match
// the archive exhaustively in both directions. Nothing here proves the bundle
// came from anyone — that is Phase 3's attestation check, and bot/README.md
// says so where someone might otherwise assume this file is the trust boundary.
//
// The order matters: every check below runs against BYTES IN MEMORY, and none
// of them extracts anything. A bundle that fails here never reaches a disk.

import crypto from "node:crypto";

import { readZip, readEntry, S_IFMT, S_IFLNK, S_IFDIR } from "../../tools/lib/zip.mjs";
import { platformKeyFromManifest } from "../../tools/lib/platform.mjs";

const SHELLS = new Set([
  "sh", "bash", "zsh", "fish", "dash", "csh", "ksh",
  "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
]);
const DECLARED_RUNTIMES = new Set(["python", "python3", "node", "deno", "bun"]);
// Read while they still exist; never authoritative. PRODUCTION_PLAN §5.2
// retires them, and §3.10 deletes them one release later.
const LEGACY_ENTRIES = new Set(["SIGNATURE", "PUBKEY"]);

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

// ---------------------------------------------------------------------------
// The two digest constructions, as this repo's independent implementation.
//
// They are defined by AstraPlugins/astra-plugin-cli/src/bundle.rs (the packer)
// and re-derived by Astra/astra-daemon/src/plugins/bundle.rs (the reader). This
// is the third. Three implementations of one written-down format is the point:
// the packer and the reader were written from the same notes, so a mistake in
// the notes reproduces in both, and the registry is the only party positioned
// to notice. tools/selftest.mjs pins both against known-answer vectors computed
// outside all three programs — change the construction anywhere and one of the
// three goes red rather than all three quietly agreeing on a new answer.
//
//   artifact digest = sha256(whole .astraplugin file), bare lowercase hex
//   manifest digest = sha256("astra.bundle/2\0" || MANIFEST.json bytes), ditto
//
// The domain prefix is what stops a manifest digest being presented as a file
// digest, or vice versa: the two are different functions of the same bytes.
// ---------------------------------------------------------------------------

/** The domain-separation prefix, `"astra.bundle/2\0"`. */
export const MANIFEST_DIGEST_DOMAIN = Buffer.from("astra.bundle/2\u0000", "latin1");

/**
 * `SHA256("astra.bundle/2\0" || manifest_bytes)`, lowercase hex.
 * @param {Buffer} manifestBytes the exact stored bytes of MANIFEST.json
 */
export function manifestDigest(manifestBytes) {
  return crypto.createHash("sha256")
    .update(MANIFEST_DIGEST_DOMAIN)
    .update(manifestBytes)
    .digest("hex");
}

/** `sha256` of the whole artifact, lowercase hex — what the index carries. */
export function artifactDigest(buf) {
  return sha256(buf);
}

/**
 * MANIFEST.json lifted straight out of the local file header at offset 0.
 *
 * Deliberately does not consult the central directory. `readEntry` follows the
 * central directory's offset, and nothing in this repo's ZIP reader checks that
 * the local header it lands on carries the same name — so a crafted archive can
 * file one set of bytes under MANIFEST.json in the index while a reader that
 * starts at byte zero, as the daemon does, sees another. Reading both and
 * comparing is the only way to notice.
 *
 * @param {Buffer} buf the whole .astraplugin
 * @returns {Buffer} the stored manifest bytes
 * @throws if entry zero is not a STORED MANIFEST.json
 */
export function manifestBytesFromLocalHeader(buf) {
  if (buf.length < 30 || buf.readUInt32LE(0) !== 0x04034b50) {
    throw new Error("the file does not begin with a ZIP local file header");
  }
  const method = buf.readUInt16LE(8);
  const compressedSize = buf.readUInt32LE(18);
  const uncompressedSize = buf.readUInt32LE(22);
  const nameLen = buf.readUInt16LE(26);
  const extraLen = buf.readUInt16LE(28);
  const name = buf.subarray(30, 30 + nameLen).toString("utf8");
  if (name !== "MANIFEST.json") {
    throw new Error(`the first archive entry is ${JSON.stringify(name)}, not MANIFEST.json`);
  }
  if (method !== 0) {
    throw new Error(`MANIFEST.json is compressed (method ${method}); §5.2 requires it stored`);
  }
  if (compressedSize !== uncompressedSize) {
    throw new Error("MANIFEST.json's stored and uncompressed sizes disagree");
  }
  const start = 30 + nameLen + extraLen;
  const end = start + compressedSize;
  if (end > buf.length) throw new Error("MANIFEST.json runs past the end of the file");
  return Buffer.from(buf.subarray(start, end));
}

/**
 * @param {Buffer} buf the whole .astraplugin
 * @param {{id: string, version: string, platformKey: string}} expected
 * @param {{max_archive_entries: number, max_extract_bytes: number}} limits
 * @returns {{level: "error"|"warn", code: string, message: string}[]}
 */
export function checkBundle(buf, expected, limits) {
  const findings = [];
  const err = (code, message) => findings.push({ level: "error", code, message });
  const warn = (code, message) => findings.push({ level: "warn", code, message });

  let zip;
  try {
    zip = readZip(buf);
  } catch (e) {
    err("E_BUNDLE_UNREADABLE", `${e.message}`);
    return findings;
  }
  const entries = zip.entries;

  if (entries.length > limits.max_archive_entries) {
    err("E_BUNDLE_TOO_MANY_ENTRIES",
      `${entries.length} entries, over the daemon's cap of ${limits.max_archive_entries} — it would refuse to extract this`);
  }
  const totalUncompressed = entries.reduce((n, e) => n + e.size, 0);
  if (totalUncompressed > limits.max_extract_bytes) {
    err("E_BUNDLE_TOO_LARGE_EXTRACTED",
      `${totalUncompressed} bytes uncompressed, over the daemon's cap of ${limits.max_extract_bytes}`);
  }

  // Path shape and entry kind, before anything is read.
  const seen = new Set();
  for (const e of entries) {
    const n = e.name;
    if (seen.has(n)) {
      err("E_BUNDLE_DUPLICATE_ENTRY",
        `${n} appears twice — the second copy would overwrite a file that already matched the manifest`);
    }
    seen.add(n);
    if (n.startsWith("/") || /^[A-Za-z]:/.test(n) || n.includes("\\")) {
      err("E_BUNDLE_ABSOLUTE_PATH", `${JSON.stringify(n)} is an absolute or Windows-style path`);
    }
    if (n.split("/").includes("..")) {
      err("E_BUNDLE_TRAVERSAL", `${JSON.stringify(n)} contains a ".." component`);
    }
    if (n.includes(":")) {
      err("E_BUNDLE_ADS", `${JSON.stringify(n)} contains ':' — an NTFS alternate data stream on Windows`);
    }
    if (/[. ]$/.test(n)) {
      err("E_BUNDLE_TRAILING_DOT", `${JSON.stringify(n)} ends in a dot or space, which Windows silently strips`);
    }
    if ((e.unixMode & S_IFMT) === S_IFLNK) {
      err("E_BUNDLE_SYMLINK",
        `${JSON.stringify(n)} is a symlink — the guards elsewhere validate the entry path, not the link target`);
    }
  }

  const manifestEntry = entries.find((e) => e.name === "MANIFEST.json");
  if (!manifestEntry) {
    err("E_MANIFEST_MISSING", "MANIFEST.json is not in the archive; this is not a v2 bundle");
    return findings;
  }
  if (manifestEntry.index !== 0) {
    err("E_MANIFEST_NOT_FIRST", `MANIFEST.json is entry ${manifestEntry.index}, and §5.2 requires it first`);
  }
  if (manifestEntry.method !== 0) {
    err("E_MANIFEST_COMPRESSED", "MANIFEST.json must be stored uncompressed");
  }

  // Two independent readings of the same entry, compared.
  //
  // `readEntry` follows the CENTRAL DIRECTORY's offset for MANIFEST.json.
  // `manifestBytesFromLocalHeader` starts at byte zero and reads the local file
  // header, which is what the daemon does. On an honest archive these are the
  // same bytes. On a crafted one they need not be: the central directory is
  // appended last and nothing in the format forces it to describe the archive
  // it is attached to, so an attacker can point the index at a benign entry
  // while byte zero holds the manifest that will actually be enforced. The
  // registry would then hash, display and approve a manifest no daemon reads.
  const centralBytes = (() => {
    try { return readEntry(buf, manifestEntry); } catch (e) {
      err("E_BUNDLE_UNREADABLE", `MANIFEST.json: ${e.message}`);
      return null;
    }
  })();
  if (centralBytes === null) return findings;

  let localBytes = null;
  try {
    localBytes = manifestBytesFromLocalHeader(buf);
  } catch (e) {
    err("E_MANIFEST_LOCAL_HEADER", `MANIFEST.json cannot be read from byte zero: ${e.message}`);
  }
  if (localBytes !== null && !localBytes.equals(centralBytes)) {
    err("E_MANIFEST_HEADER_DISAGREE",
      "the MANIFEST.json the central directory points at is not the one at byte zero " +
      `(central ${sha256(centralBytes).slice(0, 16)}…, local ${sha256(localBytes).slice(0, 16)}…) — ` +
      "the daemon reads the local header, so the manifest checked here is not the manifest enforced there");
  }

  let manifest;
  try {
    manifest = JSON.parse(centralBytes.toString("utf8"));
  } catch (e) {
    err("E_MANIFEST_INVALID", `MANIFEST.json is not valid JSON: ${e.message}`);
    return findings;
  }

  if (manifest.schema !== "astra.bundle/2") {
    err("E_MANIFEST_INVALID", `MANIFEST.schema is ${JSON.stringify(manifest.schema)}, expected "astra.bundle/2"`);
  }
  // The cross-check that closes "registry entry foo serves an archive whose
  // manifest says bar, and bar installs".
  if (manifest.plugin_id !== expected.id) {
    err("E_MANIFEST_ID_MISMATCH",
      `MANIFEST.plugin_id is ${JSON.stringify(manifest.plugin_id)} but the listing is ${JSON.stringify(expected.id)}`);
  }
  if (manifest.version !== expected.version) {
    err("E_MANIFEST_VERSION_MISMATCH",
      `MANIFEST.version is ${JSON.stringify(manifest.version)} but the listing is ${JSON.stringify(expected.version)}`);
  }
  const key = platformKeyFromManifest(manifest.platform);
  if (key === null) {
    err("E_MANIFEST_PLATFORM_UNKNOWN",
      `MANIFEST.platform ${JSON.stringify(manifest.platform)} maps to no registry platform key`);
  } else if (key !== expected.platformKey) {
    err("E_MANIFEST_PLATFORM_MISMATCH",
      `MANIFEST.platform is ${key} but the listing files it under ${expected.platformKey}`);
  }
  if (manifest.protocol !== undefined && !Number.isInteger(manifest.protocol)) {
    err("E_MANIFEST_INVALID", "MANIFEST.protocol is not an integer");
  }

  // files: exhaustive in both directions, and hashed.
  const files = Array.isArray(manifest.files) ? manifest.files : null;
  if (!files) {
    err("E_MANIFEST_INVALID", "MANIFEST.files is missing or not an array");
    return findings;
  }
  const sorted = [...files].map((f) => f.path).sort();
  if (sorted.join("\0") !== files.map((f) => f.path).join("\0")) {
    err("E_MANIFEST_UNSORTED", "MANIFEST.files is not sorted by path");
  }

  const listed = new Map(files.map((f) => [f.path, f]));
  const archived = entries.filter(
    (e) => e.name !== "MANIFEST.json" && !LEGACY_ENTRIES.has(e.name) && (e.unixMode & S_IFMT) !== S_IFDIR && !e.name.endsWith("/"),
  );
  for (const e of archived) {
    if (LEGACY_ENTRIES.has(e.name)) continue;
    if (!listed.has(e.name)) {
      err("E_MANIFEST_EXTRA_FILE",
        `${e.name} is in the archive but not in MANIFEST.files — an unlisted file is a file nothing verifies`);
    }
  }
  for (const f of files) {
    const e = entries.find((x) => x.name === f.path);
    if (!e) {
      err("E_MANIFEST_MISSING_FILE", `MANIFEST.files lists ${f.path}, which is not in the archive`);
      continue;
    }
    let data;
    try {
      data = readEntry(buf, e);
    } catch (ex) {
      err("E_BUNDLE_UNREADABLE", `${f.path}: ${ex.message}`);
      continue;
    }
    if (f.size !== undefined && f.size !== data.length) {
      err("E_MANIFEST_SIZE_MISMATCH", `${f.path}: manifest says ${f.size} bytes, archive has ${data.length}`);
    }
    const actual = sha256(data);
    if (f.sha256 !== actual) {
      err("E_MANIFEST_HASH_MISMATCH", `${f.path}: manifest says ${f.sha256}, archive content hashes to ${actual}`);
    }
  }
  for (const e of entries) {
    if (LEGACY_ENTRIES.has(e.name)) {
      warn("W_LEGACY_SIGNATURE_ENTRY",
        `${e.name} is a legacy in-ZIP signature entry. It is read for compatibility and is never a trust signal here (PRODUCTION_PLAN §5.2).`);
    }
  }

  // entry.command: what the daemon will actually execute.
  const command = manifest.entry?.command;
  if (typeof command !== "string" || command.length === 0) {
    err("E_ENTRY_MISSING", "MANIFEST.entry.command is missing");
  } else {
    const normalised = command.replace(/^\.\//, "");
    const base = normalised.split("/").pop().toLowerCase();
    if (command.startsWith("/") || /^[A-Za-z]:/.test(command)) {
      err("E_ENTRY_ABSOLUTE", `entry.command ${JSON.stringify(command)} is an absolute path`);
    } else if (normalised.split("/").includes("..")) {
      err("E_ENTRY_TRAVERSAL", `entry.command ${JSON.stringify(command)} escapes the install directory`);
    } else if (SHELLS.has(base)) {
      err("E_ENTRY_SHELL", `entry.command ${JSON.stringify(command)} is a shell; the daemon would execute arbitrary arguments`);
    } else if (!listed.has(normalised) && !DECLARED_RUNTIMES.has(base)) {
      err("E_ENTRY_NOT_IN_BUNDLE",
        `entry.command ${JSON.stringify(command)} is neither a file in the bundle nor a declared runtime (${[...DECLARED_RUNTIMES].join(", ")})`);
    }
  }

  return findings;
}
