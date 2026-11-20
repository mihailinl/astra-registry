// `state_sha256`: one digest of everything the plugins service decides.
//
// Phase 2 (plugin-phase2-design-2026-11-19 §4, step 4) makes the service the
// only decider. Its `GET /plugins/v1/export` answers
// `{serial, state_sha256, files: {path: base64 bytes}}` for every file under
// `plugins/` and `log/`, the signer commits that export, and before it signs it
// asks whether the tree it is about to sign IS the export. That question is
// this digest, and the service computes it too, so the definition below is a
// contract between two codebases. `tools/vectors/export-state-v1.json` holds
// worked cases for the other implementation to test itself against.
//
// ── THE DEFINITION ──────────────────────────────────────────────────────────
//
//   state_sha256 = lowercase hex SHA-256 over the concatenation, for every file
//   in the state, sorted by path in byte order, of the UTF-8 line
//
//       <sha256-hex of the file's bytes> <path>\n
//
//   (64 lowercase hex digits, one space U+0020, the path, one line feed U+000A).
//
//   * The state is every regular file whose repo-relative path starts with
//     `plugins/` or `log/`. Nothing else in the repository is in it.
//   * A path is `/`-separated, has no leading `/`, no empty, `.` or `..`
//     segment, no backslash, no NUL or other C0 control, and is valid UTF-8.
//   * Byte order means comparing the paths' UTF-8 bytes, unsigned, shorter
//     prefix first — NOT UTF-16 code units, which is what a JavaScript `sort()`
//     or Java's `String.compareTo` gives and which differs from byte order for
//     a path holding a character above U+FFFF next to one in U+E000–U+FFFF.
//     Rust's `str::cmp` and `Vec<u8>::cmp` are byte order.
//   * A file's content is its bytes, as stored: no newline normalisation, no
//     re-encoding, no JSON canonicalisation.
//   * The empty state's digest is SHA-256 of the empty string.
//   * The file mode is not part of the digest, because the export cannot carry
//     one. Instead this side refuses any entry under `plugins/` or `log/` that is
//     not a `100644` blob (a link, an executable, a submodule), so a mode the
//     digest cannot see never reaches it (`tools/lib/tree-modes.mjs` gives the
//     registry-wide reason).
//
// On this side the state is read from git objects at a commit — `git ls-tree`
// and `git cat-file` — and never from a working tree, so an untracked or
// ignored file, a checkout's line-ending filter or a half-applied edit cannot
// move it.

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

import { cleanEnv } from "./git-env.mjs";

/** The two top-level directories whose files are the state, in no particular order. */
export const STATE_ROOTS = Object.freeze(["plugins", "log"]);

/** The one git mode a state entry may have. */
export const STATE_MODE = "100644";

const UTF8 = new TextDecoder("utf-8", { fatal: true });

const hex = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

/** Byte order over the paths' UTF-8 encodings. */
export function compareStatePaths(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/**
 * Why `p` cannot be a state path, or `null` when it can.
 *
 * @param {string} p
 */
export function statePathProblem(p) {
  if (typeof p !== "string" || p === "") return "is empty";
  if (!STATE_ROOTS.some((r) => p.startsWith(`${r}/`))) return `is not under ${STATE_ROOTS.map((r) => `${r}/`).join(" or ")}`;
  if (p.isWellFormed && !p.isWellFormed()) return "is not valid Unicode";
  if (/[\u0000-\u001f\u007f\\]/.test(p)) return "holds a control character or a backslash";
  const segments = p.split("/");
  if (segments.some((s) => s === "" || s === "." || s === "..")) return "has an empty, `.` or `..` segment";
  return null;
}

/**
 * The lines the digest is taken over, as one string.
 *
 * @param {Map<string, Buffer|Uint8Array>|Record<string, Buffer|Uint8Array>} files path to bytes
 */
export function stateLines(files) {
  const entries = files instanceof Map ? [...files.entries()] : Object.entries(files);
  for (const [p] of entries) {
    const problem = statePathProblem(p);
    if (problem) throw new Error(`${JSON.stringify(p)} ${problem}, so it has no place in the state`);
  }
  entries.sort(([a], [b]) => compareStatePaths(a, b));
  return entries.map(([p, bytes]) => `${hex(bytes)} ${p}\n`).join("");
}

/**
 * `state_sha256` of a set of files.
 *
 * @param {Map<string, Buffer|Uint8Array>|Record<string, Buffer|Uint8Array>} files
 */
export function stateSha256(files) {
  return hex(Buffer.from(stateLines(files), "utf8"));
}

function git(root, args, { input } = {}) {
  try {
    return execFileSync("git", ["--literal-pathspecs", "-C", root, ...args], {
      input,
      maxBuffer: 1024 * 1024 * 1024,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      env: cleanEnv(),
    });
  } catch (e) {
    const stderr = String(e?.stderr ?? "").trim();
    throw new Error(`git ${args.join(" ")} failed in ${root}: ${stderr || e?.message || "no output"}`);
  }
}

/**
 * Every tracked entry of `commit`'s tree under `roots`, as `{mode, type, oid, path}`.
 *
 * @param {{root: string, commit: string, roots?: readonly string[]}} opts
 */
export function treeEntriesAt({ root, commit, roots = STATE_ROOTS }) {
  const out = git(root, ["ls-tree", "-r", "-z", "--full-tree", commit, "--", ...roots]);
  const entries = [];
  for (const record of out.toString("binary").split("\0")) {
    if (!record) continue;
    const tab = record.indexOf("\t");
    const [mode, type, oid] = record.slice(0, tab).split(" ");
    let p;
    try {
      p = UTF8.decode(Buffer.from(record.slice(tab + 1), "binary"));
    } catch {
      throw new Error(`${commit} holds a path under ${roots.join("/, ")}/ that is not valid UTF-8`);
    }
    entries.push({ mode, type, oid, path: p });
  }
  return entries;
}

/**
 * The bytes of many blobs in one `git cat-file --batch`.
 *
 * @param {string} root
 * @param {string[]} oids
 * @returns {Buffer[]} in the order asked
 */
export function blobsAt(root, oids) {
  if (!oids.length) return [];
  const out = git(root, ["cat-file", "--batch"], { input: oids.map((o) => `${o}\n`).join("") });
  const blobs = [];
  let at = 0;
  for (const oid of oids) {
    const nl = out.indexOf(0x0a, at);
    const header = out.subarray(at, nl).toString("utf8").split(" ");
    if (header[0] !== oid || header[1] !== "blob") throw new Error(`git cat-file answered ${header.join(" ")} for ${oid}`);
    const size = Number(header[2]);
    blobs.push(out.subarray(nl + 1, nl + 1 + size));
    at = nl + 1 + size + 1;
  }
  return blobs;
}

/**
 * The state at a commit: path to bytes, read from git objects.
 *
 * Throws on an entry the state cannot hold (a mode other than `100644`, a path
 * that breaks the grammar), because a digest that skipped it would describe a
 * tree that is not the one being signed.
 *
 * @param {{root: string, commit: string}} opts
 * @returns {Map<string, Buffer>}
 */
export function stateFilesAt({ root, commit }) {
  const entries = treeEntriesAt({ root, commit }).filter((e) => STATE_ROOTS.some((r) => e.path.startsWith(`${r}/`)));
  for (const e of entries) {
    if (e.type !== "blob" || e.mode !== STATE_MODE) {
      throw new Error(`${e.path} at ${commit} is a ${e.type} with mode ${e.mode}; the state holds ${STATE_MODE} files only`);
    }
    const problem = statePathProblem(e.path);
    if (problem) throw new Error(`${JSON.stringify(e.path)} at ${commit} ${problem}`);
  }
  const blobs = blobsAt(root, entries.map((e) => e.oid));
  return new Map(entries.map((e, i) => [e.path, blobs[i]]));
}

/**
 * `{files, state_sha256}` at a commit.
 *
 * @param {{root: string, commit: string}} opts
 */
export function stateAt({ root, commit }) {
  const files = stateFilesAt({ root, commit });
  return { files, state_sha256: stateSha256(files) };
}

/**
 * The `files` member of an export, decoded, with what is wrong with it.
 *
 * Base64 is checked strictly — the decoded bytes must re-encode to the same
 * text — because Node's decoder skips characters it does not know, and two
 * spellings of one file would let an export say one thing and digest another.
 *
 * @param {unknown} doc an export document
 * @returns {{files: Map<string, Buffer>, problems: string[]}}
 */
export function exportFiles(doc) {
  const files = new Map();
  const problems = [];
  const raw = doc && typeof doc === "object" ? doc.files : undefined;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { files, problems: ["the export has no `files` object"] };
  }
  for (const [p, b64] of Object.entries(raw)) {
    const problem = statePathProblem(p);
    if (problem) {
      problems.push(`${JSON.stringify(p)} ${problem}`);
      continue;
    }
    if (typeof b64 !== "string") {
      problems.push(`${p}: its bytes are not a base64 string`);
      continue;
    }
    const bytes = Buffer.from(b64, "base64");
    if (bytes.toString("base64") !== b64) {
      problems.push(`${p}: its bytes are not canonical base64`);
      continue;
    }
    files.set(p, bytes);
  }
  return { files, problems };
}

/**
 * Encode a state as an export's `files` member, keys in byte order.
 *
 * @param {Map<string, Buffer>} files
 */
export function filesMember(files) {
  const out = {};
  for (const p of [...files.keys()].sort(compareStatePaths)) out[p] = files.get(p).toString("base64");
  return out;
}
