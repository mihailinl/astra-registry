// The review mark's three rules, read out of git (contract 3.0.0: B.4's
// review-mark paragraph; DEC-19; MOD-56; §4.8 row 11).
//
//   1. Every version record added on the first-parent line from **3.0.0's
//      landing commit** on carries `review: "unreviewed"`, whichever path
//      published it.
//   2. `review` becomes `reviewed` only in a commit that adds a moderation-log
//      `review` entry naming that version and carries a `Service-Decision:`
//      trailer, and only from `unreviewed` or absent.
//   3. No commit changes it in any other direction.
//
// **Why a separate module, and not three more checks inside the validator's
// tree walk.** Every other rule `tools/validate.mjs` applies is a property of
// the files as they stand. These three are properties of the COMMIT that
// changed a file, which no per-record schema and no tree walk can see: the same
// record with no `review` member is correct if it was added before the landing
// commit and a defect if it was added after. So they read git, and they read it
// in the one shape B.4 publishes for finding the landing commit, so that this
// module, detector A's row 11 and the service's reader find the same commit.
//
// **Two halves, because the publish path validates before it commits.**
// `bot/publish-apply.mjs` and the moderation commit job both run the validator
// over a working tree whose new records are not committed yet. The committed
// half walks history from the landing commit to HEAD; the working-tree half
// compares the tree with HEAD, and is the half that closes the race a
// publication run opens when it checks out main before the landing commit and
// pushes after it: its push is refused, `publish-apply` resets to the new main
// and re-runs THIS validator over the re-applied record, and a record without
// the mark is refused there rather than committed (bot/tests/
// publish-apply.test.mjs). The working-tree half needs only HEAD, so it also
// runs in a depth-1 checkout, where the committed half says "not asked".
//
// **What neither half is.** It is not detector A's row 11, which alarms on a
// `main` it did not gate (registry plan BOT-43), and it does not decide what a
// moderation-log entry must contain beyond naming the version: that is
// `bot/moderation.mjs --check`'s.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { cleanEnv } from "./git-env.mjs";
import { trailerLine } from "../../bot/lib/decisions.mjs";
import { SOURCE_DIR as MODERATION_DIR } from "../../bot/lib/moderation.mjs";

/** The file whose first-parent history names the landing commit (B.4). */
export const VERSION_SCHEMA_PATH = "schema/version-v1.json";

/** What a publishing commit writes, and the one value a move may reach (MOD-56). */
export const UNREVIEWED = "unreviewed";
export const REVIEWED = "reviewed";

/** The moderation-log action an `M_REVIEW` writes (MOD-47, 3.0.0). */
export const REVIEW_ACTION = "review";

const VERSION_FILE = /^plugins\/([^/]+)\/versions\/([^/]+)\.json$/;
const LOG_FILE = new RegExp(`^${MODERATION_DIR.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/[^/]+\\.json$`);
const MAX_BUFFER = 256 * 1024 * 1024;

const git = (root, args, { input, allowFailure = false } = {}) => {
  try {
    // A batch read comes back as bytes: `cat-file --batch` sizes each object
    // in BYTES, and slicing decoded text by a byte count cuts a record that
    // carries a non-ASCII string in the wrong place.
    return execFileSync("git", ["-C", root, ...args], {
      ...(input === undefined ? { encoding: "utf8" } : {}),
      maxBuffer: MAX_BUFFER,
      env: { ...cleanEnv(), GIT_PAGER: "cat", GIT_OPTIONAL_LOCKS: "0" },
      stdio: ["pipe", "pipe", "pipe"],
      ...(input === undefined ? {} : { input }),
    });
  } catch (e) {
    if (allowFailure) return null;
    throw new Error(`git ${args.join(" ")} failed in ${root}: ${String(e?.stderr ?? e?.message ?? e).trim()}`);
  }
};

/** Does this text of schema/version-v1.json declare the member? Unparseable text declares nothing. */
export function declaresReview(text) {
  if (typeof text !== "string") return false;
  try {
    const doc = JSON.parse(text);
    return Boolean(doc && typeof doc === "object" && doc.properties && Object.hasOwn(doc.properties, "review"));
  } catch {
    return false;
  }
}

/**
 * `<rev>:<path>` for many specs in one `git cat-file --batch`. Returns a Map
 * from spec to its text, with a missing object mapped to null.
 */
export function readBlobs(root, specs) {
  const out = new Map();
  const list = [...new Set(specs)];
  if (list.length === 0) return out;
  const buf = git(root, ["cat-file", "--batch"], { input: `${list.join("\n")}\n` });
  let at = 0;
  for (const spec of list) {
    const nl = buf.indexOf(0x0a, at);
    const header = buf.subarray(at, nl).toString("utf8");
    at = nl + 1;
    const m = /^[0-9a-f]{40,64} (\w+) (\d+)$/.exec(header);
    if (!m) {
      out.set(spec, null);
      continue;
    }
    const size = Number(m[2]);
    out.set(spec, m[1] === "blob" ? buf.subarray(at, at + size).toString("utf8") : null);
    at += size + 1;
  }
  return out;
}

/**
 * B.4's recipe for 3.0.0's landing commit, on `ref`'s first-parent line: walk
 * schema/version-v1.json's first-parent history oldest first and take the
 * first commit whose copy declares `review`. Null when no commit does.
 */
export function landingCommit(root, { ref = "HEAD" } = {}) {
  const log = git(root, ["log", "--first-parent", "--reverse", "--format=%H", ref, "--", VERSION_SCHEMA_PATH], { allowFailure: true });
  if (!log) return null;
  const commits = log.split("\n").filter(Boolean);
  const texts = readBlobs(root, commits.map((c) => `${c}:${VERSION_SCHEMA_PATH}`));
  return commits.find((c) => declaresReview(texts.get(`${c}:${VERSION_SCHEMA_PATH}`))) ?? null;
}

const parseJson = (text) => {
  if (typeof text !== "string") return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

const markOf = (doc) => (doc && typeof doc === "object" && Object.hasOwn(doc, "review") ? doc.review : undefined);
const show = (v) => (v === undefined ? "absent" : JSON.stringify(v));

/** Does this moderation-log document name `id@version` under the `review` action? */
function namesReview(doc, id, version) {
  return Boolean(doc && doc.action === REVIEW_ACTION && doc.plugin === id &&
    Array.isArray(doc.versions) && doc.versions.includes(version));
}

/** Is `value` a `Service-Decision:` trailer value BOT-37's grammar accepts? */
function serviceDecisionOk(value) {
  try {
    trailerLine("Service-Decision", value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Judge one change of a version record's mark. `logs` are the moderation-log
 * documents the same change adds; `trailers` the commit's `Service-Decision:`
 * values, or null for a working tree, which has no message yet.
 */
function judgeMove({ id, version, before, after, logs, trailers, where }) {
  if (!(before === undefined || before === UNREVIEWED) || after !== REVIEWED) {
    return `${where} changes its review mark from ${show(before)} to ${show(after)}. The only change the contract ` +
      `allows is from \`${UNREVIEWED}\` or absent to \`${REVIEWED}\`, by an applied \`M_REVIEW\` (MOD-56); no commit ` +
      "changes it in any other direction (B.4; §4.8 row 11)";
  }
  if (!logs.some((doc) => namesReview(doc, id, version))) {
    return `${where} marks ${id} ${version} \`${REVIEWED}\` and adds no moderation-log \`${REVIEW_ACTION}\` entry ` +
      `under ${MODERATION_DIR}/ naming that version. Only the commit that applies an \`M_REVIEW\` sets the mark, and it ` +
      "logs the versions it moved (MOD-56; §4.8 row 11)";
  }
  if (trailers !== null && !trailers.some(serviceDecisionOk)) {
    return `${where} marks ${id} ${version} \`${REVIEWED}\` in a commit that carries no \`Service-Decision:\` trailer. ` +
      "An `M_REVIEW` is a service decision, and its commit names it (MOD-56; BOT-37; §4.8 row 11)";
  }
  return null;
}

/**
 * The three rules over `root`'s committed first-parent history and its working
 * tree.
 *
 * @param {string} root a checkout; the rules are asked only where it is the top
 *   of its own git work tree, never of a repository that merely encloses it
 * @returns {{errors: {file: string, message: string}[], notes: string[], landing: string|null}}
 */
export function reviewMarkFindings(root) {
  const errors = [];
  const notes = [];
  const result = (landing = null) => ({ errors, notes, landing });

  let top = null;
  try {
    top = String(git(root, ["rev-parse", "--show-toplevel"], { allowFailure: true }) ?? "").trim() || null;
  } catch {
    top = null;
  }
  if (!top || fs.realpathSync(top) !== fs.realpathSync(root)) {
    notes.push(
      `not asked: ${root} is not the top of a git work tree of its own, so no commit can be said to have added a ` +
      "version record. The review-mark rules read git (B.4); a fixture directory has none");
    return result();
  }
  const headOk = git(root, ["rev-parse", "--verify", "-q", "HEAD"], { allowFailure: true }) !== null;
  const shallow = String(git(root, ["rev-parse", "--is-shallow-repository"], { allowFailure: true }) ?? "").trim() === "true";

  const treeSchema = fs.existsSync(path.join(root, VERSION_SCHEMA_PATH))
    ? fs.readFileSync(path.join(root, VERSION_SCHEMA_PATH), "utf8")
    : null;
  const headSchema = headOk ? readBlobs(root, [`HEAD:${VERSION_SCHEMA_PATH}`]).get(`HEAD:${VERSION_SCHEMA_PATH}`) : null;

  // ── the committed half ─────────────────────────────────────────────────
  let landing = null;
  if (headOk && !shallow) {
    landing = landingCommit(root);
    if (landing) committedHalf(root, landing, errors);
  } else if (headOk && shallow) {
    notes.push(
      "not asked: this checkout is shallow, so the commits that added each version record since the landing commit " +
      "cannot be walked. build-index.yml's check job and both publish jobs fetch the whole history and ask it");
  }

  // ── the working-tree half ─────────────────────────────────────────────
  // Landed at or before the tree being judged: HEAD's schema declares the
  // member (so the landing commit is HEAD or an ancestor of it), or the tree's
  // does (the commit about to be made is the landing commit).
  const landed = declaresReview(headSchema) || declaresReview(treeSchema);
  if (!landed) {
    notes.push("3.0.0's landing commit is not on this line and the tree does not declare `review`, so no version record here is held to the mark yet");
    return result(landing);
  }
  workingTreeHalf(root, { headOk }, errors);
  return result(landing);
}

/** The commits from `landing` (inclusive) to HEAD on the first-parent line. */
function committedHalf(root, landing, errors) {
  const parent = git(root, ["rev-parse", "--verify", "-q", `${landing}^1`], { allowFailure: true });
  const range = parent ? [`${String(parent).trim()}..HEAD`] : ["HEAD"];
  // `--parents`, so each line is the commit and its parents: the first one is
  // the parent a first-parent line diffs against, a merge's included.
  const lines = String(git(root, ["rev-list", "--first-parent", "--reverse", "--parents", ...range]) ?? "")
    .split("\n").filter(Boolean);
  if (lines.length === 0) return;

  // One diff-tree over every commit, each against its FIRST parent, limited to
  // the two trees the rules read. A commit with no change there prints nothing.
  const pairs = lines.map((l) => {
    const [c, p] = l.split(" ");
    return p ? `${c} ${p}` : c;
  });
  const raw = git(root, ["diff-tree", "--stdin", "-r", "--no-renames", "--name-status", "-z", "--root", "--",
    "plugins", MODERATION_DIR], { input: `${pairs.join("\n")}\n` }).toString("utf8");
  const tokens = raw.split("\0").filter((t) => t !== "");
  const changes = new Map();
  let current = null;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (/^[0-9a-f]{40,64}$/.test(t)) {
      current = t;
      if (!changes.has(current)) changes.set(current, []);
      continue;
    }
    const file = tokens[++i];
    if (current && file !== undefined) changes.get(current).push({ status: t[0], file });
  }

  const parentOf = new Map(pairs.map((p) => p.split(" ")).map(([c, p]) => [c, p ?? null]));
  const specs = [];
  for (const [c, list] of changes) {
    for (const { status, file } of list) {
      if (VERSION_FILE.test(file)) {
        if (status === "A" || status === "M") specs.push(`${c}:${file}`);
        if (status === "M" && parentOf.get(c)) specs.push(`${parentOf.get(c)}:${file}`);
      } else if (LOG_FILE.test(file) && status === "A") {
        specs.push(`${c}:${file}`);
      }
    }
  }
  const blobs = readBlobs(root, specs);

  const moved = [];
  for (const [c, list] of changes) {
    const logs = list
      .filter(({ status, file }) => status === "A" && LOG_FILE.test(file))
      .map(({ file }) => parseJson(blobs.get(`${c}:${file}`)))
      .filter(Boolean);
    for (const { status, file } of list) {
      const m = VERSION_FILE.exec(file);
      if (!m) continue;
      const [, id, version] = m;
      const after = markOf(parseJson(blobs.get(`${c}:${file}`)));
      if (status === "A") {
        if (after !== UNREVIEWED) {
          errors.push({
            file,
            message:
              `was added in ${c.slice(0, 12)}, at or after 3.0.0's landing commit, with its review mark ${show(after)}. ` +
              `Every version record added from that commit carries \`review: "${UNREVIEWED}"\`, whichever path ` +
              "published it (B.4; DEC-19; §4.8 row 11)",
          });
        }
      } else if (status === "M") {
        const before = markOf(parseJson(blobs.get(`${parentOf.get(c)}:${file}`)));
        if (before !== after) moved.push({ c, file, id, version, before, after, logs });
      }
    }
  }
  if (moved.length === 0) return;

  const trailerOut = git(root, ["log", "--no-walk=unsorted", "--format=%H%x00%(trailers:key=Service-Decision,valueonly,separator=%x01)%x00",
    ...[...new Set(moved.map((x) => x.c))]]);
  const trailers = new Map();
  const parts = String(trailerOut).split("\0");
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const c = parts[i].trim();
    if (c) trailers.set(c, parts[i + 1].split("\x01").map((v) => v.trim()).filter(Boolean));
  }
  for (const x of moved) {
    const why = judgeMove({
      id: x.id, version: x.version, before: x.before, after: x.after, logs: x.logs,
      trailers: trailers.get(x.c) ?? [], where: `commit ${x.c.slice(0, 12)}`,
    });
    if (why) errors.push({ file: x.file, message: why });
  }
}

/** The tree as it stands against HEAD: what the next commit would add or change. */
function workingTreeHalf(root, { headOk }, errors) {
  const atHead = new Set();
  if (headOk) {
    const listed = git(root, ["ls-tree", "-r", "-z", "--name-only", "HEAD", "--", "plugins", MODERATION_DIR]);
    for (const f of String(listed).split("\0").filter(Boolean)) atHead.add(f);
  }
  const walk = (rel) => {
    const abs = path.join(root, rel);
    let entries;
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return [];
    }
    return entries.flatMap((e) => (e.isDirectory() ? walk(`${rel}/${e.name}`) : e.isFile() ? [`${rel}/${e.name}`] : []));
  };
  const versionFiles = walk("plugins").filter((f) => VERSION_FILE.test(f));
  const addedLogs = walk(MODERATION_DIR)
    .filter((f) => LOG_FILE.test(f) && !atHead.has(f))
    .map((f) => parseJson(fs.readFileSync(path.join(root, f), "utf8")))
    .filter(Boolean);
  const tracked = versionFiles.filter((f) => atHead.has(f));
  const before = readBlobs(root, tracked.map((f) => `HEAD:${f}`));

  for (const file of versionFiles) {
    const [, id, version] = VERSION_FILE.exec(file);
    const doc = parseJson(fs.readFileSync(path.join(root, file), "utf8"));
    if (doc === undefined) continue; // an unparseable record is the schema check's to refuse
    const after = markOf(doc);
    if (!atHead.has(file)) {
      if (after !== UNREVIEWED) {
        errors.push({
          file,
          message:
            `is added by this change with its review mark ${show(after)}, at or after 3.0.0's landing commit. Every ` +
            `version record added from that commit carries \`review: "${UNREVIEWED}"\`, whichever path published it; ` +
            "a publication run that derived this record before the landing commit is refused here and publishes on its " +
            "next run (B.4; DEC-19)",
        });
      }
      continue;
    }
    const prior = markOf(parseJson(before.get(`HEAD:${file}`)));
    if (prior === after) continue;
    const why = judgeMove({ id, version, before: prior, after, logs: addedLogs, trailers: null, where: "this change" });
    if (why) errors.push({ file, message: why });
  }
}
