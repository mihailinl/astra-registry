// What Pages serves, and the one function that decides whether the withdrawal
// list on it is signed.
//
// ── the latch (D5, ROLL-57, ROLL-14) ────────────────────────────────────────
//
// Pages serves an UNSIGNED withdrawal list today, and every shipped 0.2.x
// daemon reads that and stays `NotEnforced`. The moment Pages serves a list
// that verifies, those clients arm themselves, and seven days after their last
// accepted fetch an unsigned or stale list blocks installs. Arming is therefore
// one-way in the field whatever git says, and the flag has to be read the same
// way:
//
//   **armed** when ANY commit reachable from the Source-Commit ADDED
//   `policy/pages-withdrawal-list.json`.
//
// History, not the current tree, and the difference is the whole point. Reading
// the tree makes a revert of the flag commit put an unsigned list back in front
// of clients that have already armed — they do not disarm, they block installs
// a week later, and the person who reverted sees a green build. Reading the
// history means the revert changes nothing, which is the honest model of what
// the field is doing.
//
// The flag is never changed and never deleted, not even at R9b. RC-R1-6's
// "Arming flag is permanent" row is what asserts that; this module only has to
// be unable to notice.
//
// ── one function, not a condition in a workflow ─────────────────────────────
//
// `armingState` is the single arming decision D5 asks for. The `pages` job,
// RC-R1-5's served-vs-signed check and RC-R1-7's probe all have to agree about
// when the latch closed, and three readings of "is the flag there" in three
// languages is three chances to read it differently.

import fs from "node:fs";
import path from "node:path";

import { blobAt, gitMaybe } from "./git.mjs";
import { SIGNED_FILES } from "./plan.mjs";

/** The flag. Its content is `schema` and `armed_at`, exactly (G3, proposed). */
export const FLAG_PATH = "policy/pages-withdrawal-list.json";

/** G3's proposed schema for the flag. `MBE-PENDING`: readers ignore it until a contract version records it. */
export const FLAG_SCHEMA = "astra.registry.pages-withdrawal-list/1";

/**
 * Has the latch closed at this commit, and where.
 *
 * `--full-history` deliberately: the default history simplification can drop
 * the commit that added a file when later commits made the same content reach
 * the tip another way, and "was it ever added" is exactly the question
 * simplification is entitled to answer with a shrug. `--diff-filter=A` keeps
 * only the commits that added it, `--reverse` puts the oldest first, and the
 * oldest is the latch.
 *
 * @param {{root: string, sourceCommit: string, flagPath?: string}} opts
 * @returns {{armed: boolean, latch_commit: string|null, latch_committed_at: string|null,
 *            armed_at: string|null, flag: object|null, adds: number}}
 */
export function armingState({ root, sourceCommit, flagPath = FLAG_PATH }) {
  const listed = gitMaybe(
    ["log", "--full-history", "--diff-filter=A", "--reverse", "--format=%H %cI", sourceCommit, "--", flagPath],
    { root },
  );
  if (!listed.ok) {
    throw new Error(`could not read the arming history at ${sourceCommit}: ${listed.error}`);
  }
  const lines = listed.out.split("\n").map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) {
    return { armed: false, latch_commit: null, latch_committed_at: null, armed_at: null, flag: null, adds: 0 };
  }
  const [sha, committedAt] = lines[0].split(/\s+/);
  let flag = null;
  const text = blobAt({ root, ref: sha, path: flagPath });
  if (text !== null) {
    try {
      flag = JSON.parse(text);
    } catch {
      // Unparseable is not un-armed. The latch is the commit, not the content:
      // treating a broken flag as "not armed" would hand anybody with commit
      // access a one-byte disarm, and clients in the field do not disarm.
      flag = null;
    }
  }
  return {
    armed: true,
    latch_commit: sha,
    latch_committed_at: committedAt,
    armed_at: typeof flag?.armed_at === "string" ? flag.armed_at : null,
    flag,
    adds: lines.length,
  };
}

/**
 * RC-R1-6's "Arming flag is permanent", as a rule rather than as a promise.
 *
 * `armingState` above reads HISTORY and is deliberately unable to notice the
 * flag being edited or deleted — that is what makes a revert a no-op, which is
 * the honest model of clients that have armed and do not disarm. The cost is
 * that the file itself is unguarded, and this is the guard: **once added it is
 * never modified, never deleted and never re-added, and it holds exactly
 * `schema` and `armed_at`.** There is no R9b exception; when Pages is retired
 * the flag stays as a dated record of the day the field armed.
 *
 * A function rather than four git commands inside a test, so it can be run
 * against a fixture repository and watched failing — the flag does not exist
 * in this repository yet (2026-09-19), and a rule whose only subject is a file
 * that is not there is a rule nobody has seen work.
 *
 * Modifications and deletions are asked for directly instead of "find the add,
 * then look after it", so a change among the commits a clone DID fetch is
 * reported however shallow the clone is.
 *
 * **But a shallow clone can invent a clean answer, and this used to give it.**
 * This paragraph said it could not. The commit at a shallow boundary has no
 * parent, so git reports every file in it as ADDED — including a flag that was
 * really added long before and edited in exactly that commit. A depth-1 clone
 * is nothing but that commit: given a history that adds the flag and then
 * edits it, this returned `problems: []` and the suite printed `ok`, while a
 * full clone of the same history named the editing commit. Measured on
 * 2026-09-22 (gap 75), and again on dac28bc before this changed.
 *
 * So the precondition is asked before the answer is believed. In a shallow
 * checkout the history half comes back as `notAsked` — a sentence saying why
 * — and never as an empty list a caller could read as clean. What IS asked is
 * still reported, the shape half and any change among the fetched commits, so
 * **clean means `problems` is empty AND `notAsked` is null**; a caller that
 * reads only `problems` is making gap 75's mistake again.
 *
 * Shallowness is asked the way `tools/coverage/git.mjs`'s `isShallow` and
 * every other history rule in this repository asks it — `git rev-parse
 * --is-shallow-repository` — but through this directory's `./git.mjs` rather
 * than by importing that module: `./git.mjs` is the one place the signer
 * shells out to git, and `run.mjs` imports this file. Deliberately not a
 * commit count or a floor: a history that is complete and short is a real
 * history, and the environment that produces an incomplete one in this estate
 * is a checkout with a `fetch-depth`.
 *
 * **Where it runs, and why the signer is deliberately not one of the places.**
 * RC-R1-6 makes this a suite row, and the suite is its production caller:
 * `tools/selftest/revocations.mjs` asks it of this repository, and every lane
 * `node tools/selftest.mjs --lanes` reports as LIVE runs that — on a pull
 * request, on the push, and before a publication commits. Which of those can
 * ask the history half depends on its checkout, and the runner derives that
 * as well: it prints the live lanes that reach the suite with the whole
 * history, and fails when there are none.
 *
 * `tools/signer/run.mjs` must not call it (gap 23, decided). What this
 * refuses is HISTORY, and `main` is append-only, so once it is red it is red
 * on every run after it for good — no commit can repair it. In the signer that
 * would stop every later withdrawal list reaching `signed` or Pages, over a
 * record-keeping breach that changes nothing `armingState` decides (it reads
 * the first add, not the file), and seven days on every armed client would
 * block installs. Wiring it there answers the breach with the one outage this
 * estate cannot afford.
 *
 * @param {{root: string, ref?: string, flagPath?: string}} opts
 * @returns {{problems: string[], notAsked: string|null, shallow: boolean, added: string[],
 *            changed: string[], present: boolean}}
 */
export function flagPermanenceProblems({ root, ref = "HEAD", flagPath = FLAG_PATH }) {
  const problems = [];
  const asked = gitMaybe(["rev-parse", "--is-shallow-repository"], { root });
  if (!asked.ok) {
    // Not "false". A precondition that could not be asked is not one that
    // holds, and reading the failure as "not shallow" is the clean answer this
    // exists to stop giving.
    throw new Error(`could not ask whether ${root} is a shallow checkout: ${asked.error}`);
  }
  const shallow = asked.out.trim() === "true";
  const notAsked = shallow
    ? `${root} is a shallow checkout: its oldest fetched commit has no parent, so git reports it as having ` +
      `ADDED every file in it — ${flagPath} included, however that commit had changed it. Whether the flag ` +
      "was ever modified, deleted or re-added cannot be asked of history this checkout does not hold; its " +
      "shape, and any change among the commits that were fetched, were asked"
    : null;
  const log = (filter) => {
    const out = gitMaybe(
      ["log", "--full-history", `--diff-filter=${filter}`, "--format=%H", ref, "--", flagPath],
      { root },
    );
    if (!out.ok) throw new Error(`could not read the history of ${flagPath} at ${ref}: ${out.error}`);
    return out.out.split("\n").map((l) => l.trim()).filter(Boolean);
  };

  const changed = log("MDR");
  const added = log("A");
  if (changed.length) {
    problems.push(
      `${flagPath} was modified, renamed or deleted after it was added, by ${changed.length} commit(s) ` +
      `(${changed.map((s) => s.slice(0, 12)).join(", ")}). It records that clients in the field have armed, and ` +
      "they do not disarm: changing it alters nothing they do and hides what they are doing. There is no R9b " +
      "exception — the flag stays as a dated record when Pages is retired.",
    );
  }
  if (added.length > 1) {
    problems.push(
      `${flagPath} was added ${added.length} times, so it has been deleted and re-added. The latch is the FIRST ` +
      "add, and every reader that takes the newest one now disagrees with every reader that takes the oldest.",
    );
  }

  const file = path.join(root, flagPath);
  const present = fs.existsSync(file);
  if (!present) return { problems, notAsked, shallow, added, changed, present };

  let flag = null;
  try {
    flag = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    problems.push(`${flagPath} is not readable JSON (${e.message}), so nothing can say what it arms`);
    return { problems, notAsked, shallow, added, changed, present };
  }
  const keys = Object.keys(flag).sort();
  if (keys.join(",") !== "armed_at,schema") {
    problems.push(
      `${flagPath} holds [${keys.join(", ")}] and must hold exactly \`schema\` and \`armed_at\`. Anything else in ` +
      "it is a field some reader will eventually branch on, and the latch's whole value is that it says one thing.",
    );
  }
  if (flag.schema !== FLAG_SCHEMA) {
    problems.push(`${flagPath} carries schema ${JSON.stringify(flag.schema)} and no reader here knows it`);
  }
  return { problems, notAsked, shallow, added, changed, present };
}

/**
 * The four `registry/v1/` files Pages serves, as bytes.
 *
 * Three of them are always `signed`'s head. The fourth is the latch:
 *
 *   * armed   → `signed`'s list, signed, which is what arms a 0.2.x client;
 *   * not yet → main's committed unsigned list, exactly as today, so those
 *               clients stay `NotEnforced`.
 *
 * @param {{root: string, head: object, arming: {armed: boolean}, sourceCommit: string}} opts
 */
export function pagesRegistryFiles({ root, head, arming, sourceCommit }) {
  if (!head?.present) {
    throw new Error("Pages serves `signed`'s head and there is no head yet; the publish job runs first (D1)");
  }
  const files = {};
  for (const name of ["index", "trust", "root"]) {
    const bytes = head.bytes[name];
    if (typeof bytes !== "string") {
      throw new Error(`\`signed\`@${String(head.sha).slice(0, 12)} has no ${SIGNED_FILES[name]}`);
    }
    files[SIGNED_FILES[name]] = bytes;
  }

  if (arming.armed) {
    const bytes = head.bytes.revocations;
    if (typeof bytes !== "string") {
      throw new Error(`the latch is closed and \`signed\`@${String(head.sha).slice(0, 12)} has no withdrawal list`);
    }
    files[SIGNED_FILES.revocations] = bytes;
    return { files, list_source: "signed" };
  }

  const unsigned = blobAt({ root, ref: sourceCommit, path: SIGNED_FILES.revocations });
  if (unsigned === null) {
    throw new Error(`the latch is open and main@${sourceCommit.slice(0, 12)} has no ${SIGNED_FILES.revocations}`);
  }
  return { files: { ...files, [SIGNED_FILES.revocations]: unsigned }, list_source: "main" };
}

/**
 * The tree to deploy: the rendered site, with the four documents laid over it.
 *
 * Over, and in that order, because the site build is a NON-FATAL step (D5,
 * MOD-46, ROLL-55): a render failure redeploys the newest `pages-site`
 * artifact, and the documents that go on top of it are this run's. A site that
 * cannot render must never be able to take the catalogue and the withdrawal
 * list down with it, and an assembly that let the site win would do exactly
 * that with a stale `registry/v1/index.json` inside an old artifact.
 *
 * @param {{site?: Record<string,string>, registry: Record<string,string>}} opts
 */
export function pagesTree({ site = {}, registry }) {
  const overwritten = Object.keys(registry).filter((p) => Object.hasOwn(site, p));
  return { tree: { ...site, ...registry }, overwritten };
}
