// Which listings are `grandfathered`, which are `frozen`, and which are simply
// `listed` — decided from git, by contract MIG-1's rule, and by nothing else.
//
// Registry plan M-T5.1. Its consumers are B-T3.3a (`B_UNBOUND`'s scope and
// MIG-1's revoked-binding `frozen`), B-T3.3b (MIG-12's wait) and B-T2.6 (which
// listings the poll reads at all). It is DARK until the first of those lands:
// `bot/lib/identity.mjs`'s `bindingDecision` refuses to decide a binding while
// this module is one of the four things it cannot obtain, and that refusal is
// not this task's to lift — three of the four are still missing.
//
// ── WHY THE ANSWER COMES FROM GIT AND NOT FROM AN ANSWER ────────────────────
//
// BOT-72: the bot decides `grandfathered` and `frozen` ONLY from git. The
// service derives the same states from the same records at the served
// `Source-Commit` (MIG-7), so the two agree because they read one source, not
// because they were written to agree. DEC-11 is the general form: a service
// answer is necessary and never sufficient, and a compromised or merely wrong
// service answering "that listing is grandfathered" must not be able to lift a
// wait the deadline imposes.
//
// ── THE ONE THING GIT CANNOT SAY, AND HOW IT ARRIVES ────────────────────────
//
// MIG-1 has a clause that git cannot answer: a listing with an identity record
// is `frozen` WHILE ITS BINDING IS REVOKED. A revocation writes nothing to this
// repository — `M_BINDING_REVOKE` is no service decision (contract §7.2) — so a
// git-only reader physically cannot produce that `frozen`, and a reader that
// guessed would be a second identity system.
//
// So the git answer and the verdict are two arguments, not one function:
//
//   listingState(tree)            the git answer, pure, no guess
//   listingState(tree, overlay)   the same, plus MIG-1's revoked-binding clause
//
// The overlay is applied ONLY when the run's answer is explicitly not shadow.
// In shadow every verdict is `unknown` (ID-71), and an answer that carries no
// `shadow` member at all is read AS shadow, never as not-shadow — the same
// direction `bot/decide.mjs` takes for BOT-92, and for the same reason: the
// member's absence is a fact about a parser, not a fact about the service.
//
// ── WHAT `unlisted` IS DOING HERE ───────────────────────────────────────────
//
// B.3 lists four listing states and MIG-7 derives three of them: an unlisted id
// is answered `plugin_not_listed` before a state is computed at all, and MIG-30
// keeps unlisted listings out of the poll. So `unlisted` is reported ALONGSIDE
// the state rather than instead of it. Collapsing the two would lose the state
// the caller needs: an unlisted listing whose deadline has passed is `frozen`,
// and ID-25 refuses `B_UNBOUND` a release to a `frozen` listing whether or not
// anybody can see it in the catalogue.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { validate } from "../../tools/lib/jsonschema.mjs";

/** contract B.4's two records: the paths, and the schema strings in them. */
export const DEADLINE_FILE = path.posix.join("policy", "binding-deadline.json");
export const CUTOVER_FILE = path.posix.join("log", "cutover.json");
export const DEADLINE_SCHEMA = "astra.registry.deadline/1";
export const CUTOVER_SCHEMA = "astra.registry.cutover/1";

/**
 * The states this module decides, MIG-1's three. `unlisted` is not among them
 * on purpose — see the header.
 */
export const LISTING_STATES = ["listed", "grandfathered", "frozen"];

/** BOT-72's alert: the deadline has passed and the cutover marker is not on `main`. */
export const DEADLINE_ALERT = "deadline_passed_no_cutover";

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

/** `schema/deadline-v1.json`, read from disk so the file stays the single statement. */
export const deadlineSchema = (root = REPO_ROOT) =>
  readJson(path.join(root, "schema", "deadline-v1.json"));

/** `schema/cutover-v1.json`. */
export const cutoverSchema = (root = REPO_ROOT) =>
  readJson(path.join(root, "schema", "cutover-v1.json"));

/** §0.7: RFC 3339 UTC, whole seconds, ending in `Z`. The schemas say the same. */
const TIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;

/**
 * A §0.7 time as epoch milliseconds, or a refusal.
 *
 * The round-trip is the half the pattern cannot do: `2026-02-31T00:00:00Z`
 * matches the grammar and is not a date, and JavaScript will happily roll it
 * forward to 3 March rather than complain. A deadline that silently moved two
 * days is exactly the class of defect this module exists to keep out of a
 * listing's state, so it is refused here and in `tools/validate.mjs`.
 */
export function parseTime(value, where) {
  if (typeof value !== "string" || !TIME_RE.test(value)) {
    throw new Error(
      `${where} is ${JSON.stringify(value)}, which is not a §0.7 time (RFC 3339 UTC, whole seconds, ending in Z)`,
    );
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z") !== value) {
    throw new Error(`${where} is ${JSON.stringify(value)}, which is not a real moment`);
  }
  return ms;
}

/**
 * Both markers, read from a tree, each validated against its own schema.
 *
 * ABSENT IS A STATE. No deadline file means every listing with no identity
 * record — and none ever — is `grandfathered` and nothing alerts (BOT-72). No
 * cutover marker means cutover has not happened (ROLL-33). Both are the
 * ordinary state today and neither is an error.
 *
 * PRESENT AND MALFORMED IS AN ERROR, and it throws rather than reading as
 * absent. Absent grandfathers everything, which is the direction a typo must
 * not be able to take a run in: a `deadlnie` member or a fractional second
 * would otherwise quietly extend the deadline to never.
 *
 * `schemaRoot` is separate from `root` for the reason `bot/lib/holds.mjs`
 * gives: the tree being read may be a fixture, and the rules it is judged by
 * are always this repository's.
 */
export function readMarkers(root = REPO_ROOT, { schemaRoot = REPO_ROOT } = {}) {
  const one = (file, schemaString, schema, member) => {
    const abs = path.join(root, file);
    if (!fs.existsSync(abs)) return null;
    let doc;
    try {
      doc = readJson(abs);
    } catch (e) {
      throw new Error(`${file} is on main and is not readable JSON — ${e.message}. An unreadable marker is not an absent one.`);
    }
    const problems = validate(schema, doc, "$").map((p) => `${p.path} ${p.message}`);
    if (problems.length) {
      throw new Error(`${file} does not match ${schemaString}: ${problems.join("; ")}`);
    }
    // The half the pattern cannot do, done at READ time so the refusal names
    // the file rather than surfacing later as a tree member nobody can place.
    parseTime(doc[member], `${file}'s \`${member}\``);
    return doc;
  };

  const deadlineDoc = one(DEADLINE_FILE, DEADLINE_SCHEMA, deadlineSchema(schemaRoot), "deadline");
  const cutoverDoc = one(CUTOVER_FILE, CUTOVER_SCHEMA, cutoverSchema(schemaRoot), "cutover_at");
  return {
    deadline: deadlineDoc === null ? null : deadlineDoc.deadline,
    cutover: cutoverDoc === null ? null : cutoverDoc.cutover_at,
  };
}

/**
 * The two git reads this module makes, behind one function, so a test can hand
 * it a fixture repository and so nothing here composes a shell string — the
 * plugin id reaches this file from a stranger's release.
 */
export function historyReader(root) {
  const git = (args, allowFail = false) => {
    try {
      return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }).replace(/\n$/, "");
    } catch (e) {
      if (allowFail) return null;
      throw new Error(`git ${args.join(" ")}: ${String(e.stderr ?? e.message).trim().split("\n")[0]}`);
    }
  };
  return {
    /**
     * True when this checkout cannot answer a question about history.
     *
     * `actions/checkout` clones at depth 1 by default, and under such a
     * checkout `git log -- <path>` for a DELETED file returns nothing — which
     * is indistinguishable from "this listing never had an identity record".
     * That is ID-25's exact failure: a listing whose record B-T4.2's reset
     * deleted would read `grandfathered` again, and `B_UNBOUND` would stop
     * applying to it. So the reader refuses instead of answering, and the job
     * that meets this refusal needs `fetch-depth: 0`.
     */
    shallow() {
      return git(["rev-parse", "--is-shallow-repository"], true) === "true";
    },
    /** Every commit that ever touched a path, newest first; empty when none ever did. */
    touching(file) {
      const out = git(["log", "--format=%H", "--", file], true);
      return (out ?? "").split("\n").filter(Boolean);
    },
    head() {
      return git(["rev-parse", "HEAD"], true);
    },
  };
}

/**
 * Everything `listingState` needs about one listing, read from a tree and its
 * history. I/O lives here; the decision below is pure.
 *
 * ID-25's "EVER" IS A HISTORY QUESTION. "A listing that ever had an identity
 * record is never `grandfathered` again" cannot be answered from the current
 * tree: B-T4.2's reset DELETES `plugins/<id>/identity.json`, and a reader that
 * looked only at the tree would re-grandfather exactly the listing a moderator
 * had just reset. So when the record is absent the reader walks
 * `git log -- plugins/<id>/identity.json`, and when it is present it skips the
 * walk, because present already settles "ever".
 */
export function readListingTree(root, pluginId, { now, git = historyReader(root), schemaRoot = REPO_ROOT, markers } = {}) {
  if (typeof pluginId !== "string" || pluginId === "" || pluginId.includes("/") || pluginId.includes("..")) {
    throw new Error(`${JSON.stringify(pluginId)} is not a plugin id this reader will build a path out of`);
  }
  const m = markers ?? readMarkers(root, { schemaRoot });
  const listingFile = path.join(root, "plugins", pluginId, "plugin.json");
  if (!fs.existsSync(listingFile)) {
    throw new Error(`plugins/${pluginId}/plugin.json is not in this tree, so there is no listing to have a state`);
  }
  const listing = readJson(listingFile);

  const identityRel = `plugins/${pluginId}/identity.json`;
  const identityFile = path.join(root, "plugins", pluginId, "identity.json");
  let identity = null;
  if (fs.existsSync(identityFile)) {
    try {
      identity = readJson(identityFile);
    } catch (e) {
      // The same direction `bot/decide.mjs` takes: an unreadable binding is not
      // an absent one, and reading it as absent would grandfather a bound
      // listing.
      throw new Error(`${identityRel} is on main and could not be read — ${e.message}`);
    }
  }

  let everIdentity = identity !== null;
  if (!everIdentity) {
    if (git.head() === null) {
      throw new Error(
        `${root} has no commit, so ID-25's "ever had an identity record" cannot be answered. This reader ` +
        "walks history and will not answer from the working tree alone.",
      );
    }
    if (git.shallow()) {
      throw new Error(
        `${root} is a shallow checkout, so \`git log -- ${identityRel}\` cannot say whether this listing ever ` +
        "had an identity record. A reset listing would read `grandfathered` again and `B_UNBOUND` would stop " +
        "applying to it (ID-25). The job that reads listing state needs `fetch-depth: 0`.",
      );
    }
    everIdentity = git.touching(identityRel).length > 0;
  }

  return {
    plugin_id: pluginId,
    now,
    unlisted: listing?.unlisted === true,
    identity,
    ever_identity: everIdentity,
    deadline: m.deadline,
    cutover: m.cutover,
  };
}

/** Every member `listingState` reads, and what it may be. */
const TREE_MEMBERS = {
  plugin_id: (v) => typeof v === "string" && v.length > 0,
  now: (v) => typeof v === "string" && TIME_RE.test(v),
  unlisted: (v) => typeof v === "boolean",
  identity: (v) => v === null || (typeof v === "object" && !Array.isArray(v)),
  ever_identity: (v) => typeof v === "boolean",
  deadline: (v) => v === null || (typeof v === "string" && TIME_RE.test(v)),
  cutover: (v) => v === null || (typeof v === "string" && TIME_RE.test(v)),
};

/**
 * MIG-1, decided. Pure: no clock, no filesystem, no network, no service.
 *
 * EVERY MEMBER IS REQUIRED, INCLUDING THE FALSE ONES. A tree missing
 * `ever_identity` would be falsy and would read `grandfathered` — the unsafe
 * direction, and the one a caller assembling a tree by hand gets wrong. So an
 * absent member is a refusal and never a default.
 *
 * @param {object} tree from `readListingTree`
 * @param {{shadow?: boolean, token_states?: Record<string,string>}} [overlay]
 *   this run's verdicts, keyed by `token_hash`. Omit it and the answer is the
 *   git answer.
 */
export function listingState(tree, overlay) {
  if (tree === null || typeof tree !== "object" || Array.isArray(tree)) {
    throw new Error("listingState needs a tree object from readListingTree");
  }
  for (const [member, grammar] of Object.entries(TREE_MEMBERS)) {
    if (!(member in tree)) {
      throw new Error(
        `the tree is missing ${JSON.stringify(member)}. Every member is required, because a missing one would ` +
        "be read as its falsy value and MIG-1's answer would be a guess.",
      );
    }
    if (!grammar(tree[member])) {
      throw new Error(`the tree's ${member} is ${JSON.stringify(tree[member])}, which is not the thing it claims to be`);
    }
  }

  const now = parseTime(tree.now, "the tree's `now`");
  const base = {
    plugin_id: tree.plugin_id,
    unlisted: tree.unlisted,
    bound: tree.identity !== null,
    ever_bound: tree.ever_identity,
    deadline: tree.deadline,
    cutover: tree.cutover,
    decided_by: "git",
    alert: null,
  };

  // 1. A listing with an identity record. Never `grandfathered` again (ID-25),
  //    and `frozen` only while its binding is revoked — which git cannot see.
  if (tree.identity !== null) {
    const applied = applicableVerdict(tree.identity, overlay);
    if (applied.state === "revoked") {
      return {
        ...base,
        state: "frozen",
        decided_by: "git+verdict",
        why:
          `this listing has an identity record and this run's verdict for its recorded token_hash is \`revoked\`, ` +
          "so MIG-1 freezes it. A revocation writes nothing to git; the verdict is the only way to see it",
      };
    }
    return {
      ...base,
      state: "listed",
      why:
        "this listing has an identity record, so it is bound and never `grandfathered` again (ID-25)" +
        (applied.why ? `; ${applied.why}` : ""),
    };
  }

  // 2. A listing that HAD one and has none now: B-T4.2's reset deleted it.
  //    ID-25's "ever" makes it `frozen`, not `grandfathered`.
  if (tree.ever_identity) {
    return {
      ...base,
      state: "frozen",
      why:
        "`git log` shows this listing once had an identity record, and a listing that ever had one is never " +
        "`grandfathered` again (ID-25, MIG-1). A reset deletes the record; it does not restore grandfathering",
    };
  }

  // 3. A listing with no identity record and none ever: the deadline decides,
  //    and only together with the cutover marker (MIG-1 takes the LATER).
  if (tree.deadline === null) {
    return {
      ...base,
      state: "grandfathered",
      why: `there is no ${DEADLINE_FILE}, so no deadline has passed and nothing alerts (BOT-72, MIG-2)`,
    };
  }
  const deadline = parseTime(tree.deadline, DEADLINE_FILE);
  if (now < deadline) {
    return { ...base, state: "grandfathered", why: `the deadline ${tree.deadline} has not passed` };
  }
  if (tree.cutover === null) {
    // BOT-72, exactly: before the marker is on `main` a past deadline alerts
    // and FREEZES NOTHING. Freezing here would strand authors while the issue
    // channel still lives (MIG-1's Why).
    return {
      ...base,
      state: "grandfathered",
      why: `the deadline ${tree.deadline} has passed and ${CUTOVER_FILE} is not on main, so nothing freezes (BOT-72)`,
      alert: {
        kind: DEADLINE_ALERT,
        deadline: tree.deadline,
        now: tree.now,
        message:
          `the binding deadline ${tree.deadline} has passed and ${CUTOVER_FILE} is not on main. Listings stay ` +
          "`grandfathered` until it is (MIG-1, BOT-72); operators decide (MIG-29)",
      },
    };
  }
  const cutover = parseTime(tree.cutover, CUTOVER_FILE);
  if (now < cutover) {
    return {
      ...base,
      state: "grandfathered",
      why: `the deadline ${tree.deadline} has passed but cutover ${tree.cutover} has not, and MIG-1 takes the later of the two`,
    };
  }
  return {
    ...base,
    state: "frozen",
    why: `both the deadline ${tree.deadline} and cutover ${tree.cutover} have passed and this listing has no identity record (MIG-1)`,
  };
}

/**
 * What this run's answer says about the token the identity record names.
 *
 * Three ways to get nothing, and all three mean "the git answer stands":
 * no overlay at all (the caller has no verdict), an overlay that is not
 * explicitly `shadow: false`, and an overlay with no state for THIS token hash.
 *
 * THE SHADOW DEFAULT IS THE STRICT ONE. `shadow !== false` rather than
 * `shadow === true`: an answer whose `shadow` member did not survive a parser
 * is read as shadow, never as not-shadow (BOT-92, ID-71), which is the same
 * direction `bot/decide.mjs` takes on the same member. In shadow every verdict
 * is `unknown` anyway, so an overlay that claims `revoked` there is describing
 * something the service is not allowed to have said.
 */
function applicableVerdict(identity, overlay) {
  if (overlay === undefined || overlay === null) return { state: null, why: "" };
  if (typeof overlay !== "object" || Array.isArray(overlay)) {
    throw new Error("the overlay is not an object of {shadow, token_states}");
  }
  if (overlay.shadow !== false) {
    return {
      state: null,
      why: "this run's answer is shadow (or does not say it is not), so no verdict is applied and the git answer stands (ID-71)",
    };
  }
  const states = overlay.token_states ?? {};
  if (typeof states !== "object" || Array.isArray(states)) {
    throw new Error("the overlay's `token_states` is not an object keyed by token_hash");
  }
  const hash = identity.token_hash;
  if (typeof hash !== "string" || hash === "") {
    throw new Error(
      "this identity record carries no `token_hash`, so no verdict can be matched to it. " +
      "`astra.registry.identity/1` requires the member (contract B.4)",
    );
  }
  const state = states[hash];
  if (state === undefined) {
    return { state: null, why: "this run has no verdict for the recorded token_hash, so the git answer stands" };
  }
  if (typeof state !== "string") {
    throw new Error(`the overlay's state for ${hash} is ${JSON.stringify(state)}, which is not a token state`);
  }
  return { state, why: `this run's verdict for the recorded token_hash is \`${state}\`` };
}

/**
 * The convenience the callers actually want: one listing, from a tree on disk.
 *
 * `markers` is passed in by a caller reading many listings, so a run that walks
 * the catalogue parses the two records once and cannot read a different
 * deadline halfway through.
 */
export function listingStateAt(root, pluginId, { now, overlay, git, schemaRoot, markers } = {}) {
  return listingState(readListingTree(root, pluginId, { now, git, schemaRoot, markers }), overlay);
}
