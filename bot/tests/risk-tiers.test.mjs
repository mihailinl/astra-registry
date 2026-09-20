#!/usr/bin/env node
// The two risk tiers, compared against the crate that defines them.
// `node --test bot/tests/risk-tiers.test.mjs`   (registry plan B-T1.7, BOT-78)
//
// `bot/lib/policy/constants.mjs` declares two lists of permission names:
//
//   HIGH_RISK          four names whose FIRST APPEARANCE in a release stops the
//                      publication and asks a person (`R_NEW_HIGH_RISK`), and
//                      whose presence at all earns the publication delay
//                      (`P_DELAY_HIGH_RISK`);
//   CONSENT_HIGH_RISK  the five the Phase 4 consent sheet gives a checkbox to.
//
// Neither is this repository's decision. PRODUCTION_PLAN §5.5 names the four
// refused outright to a Tier-2 import and §5.6 names the five that each get a
// checkbox, and the place those two readings are written as code is the
// manifest crate the DAEMON parses `plugin.toml` with —
// `TIER2_REFUSED_PERMISSIONS` and `HIGH_RISK_PERMISSIONS` in
// `astra-plugin-cli/vendor/astra-plugin-manifest/src/permissions.rs`. Until
// this file existed, the two repositories agreed by hand: four names typed
// here, four `Permission::` variants typed there, and nothing anywhere
// comparing them.
//
// ── what the disagreement looks like from outside, which is the point ───────
//
// It looks like nothing. Both halves are green on their own the whole time:
//
//   * a permission the crate refuses at Tier 2 and this list omits is a release
//     that sails through ingest and auto-publishes — no review, no delay, no
//     checkbox — for an authority the daemon considers serious enough to refuse
//     an imported file outright;
//   * a permission in this list and not the crate's is the opposite failure and
//     is just as quiet: every release asking for it is held for a person, for a
//     tier the daemon does not think is high-risk at all, and the author is
//     told in `R_NEW_HIGH_RISK`'s own words that it "reaches outside the
//     plugin's own surface" when it does not.
//
// Nobody gets an error either way. One side is a Rust `const`, the other a JS
// array, and the only reader that meets both is a person reading two files in
// two repositories.
//
// ── why this reads git objects and not the checkout's working tree ──────────
//
// The crate is read AT `bot/manifest-probe/astra-plugins.pin`'s
// `ASTRA_PLUGINS_REF`, through `git cat-file`, never off the checkout's disk.
// The pin is the commit whose manifest rules this bot judges a stranger's
// listing by, and the checkout is a build artifact: in CI `link-deps.sh
// --clone` leaves it at the pin, on a workstation it is a sibling working copy
// at whatever branch somebody was last on, possibly dirty. Reading the working
// tree would answer a different question on every machine — and this
// repository has already shipped one floor measured against build output,
// which was right on a workstation and red in CI on the commit that added it.
// A `git cat-file` of a 40-hex commit gives the same bytes everywhere, so the
// floors below are numbers about tracked content rather than about a directory
// that happened to be lying around.
//
// ── three vocabularies, kept apart on purpose ───────────────────────────────
//
//   COULD NOT ASK   the comparison did not run: no checkout, no such commit,
//                   an unparseable pin, a constant that has been renamed. The
//                   test FAILS. An empty scan is never a clean bill of health,
//                   and a skipped cross-repository check that reads as a pass
//                   is the exact failure `couplings.md` opens with.
//   BROKEN SCAN     the reader parsed, but found fewer names than the floor.
//                   Also a failure, and said differently, because the fix is
//                   to the reader and not to either list.
//   RISK TIERS      the comparison ran and the two sides disagree. This is the
//     DIFFER        only outcome that is about the tiers themselves, and the
//                   only one whose fix is a policy decision.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { CONSENT_HIGH_RISK, HIGH_RISK } from "../lib/policy.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const PIN_REL = "bot/manifest-probe/astra-plugins.pin";
const CRATE_REL = "astra-plugin-cli/vendor/astra-plugin-manifest/src/permissions.rs";

/**
 * The floors, measured on 2026-09-20 against AstraPlugins `bc51241` — the
 * commit the pin named that day — and written here BEFORE any mutation.
 *
 * Every one of these counts a set this check enumerates, and every one of them
 * is the difference between "the lists agree" and "the reader found nothing
 * twice and compared two empty sets". They are floors and not equalities on
 * purpose: a sixth high-risk permission is an ordinary upstream act and must
 * not need a commit here to stay green, while losing one must not be silent.
 * The two exact counts the plan states — 4 and 5 — are asserted as the
 * comparison itself, against the bot's own lists, which is where they belong.
 */
const FLOOR = {
  permissionNames: 8, // PERMISSION_NAMES, the whole vocabulary
  wireIds: 8, // arms of `Permission::id()`
  tier2: 4, // TIER2_REFUSED_PERMISSIONS
  highRisk: 5, // HIGH_RISK_PERMISSIONS
  botHighRisk: 4, // this repository's HIGH_RISK
  botConsent: 5, // this repository's CONSENT_HIGH_RISK
};

/** The comparison could not be made. Never a pass, never a skip. */
class CouldNotAsk extends Error {
  constructor(message) {
    super(`COULD NOT ASK — ${message}`);
    this.name = "CouldNotAsk";
  }
}

// ── reading the crate at the pinned commit ──────────────────────────────────

/**
 * The commit this bot judges manifests by.
 *
 * Exactly one uncommented `ASTRA_PLUGINS_REF=` line, matched the way
 * `bot-tests.yml` and `build-index.yml` match it. Two would be ambiguous and a
 * reader that silently took the first is a reader that can be pointed at an old
 * commit by an edit nobody reviews as a pin change.
 */
export function readPinnedRef(text) {
  const hits = [...text.matchAll(/^ASTRA_PLUGINS_REF=(\S*)\s*$/gm)].map((m) => m[1]);
  if (hits.length === 0) {
    throw new CouldNotAsk(
      `${PIN_REL} has no ASTRA_PLUGINS_REF line. It is the only place that value is written (B-T1.4), so ` +
      "this comparison has no commit to make and cannot fall back to master — reading the crate at master is a " +
      "different question with a different answer, which is what the pin is for.",
    );
  }
  if (hits.length > 1) {
    throw new CouldNotAsk(
      `${PIN_REL} has ${hits.length} ASTRA_PLUGINS_REF lines (${hits.join(", ")}). Which commit this bot judges ` +
      "manifests by has to be one answer; delete the one that is not the pin.",
    );
  }
  if (!/^[0-9a-f]{40}$/.test(hits[0])) {
    throw new CouldNotAsk(
      `ASTRA_PLUGINS_REF in ${PIN_REL} is ${JSON.stringify(hits[0])}, which is not a 40-hex commit. A branch name ` +
      "is a pin somebody can force-push out from under this repository.",
    );
  }
  return hits[0];
}

function git(dir, args) {
  return execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/**
 * Where an AstraPlugins checkout might be, best first.
 *
 * The same three places `bot/manifest-probe/link-deps.sh` looks, in the same
 * order, so that the checkout this reads and the checkout the probe was built
 * from cannot be two different directories.
 */
function candidateDirs() {
  return [
    process.env.ASTRA_PLUGINS_DIR,
    path.join(REPO, "bot", "manifest-probe", "_deps", "AstraPlugins"),
    path.resolve(REPO, "..", "AstraPlugins"),
  ].filter(Boolean);
}

/**
 * `permissions.rs` as it stands at the pinned commit, with every place that was
 * tried and why it did not answer.
 */
function crateSourceAtPin(ref, dirs) {
  const tried = [];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) {
      tried.push(`${dir}: no such directory`);
      continue;
    }
    let top;
    try {
      top = git(dir, ["rev-parse", "--show-toplevel"]).trim();
    } catch (e) {
      tried.push(`${dir}: not inside a git repository (${String(e.stderr || e.message).trim()})`);
      continue;
    }
    if (path.resolve(top) === path.resolve(REPO)) {
      // A mis-set ASTRA_PLUGINS_DIR pointing at a path inside THIS repository
      // resolves to this repository, where the pinned commit does not exist.
      // Said plainly here, because "unknown revision" would send the reader to
      // AstraPlugins to look for a commit that is sitting in front of them.
      tried.push(`${dir}: resolves to this repository (${top}), not to an AstraPlugins checkout`);
      continue;
    }
    try {
      git(dir, ["cat-file", "-e", `${ref}^{commit}`]);
    } catch {
      tried.push(
        `${top}: has no commit ${ref} — fetch it (\`git -C ${top} fetch origin\`) or the pin names a commit on ` +
        "no reachable ref",
      );
      continue;
    }
    try {
      return { text: git(dir, ["cat-file", "-p", `${ref}:${CRATE_REL}`]), from: top };
    } catch (e) {
      tried.push(
        `${top}: ${ref} has no ${CRATE_REL} (${String(e.stderr || e.message).trim()}) — the crate moved, and this ` +
        "reader's path is stale",
      );
    }
  }
  throw new CouldNotAsk(
    `no AstraPlugins checkout could answer for ${ref}. Tried, in order:\n` +
    tried.map((t) => `    ${t}`).join("\n") +
    "\n  Set ASTRA_PLUGINS_DIR to a checkout that has the pinned commit, or run " +
    "`bot/manifest-probe/link-deps.sh --clone` with ASTRA_PLUGINS_REF set. This is NOT a pass: the bot's high-risk " +
    "tiers and the daemon's have not been compared by this run.",
  );
}

// ── parsing the crate ───────────────────────────────────────────────────────

/**
 * `//` comments out of a slice of Rust.
 *
 * Only ever applied to the inside of a `&[ … ]` literal, which holds wire ids
 * and `Permission::` paths and no string containing a slash. A doc comment
 * naming a variant it does not list would otherwise be counted as a member,
 * which is the failure mode that makes this side look bigger than it is.
 */
function stripLineComments(slice) {
  return slice.replace(/\/\/[^\n]*/g, "");
}

/** The body of `pub const <name>: &[…] = &[ … ];`. */
export function constBody(src, name) {
  const re = new RegExp(String.raw`pub const ${name}\s*:\s*&\[[^\]]*\]\s*=\s*&\[([\s\S]*?)\]\s*;`);
  const m = re.exec(src);
  if (!m) {
    throw new CouldNotAsk(
      `${CRATE_REL} has no \`pub const ${name}\`. Either it was renamed upstream — in which case this reader is ` +
      "looking for a constant that no longer exists and has to be repointed in the same commit that bumps the " +
      `pin — or the shape of the declaration changed. A reader that answered "${name} is empty" here would report ` +
      "the bot's list as wrong when nothing is wrong with it.",
    );
  }
  return stripLineComments(m[1]);
}

/** Every `Permission::Variant` named in a slice, in order, deduplicated. */
export function variantsIn(body) {
  return [...new Set([...body.matchAll(/Permission::(\w+)/g)].map((m) => m[1]))];
}

/** Every string literal in a slice, in order. */
export function stringsIn(body) {
  return [...body.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
}

/**
 * Variant → wire id, read out of `Permission::id()` itself.
 *
 * The mapping is not guessed at from the variant name. `SendChatMessage` →
 * `send_chat_message` is a convention, not a rule, and a comparison that
 * snake-cased the enum would be comparing this reader's spelling habits with
 * this repository's list rather than the crate's own answer.
 */
export function wireIds(src) {
  const at = src.indexOf("pub fn id(self)");
  if (at < 0) {
    throw new CouldNotAsk(
      `${CRATE_REL} has no \`pub fn id(self)\`, which is where the wire spelling of each variant is decided. ` +
      "Without it the two risk lists are lists of Rust identifiers and this repository's are lists of manifest " +
      "keys, and nothing can compare them.",
    );
  }
  const open = src.indexOf("{", at);
  let depth = 0;
  let end = -1;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth += 1;
    else if (src[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end < 0) throw new CouldNotAsk(`\`pub fn id(self)\` in ${CRATE_REL} does not close; this reader cannot bound it`);
  const map = new Map();
  for (const m of src.slice(open, end).matchAll(/Permission::(\w+)\s*=>\s*"([^"]*)"/g)) map.set(m[1], m[2]);
  return map;
}

/** The whole other side, parsed once. Every test asks for it; none swallows it. */
let cached;
function crate() {
  if (cached === undefined) {
    try {
      const ref = readPinnedRef(fs.readFileSync(path.join(REPO, PIN_REL), "utf8"));
      const { text, from } = crateSourceAtPin(ref, candidateDirs());
      const ids = wireIds(text);
      cached = {
        ok: true,
        ref,
        from,
        ids,
        names: stringsIn(constBody(text, "PERMISSION_NAMES")),
        tier2: variantsIn(constBody(text, "TIER2_REFUSED_PERMISSIONS")),
        highRisk: variantsIn(constBody(text, "HIGH_RISK_PERMISSIONS")),
      };
    } catch (e) {
      cached = { ok: false, error: e };
    }
  }
  if (!cached.ok) throw cached.error;
  return cached;
}

/** Variants to the manifest keys this repository writes its lists in. */
function asWireIds(variants, ids, constName, ref) {
  const missing = variants.filter((v) => !ids.has(v));
  if (missing.length) {
    throw new CouldNotAsk(
      `BROKEN SCAN at ${ref}: ${constName} names ${missing.map((v) => `Permission::${v}`).join(", ")}, for which ` +
      "`Permission::id()` has no arm. Either the enum and its id table have drifted upstream — a real defect, but " +
      "not this one — or this reader's arm pattern no longer matches. Comparing the rest would be comparing a " +
      "shorter list than the crate actually declares.",
    );
  }
  return variants.map((v) => ids.get(v)).sort();
}

function differences(ours, theirs) {
  const a = new Set(ours);
  const b = new Set(theirs);
  return {
    onlyOurs: [...a].filter((x) => !b.has(x)).sort(),
    onlyTheirs: [...b].filter((x) => !a.has(x)).sort(),
  };
}

// ── the reader proves it can fail, before it is believed about anything ─────
//
// These four run against strings, not against the crate, and they exist because
// every assertion below this point is only as good as the parse above it. A
// reader that returns an empty list for a renamed constant makes two empty sets
// equal, and the suite goes green over a comparison it did not make.

test("a renamed constant is COULD NOT ASK, not an empty list", () => {
  const src = 'pub const TIER2_REFUSED: &[Permission] = &[\n    Permission::Client,\n];\n';
  assert.throws(() => constBody(src, "TIER2_REFUSED_PERMISSIONS"), (e) => {
    assert.equal(e.name, "CouldNotAsk");
    assert.match(e.message, /TIER2_REFUSED_PERMISSIONS/);
    return true;
  });
});

test("a comment inside the list is not a member of it", () => {
  const src =
    'pub const HIGH_RISK_PERMISSIONS: &[Permission] = &[\n' +
    '    // Permission::FireTrigger was here until 2026-01-01.\n' +
    '    Permission::Client,\n];\n';
  assert.deepEqual(variantsIn(constBody(src, "HIGH_RISK_PERMISSIONS")), ["Client"]);
});

test("a variant with no id() arm is COULD NOT ASK, not a silently shorter list", () => {
  const src =
    'pub const TIER2_REFUSED_PERMISSIONS: &[Permission] = &[\n    Permission::Client,\n    Permission::Novel,\n];\n' +
    'impl Permission {\n    pub fn id(self) -> &\'static str {\n        match self {\n' +
    '            Permission::Client => "client",\n        }\n    }\n}\n';
  const ids = wireIds(src);
  assert.throws(
    () => asWireIds(variantsIn(constBody(src, "TIER2_REFUSED_PERMISSIONS")), ids, "TIER2_REFUSED_PERMISSIONS", "test"),
    /Permission::Novel/,
  );
});

test("the wire id comes from id(), not from snake-casing the variant", () => {
  const src =
    'impl Permission {\n    pub fn id(self) -> &\'static str {\n        match self {\n' +
    '            Permission::DomAccess => "dom_access_v2",\n        }\n    }\n}\n';
  assert.equal(wireIds(src).get("DomAccess"), "dom_access_v2");
});

// ── the floors, asserted before anything is compared ────────────────────────

test("the crate at the pin is reachable, and parses to more than nothing", () => {
  const c = crate();

  assert.ok(
    c.names.length >= FLOOR.permissionNames,
    `BROKEN SCAN: PERMISSION_NAMES at ${c.ref} parsed as ${c.names.length} name(s) and there were ` +
    `${FLOOR.permissionNames} on 2026-09-20. Either the vocabulary shrank upstream — which is a manifest key ` +
    "somebody's published plugin may still declare — or this reader is parsing the wrong thing.",
  );
  assert.ok(
    c.ids.size >= FLOOR.wireIds,
    `BROKEN SCAN: \`Permission::id()\` at ${c.ref} parsed as ${c.ids.size} arm(s) and there were ${FLOOR.wireIds} ` +
    "on 2026-09-20",
  );
  assert.ok(
    c.tier2.length >= FLOOR.tier2,
    `BROKEN SCAN: TIER2_REFUSED_PERMISSIONS at ${c.ref} parsed as ${c.tier2.length} name(s) and there were ` +
    `${FLOOR.tier2} on 2026-09-20. §5.5 names four refused outright to a Tier-2 import; a shorter list here is ` +
    "either a real loosening upstream or a reader that stopped finding members.",
  );
  assert.ok(
    c.highRisk.length >= FLOOR.highRisk,
    `BROKEN SCAN: HIGH_RISK_PERMISSIONS at ${c.ref} parsed as ${c.highRisk.length} name(s) and there were ` +
    `${FLOOR.highRisk} on 2026-09-20`,
  );

  // The crate's own two lists are subsets of its own vocabulary. If they are
  // not, the three constants were not parsed out of the same file, or one of
  // them was — and this is the case that has actually happened elsewhere in
  // this estate — parsed out of a doc comment above the real one.
  const vocabulary = new Set(c.names);
  const strays = [...new Set([...c.tier2, ...c.highRisk])]
    .map((v) => c.ids.get(v))
    .filter((id) => id !== undefined && !vocabulary.has(id));
  assert.deepEqual(
    strays,
    [],
    `BROKEN SCAN: ${strays.join(", ")} is in a risk list at ${c.ref} but not in PERMISSION_NAMES; this reader has ` +
    "parsed two different files, or one of these constants is not the one it looks like",
  );
});

test("this repository's own two lists are not empty either", () => {
  // Asserted separately from the comparison, because two empty lists compare
  // equal. The bot's side needs no checkout and no pin, so when this is the
  // assertion that fails the reader is looking at one file, not two.
  assert.ok(
    HIGH_RISK.length >= FLOOR.botHighRisk,
    `BROKEN SCAN: bot/lib/policy/constants.mjs HIGH_RISK holds ${HIGH_RISK.length} name(s) and held ` +
    `${FLOOR.botHighRisk} on 2026-09-20. Every one of them is a release that stops and asks a person; losing one ` +
    "is a release that stops asking.",
  );
  assert.ok(
    CONSENT_HIGH_RISK.length >= FLOOR.botConsent,
    `BROKEN SCAN: CONSENT_HIGH_RISK holds ${CONSENT_HIGH_RISK.length} name(s) and held ${FLOOR.botConsent} on ` +
    "2026-09-20",
  );
});

// ── the comparison ──────────────────────────────────────────────────────────

/**
 * The sentence both messages end with.
 *
 * `couplings.md`'s second rule for a canary: the failure names the fix. The fix
 * here is deliberately not "make them match" — which of the two lists is wrong
 * is a policy decision with the owner's name on it, and the obvious wrong fix
 * (widen or narrow this repository's array until the test is green) is one
 * keystroke away and silently changes what a stranger's release is held for.
 */
const HOW_TO_FIX =
  "Decide which side is right in PRODUCTION_PLAN's own terms — §5.5 for the Tier-2 refusals, §5.6 for the consent " +
  "sheet — and change that side. If the crate is the side that moved, the pin moves in its own commit before this " +
  "one (ROLL-2), and docs/POLICY.md's R_NEW_HIGH_RISK text names the four out loud, so it moves too. Editing " +
  "bot/lib/policy/constants.mjs to silence this test is a change to what the registry holds for a person, made " +
  "without anybody deciding it.";

test("the bot's HIGH_RISK is the crate's TIER2_REFUSED_PERMISSIONS, name for name", () => {
  const c = crate();
  const theirs = asWireIds(c.tier2, c.ids, "TIER2_REFUSED_PERMISSIONS", c.ref);
  const { onlyOurs, onlyTheirs } = differences(HIGH_RISK, theirs);
  assert.deepEqual(
    { onlyOurs, onlyTheirs },
    { onlyOurs: [], onlyTheirs: [] },
    `RISK TIERS DIFFER — measured at ${c.ref} (read from ${c.from}).\n` +
    `  bot HIGH_RISK:                  [${[...HIGH_RISK].sort().join(", ")}]\n` +
    `  TIER2_REFUSED_PERMISSIONS:      [${theirs.join(", ")}]\n` +
    (onlyOurs.length
      ? `  held for a person here and NOT refused at Tier 2 upstream: ${onlyOurs.join(", ")} — every release asking ` +
        "for it waits for a maintainer, for an authority the daemon does not treat as high-risk.\n"
      : "") +
    (onlyTheirs.length
      ? `  refused outright to a Tier-2 import upstream and NOT high-risk here: ${onlyTheirs.join(", ")} — a ` +
        "release asking for it auto-publishes with no review, no delay and no notice.\n"
      : "") +
    `  ${HOW_TO_FIX}`,
  );
});

test("the bot's CONSENT_HIGH_RISK is the crate's HIGH_RISK_PERMISSIONS, name for name", () => {
  const c = crate();
  const theirs = asWireIds(c.highRisk, c.ids, "HIGH_RISK_PERMISSIONS", c.ref);
  const { onlyOurs, onlyTheirs } = differences(CONSENT_HIGH_RISK, theirs);
  assert.deepEqual(
    { onlyOurs, onlyTheirs },
    { onlyOurs: [], onlyTheirs: [] },
    `RISK TIERS DIFFER — measured at ${c.ref} (read from ${c.from}).\n` +
    `  bot CONSENT_HIGH_RISK:          [${[...CONSENT_HIGH_RISK].sort().join(", ")}]\n` +
    `  HIGH_RISK_PERMISSIONS:          [${theirs.join(", ")}]\n` +
    (onlyOurs.length
      ? `  gets a consent checkbox here and not upstream: ${onlyOurs.join(", ")}\n`
      : "") +
    (onlyTheirs.length
      ? `  gets its own consent checkbox upstream and none here: ${onlyTheirs.join(", ")} — the user is asked to ` +
        "install a plugin without being told it holds an authority §5.6 says is worth a checkbox.\n"
      : "") +
    `  ${HOW_TO_FIX}`,
  );
});

test("the two tiers differ by push_to_ui, and by nothing else", () => {
  // The difference between the lists is the whole reason there are two of them,
  // and both repositories say so in prose: §5.5 refuses four outright, §5.6
  // gives five a checkbox, and `push_to_ui` is the one that is worth a click
  // and not worth refusing a file the user chose to import. The two tests above
  // would both stay green if the two pairs were collapsed into one list on both
  // sides at once — which is exactly the tidying the crate's own
  // `the_two_risk_lists_are_deliberately_different` was written to stop, and
  // there was nothing holding it on this side.
  const c = crate();
  const consentOnly = differences(CONSENT_HIGH_RISK, HIGH_RISK).onlyOurs;
  assert.deepEqual(
    consentOnly,
    ["push_to_ui"],
    `CONSENT_HIGH_RISK minus HIGH_RISK is [${consentOnly.join(", ")}] and it is supposed to be exactly ` +
    "[push_to_ui]. §5.6 gives push_to_ui a checkbox; §5.5 does not refuse it to a Tier-2 import. Collapsing the " +
    "two lists into one either silently refuses an imported plugin that draws in its own panel, or silently drops " +
    "a consent checkbox — and a version of this suite that only compared each list to its counterpart would stay " +
    "green while both sides were tidied together.",
  );
  const theirConsentOnly = differences(
    asWireIds(c.highRisk, c.ids, "HIGH_RISK_PERMISSIONS", c.ref),
    asWireIds(c.tier2, c.ids, "TIER2_REFUSED_PERMISSIONS", c.ref),
  ).onlyOurs;
  assert.deepEqual(
    theirConsentOnly,
    ["push_to_ui"],
    `HIGH_RISK_PERMISSIONS minus TIER2_REFUSED_PERMISSIONS at ${c.ref} is [${theirConsentOnly.join(", ")}] and was ` +
    "[push_to_ui] on 2026-09-20. The crate's own tests hold this too; if it went red there first, the pin is what " +
    "moves.",
  );
});
