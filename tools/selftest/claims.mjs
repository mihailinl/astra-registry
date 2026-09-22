// Every claim this repository makes about a reader in ANOTHER repository,
// carrying the literal search that finds it.
//
// ── what this is for ───────────────────────────────────────────────────────
//
// On 2026-09-19 two estates produced the same defect five times in one day: a
// sentence in the present tense about a component in another repository, which
// was not true. The signed-set corpus "vendored into
// `astra-daemon/testdata/signed-set-vectors/`" — that directory does not exist.
// The plugins service reading it "at a pinned commit" — nothing pins it. AV-7's
// advisory-kinds leg "in the plugins service" — no such reader, and no design
// entry for it to be unimplemented from.
//
// **It is worse than an absent implementation.** An absent implementation is a
// hole somebody can see. A row that says a coupling is watched tells a third
// party they may rename the thing, because it would be caught over there. For
// AV-7 that third party is whoever adds a revocation kind, and one unknown kind
// makes the daemon refuse the WHOLE list — so every armed build of that
// population blocks installs seven days later. The false claim is the mechanism
// by which the real failure ships.
//
// So: a claim that names a reader in another repository carries the literal
// search that finds it, and the row fails when the search comes back empty.
// Not a link, not a section number, not a requirement id — the search, run,
// with a floor, saying which tree it read, and recording the expected state in
// BOTH directions.
//
// ── why a table and not another hard-coded pair ─────────────────────────────
//
// `C12`, `C15`, `C16` and `C20` already skip loudly and are the shape this
// copies. What none of them has is a TABLE: each hard-codes one comparison, so
// a claim written tomorrow is checked by nothing until somebody writes a
// sixteenth function. Here the claims are data, and a claim added later is
// checked BY HAVING BEEN WRITTEN.
//
// ── the four verdicts, and why four ─────────────────────────────────────────
//
// Counted rather than felt, by the partner estate, over 26 uses of an
// `unexercised` sentinel and five hand-written bounds. Three of these are not
// FOUND and they fail differently and want opposite remedies:
//
//   FOUND           the search ran, over a tree that was there, and the reader
//                   is in it.
//   MEASURED ABSENT the search ran, over a tree that was there, its walk met
//                   its floor, and the needle matched nothing. Remedy: fix the
//                   claim, or fix the needle. ("not one RAISE was found in 16
//                   migration(s)" — the denominator is what makes this a
//                   finding rather than a shrug.)
//   COULD NOT ASK   the search never ran: no checkout, no `git ls-files`, or a
//                   walk below its floor. Remedy: provide the tree. **COULD
//                   NOT ASK IS NOT NO COVER**, and it is not MEASURED ABSENT
//                   either — collapsing the two makes a broken needle read as
//                   a missing tool, so somebody goes and builds a tool that
//                   already exists, and it makes the instrument report
//                   confident absences about trees it never opened, which is
//                   the defect it exists to catch wearing its own uniform.
//   OUT OF SCOPE    a permanent stated bound on what a row ever covers.
//                   **Never fixed**, because there is nothing to fix; printed
//                   every run so it cannot be read as coverage, and kept out
//                   of every count of what was checked. Collapsing this into
//                   COULD NOT ASK turns a deliberate bound into a to-do
//                   nobody will ever do, and it reads as coverage meanwhile.
//
// The last two are STATEMENTS. They are printed, they are never a pass, and
// they are never a red.
//
// ── the two kinds of subject, and why the second needs saying ───────────────
//
// `kind: "code"` searches a tree for a reader. `kind: "decision"` reads a
// design item's STATE — chosen, open, built, withdrawn — and not merely its
// existence: **a section number that resolves is not a section number that was
// decided.**
//
// The reason is the sharper half of this whole page. **The first kind of false
// claim decays; the second was never true.** A stale claim was right once and
// stopped being, so time and re-measurement find it. A decision written down
// as its expected branch was false the moment somebody who could see both
// branches typed it, and nothing that runs later can tell, because there was
// never a moment when the sentence was right. Re-measuring the other
// repository never finds it — only reading the decision does. So where a claim
// points at a design item, `open` is a legitimate printable answer that is not
// `absent`, and the row asserts the claim's own sentence is hedged to match.
//
// ── the half that runs everywhere ───────────────────────────────────────────
//
// Registry CI checks out no Astra, no minice-be and no astra-plugins-ops, so
// every foreign row is COULD NOT ASK there, for ever, loudly. What runs on
// every machine is the ANCHOR and the HEDGE: the claim's sentence must still be
// in the file that makes it, and a claim whose expected state is `absent` must
// SAY SO in that sentence. That is the check that would have caught all five
// instances at the moment each was typed, with no second checkout anywhere —
// because in every one of them the sentence was in the present tense and the
// thing was not there.
//
// Registry plan: gap 21 of `O:dev/couplings.md`; RC-R1-6 (the AV-7 rows).

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual } from "./harness.mjs";

export const FOUND = "FOUND";
export const MEASURED_ABSENT = "MEASURED ABSENT";
export const COULD_NOT_ASK = "COULD NOT ASK";
export const OUT_OF_SCOPE = "OUT OF SCOPE";

/**
 * The trees a claim can be about, and how to find one.
 *
 * `env` first, then the sibling, which is the order `tools/validate.mjs` uses
 * for `$ASTRA_PLUGINS_DIR`. `probe` is a tracked file that must exist for the
 * directory to count as that tree — a directory that happens to have the right
 * NAME is not a checkout, and pointing at one would produce a walk of nothing
 * and a confident absence.
 */
export const TREES = {
  here: {
    label: "astra-registry (this checkout)",
    env: null,
    siblings: [REPO_ROOT],
    probe: "tools/selftest.mjs",
  },
  astra: {
    label: "Astra (the daemon and the UI; private)",
    env: "ASTRA_DIR",
    siblings: ["../Astra"],
    probe: "astra-rs/Cargo.toml",
  },
  service: {
    label: "minice-be (the plugins service; private)",
    env: "ASTRA_SERVICE_DIR",
    siblings: ["../minice"],
    probe: "api/Cargo.toml",
  },
  ops: {
    label: "astra-plugins-ops (the plans and the register; private)",
    env: "ASTRA_OPS_DIR",
    siblings: ["../astra-plugins-ops"],
    probe: "dev/couplings.md",
  },
};

/** Where a tree is, and how it was found — or why it could not be asked. */
export function locate(tree) {
  const tried = [];
  const candidates = [];
  if (tree.env) {
    tried.push(`$${tree.env}${process.env[tree.env] ? ` = ${process.env[tree.env]}` : " (unset)"}`);
    if (process.env[tree.env]) candidates.push(process.env[tree.env]);
  }
  for (const rel of tree.siblings) {
    const abs = path.resolve(REPO_ROOT, rel);
    tried.push(abs);
    candidates.push(abs);
  }
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, tree.probe))) return { dir, tried };
  }
  return { dir: null, tried };
}

/**
 * The tracked files of a tree, filtered to what a claim's search is about.
 *
 * `git ls-files` rather than a disk walk, for the reason `walkRepo()` gives:
 * it is the same answer on a developer's machine and in CI, and nothing
 * downloaded, built or vendored-by-a-package-manager is in it. A `target/`
 * with half a million lines of somebody's dependency is not a place a claim
 * about a reader can be true.
 *
 * Throws rather than returning `[]`. An empty list from a failed `git` is the
 * one input that makes every search below come back absent, and it must not be
 * possible to read that as an answer.
 */
export function trackedFiles(dir, { under = [], exts = [] } = {}) {
  let listed;
  try {
    listed = execFileSync("git", ["-C", dir, "ls-files", "-z"], {
      encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    throw new Error(`\`git -C ${dir} ls-files\` failed: ${String(e.stderr || e.message).trim()}`);
  }
  return listed
    .split("\0")
    .filter(Boolean)
    .filter((rel) => under.length === 0 || under.some((u) => rel === u || rel.startsWith(`${u}/`)))
    .filter((rel) => exts.length === 0 || exts.some((x) => rel.endsWith(x)));
}

/**
 * One claim, resolved to one of the four verdicts.
 *
 * Pure with respect to the claim: everything it reads is named in the claim or
 * in `TREES`, so the tests below can construct a claim and watch each verdict
 * come out, rather than hoping the real table will one day exercise them.
 */
export function resolve(claim, trees = TREES) {
  if (claim.subject.kind === "bound") {
    return { verdict: OUT_OF_SCOPE, tree: "—", detail: claim.subject.statement };
  }

  const tree = trees[claim.subject.tree];
  if (!tree) return { verdict: COULD_NOT_ASK, tree: claim.subject.tree, detail: "no such tree is declared in TREES" };
  const { dir, tried } = locate(tree);
  if (!dir) {
    return {
      verdict: COULD_NOT_ASK,
      tree: tree.label,
      detail: `no checkout: looked for ${tree.probe} under ${tried.join(", ")}`,
    };
  }

  const { under = [], exts = [], floorFiles = 1, needle } = claim.subject;
  let files;
  try {
    files = trackedFiles(dir, { under, exts });
  } catch (e) {
    return { verdict: COULD_NOT_ASK, tree: tree.label, detail: `${dir}: ${e.message}` };
  }

  // The floor, before any conclusion. "I searched and found nothing" and "I
  // searched the wrong tree" are one observation until a minimum is asserted,
  // and the second is the more likely of the two: a path moves, a crate is
  // renamed, an extension list outlives the language. Below the floor this is
  // a broken walk and therefore COULD NOT ASK — never MEASURED ABSENT, which
  // is the collapse the whole instrument is against.
  if (files.length < floorFiles) {
    return {
      verdict: COULD_NOT_ASK,
      tree: tree.label,
      detail: `the walk of ${dir} saw ${files.length} file(s) under [${under.join(", ") || "the whole tree"}] ` +
        `with [${exts.join(", ") || "any extension"}] and the floor is ${floorFiles}; this is a broken walk, ` +
        `not an absent reader, and every conclusion below it would have been a confident absence`,
    };
  }

  const hits = [];
  for (const rel of files) {
    let text;
    try {
      text = fs.readFileSync(path.join(dir, rel), "utf8");
    } catch {
      continue;
    }
    text.split("\n").forEach((line, i) => {
      if (needle.test(line)) hits.push(`${rel}:${i + 1}`);
    });
  }

  const seen = `${hits.length} hit(s) in ${files.length} tracked file(s) of ${dir}`;
  if (claim.subject.kind === "decision") {
    // A design item's STATE, not its existence. A needle that resolves and a
    // state that was decided are different questions, and only the second one
    // is what a sentence citing the item is entitled to assert.
    if (hits.length === 0) {
      return {
        verdict: MEASURED_ABSENT,
        tree: tree.label,
        detail: `the design item itself is not in that tree — ${seen}`,
      };
    }
    const text = [...new Set(hits.map((h) => h.split(":")[0]))]
      .map((rel) => fs.readFileSync(path.join(dir, rel), "utf8"))
      .join("\n")
      .split("\n")
      .filter((line) => claim.subject.needle.test(line))
      .join("\n");
    for (const [state, re] of Object.entries(claim.subject.states)) {
      if (re.test(text)) return { verdict: FOUND, tree: tree.label, state, detail: `${seen}; state: ${state}` };
    }
    return {
      verdict: COULD_NOT_ASK,
      tree: tree.label,
      detail: `${seen}, and none of the state markers [${Object.keys(claim.subject.states).join(", ")}] matched ` +
        `any of them; the item's state cannot be read, which is not the same as the item being open`,
    };
  }

  return hits.length
    ? { verdict: FOUND, tree: tree.label, detail: `${seen} — ${hits.slice(0, 4).join(", ")}` }
    : { verdict: MEASURED_ABSENT, tree: tree.label, detail: seen };
}

// ── the claims ──────────────────────────────────────────────────────────────
//
// Seeded from the claims that exist today, each MEASURED on 2026-09-20 rather
// than copied from the page that records it. Add a row here and it is checked;
// that is the whole design.
//
// Every row carries:
//   source   the file in THIS repository that makes the claim, and a line
//            pattern that finds the sentence. The pattern is the anchor: a
//            claim reworded out from under its row leaves the row checking
//            nothing, so a source that no longer matches is a failure.
//   expect   `found` or `absent`, asserted in BOTH directions. A reader a row
//            says is absent and which now exists is as much a finding as the
//            reverse — that is how "created disarmed" and "not vendored yet"
//            stop being sentences nobody re-checks.
//   hedge    required on every `absent` row: the pattern in the claim's own
//            sentence that says out loud it is not there yet. This is the half
//            that runs with no foreign checkout, and it is the half that would
//            have caught all five of 2026-09-19's instances.
export const CLAIMS = [
  {
    id: "signed-set/selftest",
    claim: "the signer's selftest reads the signed-set corpus, by importing `loadSignedSetVectors`",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*the signer's selftest\s*\|/,
    },
    subject: {
      kind: "code",
      tree: "here",
      under: ["tools/selftest"],
      exts: [".mjs"],
      floorFiles: 10,
      needle: /loadSignedSetVectors/,
    },
    expect: "found",
    why: "the corpus's only live reader. If this goes absent the corpus proves nothing at all, in any repository, " +
      "and the eleven vectors and the closed verdict vocabulary are a file nobody opens",
  },
  {
    id: "signed-set/probe",
    claim: "the ROLL-15 probe is not in this repository and does not read the corpus (RC-R1-7 puts it in " +
      "astra-plugins-ops, unbuilt)",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*the ROLL-15 probe\s*\|/,
      hedge: /not yet/,
    },
    subject: {
      kind: "code",
      tree: "here",
      // Everything but the generator, its two READMEs and the one live reader
      // above. The question this row asks is whether a SECOND program in this
      // checkout reads the corpus, so the four files that are already
      // accounted for are not an answer to it.
      under: ["bot", "site", ".github", "tools/probe-signed-set"],
      exts: [".mjs", ".js", ".yml", ".yaml", ".json", ".md"],
      floorFiles: 40,
      // The artifact, for the reason the `signed-set/service` row gives at
      // length: `signed-set` on its own is two different things in two
      // estates, and a needle that cannot tell them apart makes a red row
      // mean nothing.
      needle: /signed-set-v1\.json|signed-set-vectors|signed_set_vectors/,
    },
    expect: "absent",
    why: "the table said this in the present tense and in the wrong repository. A reader consults this table " +
      "before renaming a verdict, and a phantom reader tells them the rename would be caught somewhere it " +
      "would not be",
  },
  {
    id: "signed-set/service",
    claim: "the plugins service does not read the corpus yet, and nothing here knows what commit it would pin",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*the plugins service\s*\|/,
      hedge: /not yet/,
    },
    subject: {
      kind: "code",
      tree: "service",
      exts: [".rs", ".ts", ".tsx", ".js", ".mjs", ".py", ".sql", ".toml", ".yaml", ".yml"],
      floorFiles: 200,
      // The ARTIFACT's name, not the concept's. Measured 2026-09-20: a needle
      // of `/signed-set/` returns ten hits in that estate, every one of them
      // `"signed-set document"` — SERVE-50's cap on a blob read from the
      // `signed` branch, which is a different thing wearing the same two
      // words. It resolved FOUND, the row went red, and the reader it sent to
      // go and look was right to go. **A needle that names a concept collides
      // across estates; a needle that names a file does not**, and this table
      // is only worth having if a red row means what it says.
      needle: /signed-set-v1\.json|signed-set-vectors|signed_set_vectors/,
    },
    expect: "absent",
    why: "ROLL-61. The day this goes FOUND, the corpus has a third consumer and the README's `not yet` is a lie " +
      "in the other direction — and whether that consumer reads a pin or a live checkout decides whether the " +
      "corpus's two authors can ever see it disagree with them",
  },
  {
    id: "signed-set/daemon",
    claim: "astra-daemon has not vendored the corpus; `astra-daemon/testdata/signed-set-vectors/` does not exist",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /\|\s*`astra-daemon`\s*\|/,
      hedge: /not yet/,
    },
    subject: {
      kind: "code",
      tree: "astra",
      under: ["astra-rs"],
      exts: [".rs", ".toml", ".md", ".json", ".txt", ".yml", ".yaml"],
      floorFiles: 300,
      needle: /signed-set-vectors|signed_set_vectors/,
    },
    expect: "absent",
    why: "client plan C1.8. This is the instance gap 21 was written about: the file said `vendored`, in the " +
      "present tense, inside the document a reader would check it against",
  },
  {
    id: "av7/daemon-enum",
    claim: "`astra-daemon/src/plugins/trust.rs`'s `RevocationKind` is the authority for the kinds this registry " +
      "may publish",
    source: {
      file: "tools/lib/revocations.mjs",
      line: /RevocationKind` is the authority/,
    },
    subject: {
      kind: "code",
      tree: "astra",
      under: ["astra-rs/astra-daemon/src"],
      exts: [".rs"],
      floorFiles: 50,
      needle: /pub enum RevocationKind/,
    },
    expect: "found",
    why: "AV-7. `KINDS` and the literal seven in tools/selftest/revocations.mjs are held against this enum by " +
      "hand. If it moves or is renamed, both are comparing against a memory, and one unknown kind makes the " +
      "daemon refuse the WHOLE withdrawal list — every armed build of that population blocks installs 7 days later",
  },
  {
    id: "av7/daemon-comparison",
    claim: "nothing in Astra compares `RevocationKind` with this repository's `KINDS`; `consistency.rs` does not " +
      "name the enum",
    source: {
      file: "tools/selftest/revocations.mjs",
      line: /`consistency\.rs` does not mention it/,
      hedge: /has not been written/,
      // Prose, not a table: the hedge is two lines further down the same
      // block comment. Three is the reach to the end of that sentence and no
      // further — a window that could touch the next bullet would let one
      // claim borrow another's hedge, which is the defect the zero default
      // exists to stop.
      window: 3,
    },
    subject: {
      kind: "code",
      tree: "astra",
      under: ["astra-rs/astra-daemon/src/consistency.rs"],
      exts: [".rs"],
      floorFiles: 1,
      needle: /RevocationKind/,
    },
    expect: "absent",
    why: "the client plan's C1.4 is the sibling-checkout pair that would close this. Until it lands, the floor in " +
      "tools/selftest/revocations.mjs is the ONLY thing that notices an eighth key — and the day C1.4 lands this " +
      "row goes red, which is the point: the comment claiming nobody compares them has outlived its truth",
  },
  {
    id: "av7/service-leg",
    claim: "the plugins service has no advisory-kinds reader — not unimplemented, unspecified",
    source: {
      file: "tools/selftest/revocations.mjs",
      line: /the plugins service — no reader/,
      hedge: /no reader/,
    },
    subject: {
      kind: "code",
      tree: "service",
      // Source extensions only, and that is a measured decision rather than
      // tidiness. On 2026-09-20 a needle over the whole tree returned two
      // hits, both prose RECORDING this absence — one in that estate's own
      // memory of gap 21, one in an attack document quoting the register row's
      // name. **A search that matches the documentation of an absence reports
      // the absence as present**, which is this instrument failing in its own
      // subject matter. A reader is code.
      exts: [".rs", ".ts", ".tsx", ".js", ".mjs", ".py", ".sql"],
      floorFiles: 200,
      needle: /advisory_kind|RevocationKind|revocation_kind|AV-7/,
    },
    expect: "absent",
    why: "AV-7's third leg. A register row saying this coupling is watched tells whoever adds a kind that the " +
      "rename would be caught over there; there is no over there",
  },
  {
    id: "security/not-after-cutoff",
    claim: "no delegated index key carries a `not_after`, so a compromise is cut off by a trust.json that DROPS " +
      "the key and never by an expiry",
    source: {
      file: "SECURITY.md",
      line: /stop accepting anything the old key signs/,
      hedge: /carries no `not_after`/,
      window: 6,
    },
    subject: {
      kind: "code",
      tree: "here",
      under: ["registry/v1/trust.json"],
      exts: [".json"],
      floorFiles: 1,
      needle: /"not_after"/,
    },
    expect: "absent",
    why: "§5.1 step 1 promised a cut-off nobody could perform: it told an operator to wait out a field that is " +
      "not in the document. This row is also the re-read RC-RN-1 owes — the 2027 renewal ceremony adds a " +
      "`not_after` for `astra-index-2026a` (ROLL-45), and on the day it appears this goes FOUND and red, which " +
      "is the whole difference between a check and a promise to look again later",
  },
  {
    id: "revocations/five-enforcement-points",
    claim: "the daemon enforces the withdrawal list at five places, the fifth being the resolved `entry.command` " +
      "binary that a sideloaded directory is caught by",
    source: {
      file: "tools/revocations/README.md",
      line: /the daemon has five places/,
    },
    subject: {
      kind: "code",
      tree: "astra",
      under: ["astra-rs/astra-daemon/src"],
      exts: [".rs"],
      floorFiles: 50,
      needle: /five enforcement points/,
    },
    expect: "found",
    why: "this README tells an author that a `digest`-only advisory has a hole and which kind closes it. The " +
      "number is the daemon's, and if the daemon ever stops enumerating five, the advice here is advice about a " +
      "program that no longer exists — and the reader it misleads is writing a withdrawal during an incident",
  },
  {
    id: "d10/compromise-half",
    claim: "OPEN-OWNER-25's compromise half is OPEN, so D10's procedure is a proposal and the rotation section " +
      "may not write it as the procedure",
    source: {
      file: "docs/RUNBOOK.md",
      line: /OPEN-OWNER-25/,
      // No bare `open` alternative: the item's own id contains OPEN, so a
      // pattern that accepted it would be satisfied by the citation and would
      // assert nothing at all. Measured — `/open/i` passes against the string
      // `OPEN-OWNER-25` alone.
      hedge: /\bproposal\b|has not answered|awaiting the owner/i,
    },
    subject: {
      kind: "decision",
      tree: "ops",
      under: ["dev/server-registry-plan-registry.md"],
      exts: [".md"],
      floorFiles: 1,
      // The STATUS row's own spelling, and nothing else in the plan. Fourteen
      // other lines name this item — an exit need, a version-schedule row, a
      // task's ID list — and one of them reads `compromise half answered`
      // while describing what R1 must reach, not what is true today. A state
      // read off prose about the item is a state read off somebody's plan for
      // it, so this needle matches the one line that IS the status.
      needle: /\*\*OPEN-OWNER-25, compromise half: [A-Z]+\*\*/,
      // Read in this order; the first that matches wins, so the decided
      // spellings come first and `open` cannot win by being looser. None
      // matching is COULD NOT ASK, not `open`: an item whose state cannot be
      // read is not an item that was left open, and the two need opposite
      // acts — one waits on a person, the other on a reader that has stopped
      // matching the document.
      states: {
        answered: /compromise half: (ANSWERED|CLOSED|DECIDED)\*\*/,
        withdrawn: /compromise half: WITHDRAWN\*\*/,
        open: /compromise half: OPEN\*\*/,
      },
    },
    expect: "found",
    expectState: "open",
    why: "this is the kind of false claim that never decays, because it was never true. D10 contradicts SERVE-30's " +
      "rule that the outgoing key keeps signing until R9b, and R1 cannot exit without the owner's answer. A " +
      "runbook that prints D10 as the compromise procedure is a decision presented as an outcome, and no amount " +
      "of re-measuring another repository finds it — only reading the decision does",
  },
  {
    id: "bound/current-bytes",
    claim: "NOT checked here: that a reader this instrument FOUND reads the CURRENT bytes",
    source: {
      file: "tools/testkeys/vectors/README.md",
      line: /at a commit it will pin/,
    },
    subject: {
      kind: "bound",
      statement:
        "a found reader may be reading a vendored copy from any day, or a live checkout of any commit. Nothing " +
        "in this repository pins any foreign tree, so this instrument can say a reader EXISTS and can never say " +
        "it is in step. That is closed by a pin — ROLL-61 for the service, C1.8's re-vendor for the daemon — and " +
        "not by anything on this line. It is printed every run so it is never read as coverage",
    },
    expect: "out-of-scope",
    why: "a permanent bound, and permanently stated. The alternative is a green row that a reader takes for a " +
      "freshness check somebody already built",
  },
];

/** The four verdicts a table resolves to, in the order they are printed. */
export function resolveAll(claims = CLAIMS) {
  return claims.map((c) => ({ claim: c, ...resolve(c) }));
}

/**
 * The claim's own sentence, as it stands in the file that makes it — each
 * matching line together with the `window` lines after it.
 *
 * **The window defaults to ZERO, and that default was measured rather than
 * chosen.** It was 3, on the reasoning that a claim in prose is a paragraph
 * and the hedge belongs wherever the author put it. Then the canary for the
 * `signed-set/probe` row — restore the false present-tense row and watch the
 * suite go red — came back GREEN. In a markdown table the rows are adjacent
 * LINES, so a three-line window read the NEXT ROW's `**not yet**` and greened
 * the unhedged one above it. A hedge borrowed from the row below is the
 * instrument doing the thing it exists to catch, and it was invisible until a
 * canary was watched rather than assumed.
 *
 * So: zero by default, which is exactly right for a table row, and a `window`
 * stated per row where the claim really is a paragraph — never wide enough to
 * reach a neighbouring claim.
 */
export function sourceLines(claim, root = REPO_ROOT) {
  const file = path.join(root, claim.source.file);
  if (!fs.existsSync(file)) return null;
  const all = fs.readFileSync(file, "utf8").split("\n");
  const window = claim.source.window ?? 0;
  const out = [];
  all.forEach((line, i) => {
    if (claim.source.line.test(line)) out.push(all.slice(i, i + 1 + window).join("\n"));
  });
  return out;
}

export async function run() {
  console.log("\nclaims about readers in other repositories");

  const resolved = resolveAll();

  // The transcript, before any assertion, because two of the four verdicts are
  // never a pass and never a red and a printed line is the only place they can
  // live. A run that says nothing about what it could not ask is a run whose
  // silence reads as coverage.
  //
  // ── and it is CAPTURED, because nothing used to read it ────────────────────
  //
  // The check below is named "OUT OF SCOPE is printed, is never a pass, and is
  // never counted as checked", and until 2026-09-22 its first clause was
  // asserted by nothing: the printing happens here, before any `test()` runs,
  // and the body only inspected the in-memory `resolved` array. Measured — a
  // `continue` on OUT_OF_SCOPE in this loop plus the deletion of the summary's
  // out-of-scope clause made the permanent bound completely invisible in the
  // run, and the suite came back 317 passed, 0 failed, exit 0, with the check
  // still printing `ok`. The paragraph above says a printed line is the only
  // place these verdicts can live; it was the one thing nobody checked.
  //
  // `console.log` is wrapped rather than a second array being built beside the
  // printing, and that distinction is the whole repair. An array appended to
  // next to each `console.log` is two statements that can be separated, and the
  // check would then be asserting that the ARRAY was built — which is what it
  // was already doing wrong, one level down. What is asserted has to be what
  // reached stdout.
  const printed = [];
  const counted = (v) => resolved.filter((r) => r.verdict === v).length;
  {
    const realLog = console.log;
    console.log = (...args) => { printed.push(args.map(String).join(" ")); realLog(...args); };
    try {
      for (const r of resolved) {
        console.log(`        ${r.verdict.padEnd(15)} ${r.claim.id}`);
        console.log(`                        tree: ${r.tree}`);
        console.log(`                        ${r.detail}`);
      }
      console.log(
        `        — ${counted(FOUND)} found, ${counted(MEASURED_ABSENT)} measured absent, ` +
        `${counted(COULD_NOT_ASK)} could not ask, ${counted(OUT_OF_SCOPE)} out of scope (never checked, never fixed)`,
      );
    } finally {
      console.log = realLog;
    }
  }

  await test("the claims table has a floor, unique ids, and a well-formed row for each", () => {
    // The floor on the TABLE, for the reason every enumerating check in this
    // repository states one: an empty table agrees with everything. Nine on
    // 2026-09-20; the floor is 6, so retiring a claim whose subject is gone is
    // an ordinary act and does not put the next author in front of a red check
    // with one keystroke between them and zero.
    assert(CLAIMS.length >= 6,
      `the claims table holds ${CLAIMS.length} row(s) and held 9 on 2026-09-20; this is a table that has been ` +
      `emptied rather than a repository with fewer cross-repository claims`);

    const twice = CLAIMS.map((c) => c.id).filter((id, i, a) => a.indexOf(id) !== i);
    assertEqual([...new Set(twice)].join(", "), "", "two claims share an id, so one of them is invisible in the transcript");

    const bad = [];
    for (const c of CLAIMS) {
      if (!["found", "absent", "out-of-scope"].includes(c.expect)) bad.push(`${c.id}: expect is ${c.expect}`);
      if (!c.why) bad.push(`${c.id}: no \`why\`, so a reader of a red row cannot tell what it costs to ignore it`);
      // The hedge is REQUIRED on every `absent` row and forbidden as a
      // decoration on the others: it is the assertion that this repository's
      // own sentence admits the reader is not there. Without it the row would
      // pass while the document went on claiming the reader in the present
      // tense — which is every one of 2026-09-19's five instances.
      if (c.expect === "absent" && !c.source.hedge) bad.push(`${c.id}: an \`absent\` claim with no \`hedge\` pattern`);
      if (c.subject.kind === "decision" && !c.expectState) bad.push(`${c.id}: a decision row with no \`expectState\``);
      if (c.expectState === "open" && !c.source.hedge) bad.push(`${c.id}: an \`open\` decision with no \`hedge\` pattern`);
      // A hedge satisfied by the citation itself asserts nothing. `/open/i`
      // against a sentence whose only content is `OPEN-OWNER-25` is the
      // measured case, and it would have made this row green while the
      // runbook printed an undecided procedure as the procedure.
      if (c.source.hedge && c.source.hedge.test(c.id)) bad.push(`${c.id}: the hedge matches the claim's own id`);
    }
    assertEqual(bad.join("; "), "", "a row in the claims table cannot be resolved");
  });

  await test("every claim's own sentence is still in the file that makes it", () => {
    // The anchor. A claim reworded, moved or deleted out from under its row
    // leaves the row checking a foreign tree for a sentence nobody makes any
    // more — searching, passing, and about nothing. This is the failure a
    // requirement id in place of a search has by construction, and the reason
    // the row carries the literal pattern.
    const orphaned = [];
    for (const c of CLAIMS) {
      const lines = sourceLines(c);
      if (lines === null) orphaned.push(`${c.id}: ${c.source.file} is not in this repository`);
      else if (lines.length === 0) orphaned.push(`${c.id}: nothing in ${c.source.file} matches ${c.source.line}`);
    }
    assertEqual(orphaned.join("; "), "",
      "a claims row has lost the sentence it is about; either restore the sentence or retire the row, and do not " +
      "leave a row that searches another repository on behalf of nobody");
  });

  await test("a claim whose expected state is `absent` says so in its own sentence (the half that needs no checkout)", () => {
    // This is the whole of gap 21 caught from inside one repository, and it is
    // the only part of this module that runs in registry CI. Every one of
    // 2026-09-19's five instances was a sentence in the PRESENT TENSE about a
    // thing that was not there — so the sentence is what is asserted, and no
    // second checkout is needed to assert it.
    const unhedged = [];
    for (const c of CLAIMS) {
      // `absent` rows, and decision rows whose expected state is `open` —
      // which is the same defect in the tense that never decays. A sentence
      // citing an undecided item as though it were decided was false the
      // moment it was typed, so the sentence is where it has to be caught.
      const mustHedge = c.expect === "absent" || c.expectState === "open";
      if (!mustHedge) continue;
      const lines = sourceLines(c) ?? [];
      if (!lines.some((l) => c.source.hedge.test(l))) {
        unhedged.push(`${c.id} — ${c.source.file}: ${JSON.stringify(lines[0] ?? "(no line)")}`);
      }
    }
    assertEqual(unhedged.join("; "), "",
      "this repository states in the PRESENT TENSE that a reader in another repository exists, and the measured " +
      "answer is that it does not. That sentence is not a stale note: it tells the next person to rename the " +
      "thing that the rename would be caught over there, and it would not be. Hedge the sentence or build the " +
      "reader");
  });

  await test("every measurable claim matches its expected state, in BOTH directions", () => {
    const wrong = [];
    for (const r of resolved) {
      if (r.verdict === COULD_NOT_ASK || r.verdict === OUT_OF_SCOPE) continue;
      const want = r.claim.expect === "found" ? FOUND : MEASURED_ABSENT;
      if (r.verdict !== want) {
        wrong.push(
          `${r.claim.id}: expected ${want}, measured ${r.verdict} in ${r.tree} — ${r.detail}. ${r.claim.why}`,
        );
        continue;
      }
      if (r.claim.expectState && r.state !== r.claim.expectState) {
        wrong.push(
          `${r.claim.id}: the design item is there and its state is ${JSON.stringify(r.state)}, and this ` +
          `repository's sentence is written for ${JSON.stringify(r.claim.expectState)} — ${r.claim.why}`,
        );
      }
    }
    assertEqual(wrong.join("\n  "), "", "a claim about another repository does not match that repository");
  });

  await test("COULD NOT ASK is not NO COVER: an unreadable tree never resolves to MEASURED ABSENT", () => {
    // The defect one level up, and the reason this verdict exists at all. A
    // sibling checkout goes missing, a path moves, an extension list outlives
    // its language — and a grep that matched nothing because it opened nothing
    // becomes a confident absence. Watched here rather than hoped for, in all
    // three of the ways it can happen.
    const base = {
      id: "synthetic", claim: "x", why: "x", expect: "absent",
      source: { file: "tools/selftest.mjs", line: /MODULES/, hedge: /./ },
    };

    const noTree = resolve({ ...base, subject: { kind: "code", tree: "nowhere", needle: /x/ } });
    assertEqual(noTree.verdict, COULD_NOT_ASK, "an undeclared tree resolved to something other than COULD NOT ASK");

    // A tree that is DECLARED and whose checkout is not on this machine —
    // which is every foreign row of the real table in registry CI, and is
    // therefore the state this module spends most of its life in.
    const absentTree = {
      gone: { label: "a repository nobody has here", env: "ASTRA_NO_SUCH_DIR", siblings: ["../no-such-checkout"], probe: "Cargo.toml" },
    };
    const noCheckout = resolve({ ...base, subject: { kind: "code", tree: "gone", needle: /x/ } }, absentTree);
    assertEqual(noCheckout.verdict, COULD_NOT_ASK, "a tree with no checkout must not resolve to an absence");
    assert(noCheckout.detail.includes("no checkout") && noCheckout.detail.includes("no-such-checkout"),
      "a skip has to NAME what it did not read, or it reads as a pass in a wall of green");

    // The probe file is what separates a checkout from a directory with the
    // right name. Pointed at this repository while asking for Astra's
    // `Cargo.toml`, the answer must still be COULD NOT ASK — otherwise a
    // mistyped env var searches the wrong tree and reports a confident
    // absence about the right one.
    const wrongTree = {
      astra: { label: "Astra", env: "ASTRA_NO_SUCH_DIR", siblings: ["."], probe: "astra-rs/Cargo.toml" },
    };
    assertEqual(resolve({ ...base, subject: { kind: "code", tree: "astra", needle: /x/ } }, wrongTree).verdict,
      COULD_NOT_ASK,
      "a directory without the tree's probe file was accepted as that tree, so the search ran somewhere else and " +
      "its answer would have been reported about the tree it never opened");

    // A tree that IS there, whose walk falls below its floor. This is the
    // subtle one: `git ls-files` succeeded, the directory is a real checkout,
    // and the filter matched nothing — so the needle would have searched zero
    // files and come back empty, which is indistinguishable from an answer.
    const brokenWalk = resolve({
      ...base,
      subject: {
        kind: "code",
        tree: "here",
        under: ["tools/selftest"],
        exts: [".this-extension-does-not-exist"],
        floorFiles: 10,
        needle: /anything/,
      },
    });
    assertEqual(brokenWalk.verdict, COULD_NOT_ASK,
      "a walk below its floor resolved to an absence; it is a broken walk, and reporting it as an absence is " +
      "exactly the confident-absence-about-a-tree-nobody-opened this instrument exists to catch");
    assert(brokenWalk.detail.includes("broken walk"), "the message must say which of the two it is");

    // And the floor is a floor rather than a formality: the same walk with a
    // floor it can meet answers the question instead of refusing it.
    //
    // The needle is ASSEMBLED rather than written, and that is not cleverness.
    // Written as a literal it appeared in this file, which is under
    // `tools/selftest/` — so the moment this module was committed and `git
    // ls-files` began returning it, the search found itself and the canary
    // came back FOUND. It was green for as long as the file was untracked and
    // red on the first run after the commit, which is the most useful way that
    // failure could possibly have arrived. `isSuiteFile` in harness.mjs exists
    // for the same reason: the file that states a rule is not an instance of
    // it.
    const absentToken = new RegExp(["no", "such", "token", "in", "this", "tree"].join("-"));
    const realWalk = resolve({
      ...base,
      subject: { kind: "code", tree: "here", under: ["tools/selftest"], exts: [".mjs"], floorFiles: 10, needle: absentToken },
    });
    assertEqual(realWalk.verdict, MEASURED_ABSENT,
      "a walk that met its floor and matched nothing is an ANSWER, and refusing to give it would make the floor " +
      "a way of never concluding anything");
  });

  await test("OUT OF SCOPE is printed, is never a pass, and is never counted as checked", () => {
    // A permanent bound is not a to-do and not coverage. Both collapses cost
    // something specific: read as COULD NOT ASK it becomes a task nobody can
    // ever complete, and read as FOUND it becomes a check somebody thinks
    // exists.
    const bounds = resolved.filter((r) => r.verdict === OUT_OF_SCOPE);
    assert(bounds.length >= 1,
      "no row states a permanent bound. This instrument has at least one — it can say a foreign reader EXISTS " +
      "and can never say it reads the current bytes — and an unstated bound is read as coverage");
    for (const b of bounds) {
      assertEqual(b.claim.expect, "out-of-scope", `${b.claim.id} resolved OUT OF SCOPE without declaring it`);
      assert(b.detail && b.detail.length > 40,
        `${b.claim.id}: a bound with no statement is a silence, which is the thing it is here to prevent`);
      // `is printed`, the first clause of this name, asserted against what this
      // run actually wrote to stdout. Not against `resolved`, which is what it
      // used to do and which is true whether or not a single line was emitted.
      assert(printed.some((l) => l.includes(OUT_OF_SCOPE) && l.includes(b.claim.id)),
        `${b.claim.id} resolved OUT OF SCOPE and no line of this run's transcript says so. A bound that is not ` +
        `printed is a bound nobody can read, and a run whose silence about it reads as coverage is the failure ` +
        `this verdict exists to prevent`);
      assert(printed.some((l) => l.includes(b.detail)),
        `${b.claim.id}: the bound's STATEMENT never reached stdout, so the transcript names a bound and does not ` +
        `say what it bounds — which is the collapse into COULD NOT ASK wearing the right label`);
    }
    // And the summary line carries the count with the words that keep it out of
    // both collapses. Deleting the clause is the cheapest way to make a
    // permanent bound invisible while every row below still prints `ok`.
    assert(
      printed.some((l) => l.includes(`${counted(OUT_OF_SCOPE)} out of scope (never checked, never fixed)`)),
      `the summary line does not state ${counted(OUT_OF_SCOPE)} out of scope (never checked, never fixed); a ` +
      `count printed without those words is read as a to-do on one side and as coverage on the other, and the ` +
      `transcript this run wrote was: ${JSON.stringify(printed.filter((l) => l.includes("found,"))[0] ?? "(no summary line at all)")}`,
    );
    // And it is excluded from the counts the line above prints, so "3 found"
    // never quietly includes a row that checks nothing.
    const checkable = resolved.filter((r) => r.verdict === FOUND || r.verdict === MEASURED_ABSENT);
    assert(!checkable.some((r) => r.claim.expect === "out-of-scope"),
      "a bound was counted among the rows that were measured");
  });

  await test("a decision row reads the item's STATE, and an unreadable state is not `open`", () => {
    // "A section number that resolves is not a section number that was
    // decided." The first kind of false claim decays and re-measurement finds
    // it; this kind was never true, so the only thing that finds it is reading
    // what was decided. Three synthetic decisions, one per outcome.
    const base = {
      id: "synthetic-decision", claim: "x", why: "x", expect: "found", expectState: "open",
      source: { file: "tools/selftest.mjs", line: /MODULES/ },
    };
    const subject = (states) => ({
      kind: "decision",
      tree: "here",
      under: ["tools/selftest.mjs"],
      exts: [".mjs"],
      floorFiles: 1,
      needle: /const MODULES = \[/,
      states,
    });

    const open = resolve({ ...base, subject: subject({ answered: /never-appears/, open: /const MODULES/ }) });
    assertEqual(open.verdict, FOUND, "a decision whose item is present must resolve FOUND");
    assertEqual(open.state, "open", "the state a marker matched was not reported");

    // The order is load-bearing: `answered` is asked first, so an item that
    // has been decided cannot be reported as open by a looser fallback.
    const answered = resolve({ ...base, subject: subject({ answered: /const MODULES/, open: /const MODULES/ }) });
    assertEqual(answered.state, "answered", "a decided item was reported as open by the fallback marker");

    // No marker matched. Not `open` — the item's state could not be read, and
    // the two need opposite acts: one is waiting on somebody, the other is a
    // reader that has stopped matching the document.
    const unreadable = resolve({ ...base, subject: subject({ answered: /never-appears/, open: /never-either/ }) });
    assertEqual(unreadable.verdict, COULD_NOT_ASK,
      "a design item whose state markers all missed was reported as a state; an unreadable state is not `open`");
    assert(unreadable.detail.includes("not the same as the item being open"),
      "the message must separate `nobody has decided` from `this reader cannot tell`");

    // And the item not being in the tree at all is an absence rather than an
    // unreadable state, because those need opposite fixes too.
    const gone = resolve({
      ...base,
      subject: { ...subject({ open: /x/ }), needle: /no-such-decision-id-anywhere/ },
    });
    assertEqual(gone.verdict, MEASURED_ABSENT, "a cited design item that is not in the tree must be an absence");
  });
}
