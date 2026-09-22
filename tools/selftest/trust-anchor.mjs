// The root of this estate's trust, verified — with the estate's own verifier,
// on the bytes that are COMMITTED.
//
// ── the finding this module exists for (couplings gap 48) ───────────────────
//
// On 2026-09-22 a lane flipped one bit in the root signature of
// `registry/v1/trust.json` — the document every other signed document in this
// repository is checked AGAINST — and ran the whole suite:
//
//     INCOMPLETE  300 passed, 0 failed, 1 not asked (24 modules)     exit 0
//
// Zero checks red, and the printed transcript byte-identical to the transcript
// of the sound tree. Measured again here before this file was written, on the
// same commit, with the same result. The verifier in `bot/lib/` refuses that
// document the moment it is asked — `no trusted key signed this document; it
// offers astra-root-2026a` — and nothing in 300 checks asked it.
//
// **Why it stayed invisible is the shape of the repair.** The anchor is the one
// document in the estate with nothing above it. Every other signed document is
// checked by being COMPARED with this one — index signatures, the rehearsal
// steps, the served set, the delegated index keys — so each of those checks is
// a comparison, and a comparison needs two documents. The anchor has no second
// document to be compared with, so it fell through a suite built out of
// comparisons. The repair is therefore not another comparison. It is calling
// the verifier that already exists on the file itself.
//
// ── the verifier is the repository's own, and that is not a style preference ─
//
// `loadWorkflowAllowlist` is the exact call `bot/ingest.mjs` makes before it
// will believe anything about a release, and it is used here unchanged: same
// function, same default key set, a file path in and a verdict out. A
// hand-rolled `crypto.verify` beside it would be a second implementation of one
// rule — two places that can come to disagree about what a valid anchor is,
// with the test half being the one nobody would notice had drifted. This
// estate is currently paying for exactly that shape elsewhere; it is not worth
// repeating for the document at the bottom of the chain.
//
// It also means this module inherits the verifier's failing-closed behaviour
// rather than reimplementing it: a missing file, an unparseable one and an
// empty key set are all `E_TRUST_UNPROVISIONED`, never a pass. The first check
// below watches that live, because a verifier that verifies nothing passes
// every assertion under it.
//
// ── committed, not only what happens to be on disk ──────────────────────────
//
// The failure mode is a bad anchor REACHING A PUBLICATION. `git show
// HEAD:registry/v1/trust.json` is therefore the subject that matters: it is
// what a merge carries, what `signed` copies byte for byte (tools/signer/
// plan.mjs's D2), and what Pages eventually serves. A check that read only the
// working tree would pass on a commit whose anchor is corrupt as long as
// somebody's editor buffer was clean.
//
// The working tree is checked too, in its own test, for the other reason: it is
// the document the rest of this suite compares against all night. Both are
// named in their own check so a red says which one, and the two are compared
// only to tell a reader whether the damage is committed or local.
//
// ── two key sets, and which is which ────────────────────────────────────────
//
// COMPILED (`bot/lib/roots.mjs`) is what production judges with:
// `loadWorkflowAllowlist` defaults to it and `bot/ingest.mjs` passes no file,
// deliberately — B-T1.5 took the roots out of `--registry-dir` so that a run
// pointed at any directory could not also be a run whose anchor came out of
// that directory. So "would the bot accept this anchor" is asked against the
// compiled set.
//
// PUBLISHED (`registry/v1/root.json`) is what a client fetches beside the
// anchor and verifies with. `roots.mjs` already holds the two sets equal; this
// module does not repeat that comparison — it asks the different question of
// whether the ANCHOR verifies under each of them, which a set comparison
// cannot answer. During SERVE-92's rotation both sets contain whichever root
// signed the anchor at every step, so neither leg is a rotation tripwire.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../lib/sources.mjs";
import { loadRootKeys, loadWorkflowAllowlist } from "../../bot/lib/attestation.mjs";
import { compiledRootKeys } from "../../bot/lib/roots.mjs";
import { gitMaybe } from "../signer/git.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";

const TRUST_REL = "registry/v1/trust.json";
const ROOT_REL = "registry/v1/root.json";

/** The key ids in a key set, for a message that has to say WHICH key. */
const idsOf = (set) => set.keys.map((k) => k.key_id).join(", ") || "none";

/**
 * A verdict, rendered for a failure message.
 *
 * `loadWorkflowAllowlist` already names the file and the key ids the document
 * offered; what it cannot know is which key set it was handed and where the
 * bytes came from, and those are the two facts a reader needs in order to know
 * whether to go and look at the anchor or at the roots.
 */
const why = (verdict, where, set) =>
  `${where}: ${verdict.ok ? "accepted" : `${verdict.code} — ${verdict.message}`} ` +
  `(verified against the ${set.status} root set: ${idsOf(set)})`;

export async function run() {
  console.log("\nthe trust anchor itself (registry/v1/trust.json)");

  // `git show` rather than a read of the file: this is the whole point of the
  // module. `gitMaybe` and not `blobAt`, even though `blobAt` is the named
  // helper for a file's bytes at a ref, because `blobAt` answers `null` for
  // both "this is not a git checkout" and "HEAD has no such path" — and those
  // send a reader to two different places. The error text is kept for the
  // message.
  const show = gitMaybe(["show", `HEAD:${TRUST_REL}`], { root: REPO_ROOT });
  const committedFile = path.join(tmp, "trust-anchor-at-HEAD.json");
  if (show.ok) fs.writeFileSync(committedFile, show.out);

  const compiled = compiledRootKeys();
  const published = loadRootKeys(path.join(REPO_ROOT, ROOT_REL));

  // ── the floor, first, because everything below it is an `ok === true` ──────
  //
  // A verifier handed nothing accepts nothing, and this is the check that says
  // so out loud rather than trusting the sentence in `attestation.mjs` that
  // says it. Every assertion below asserts that a verdict came back `ok`; if
  // the verifier could be made to answer `ok` over an absence, all three of
  // them would pass over an estate with no anchor at all — which is the
  // failure this module was written to end, one level down.
  //
  // Four absences, because they are four different ways to hand it nothing and
  // they arrive by different accidents: a path that moved, a write that
  // truncated to zero, a merge conflict left in the file, and a root set that
  // resolved empty.
  await test("the verifier refuses an anchor it was handed nothing of", () => {
    const write = (name, body) => {
      const p = path.join(tmp, name);
      fs.writeFileSync(p, body);
      return p;
    };
    const cases = [
      ["a path that is not there", path.join(tmp, "trust-anchor-absent.json"), compiled],
      ["a document of zero bytes", write("trust-anchor-empty.json", ""), compiled],
      ["a document that is not JSON", write("trust-anchor-garbage.json", "<<<<<<< HEAD\n"), compiled],
      ["a key set with no roots in it", committedFile, { status: "empty", keys: [] }],
    ];
    for (const [what, file, roots] of cases) {
      const verdict = loadWorkflowAllowlist({ trustFile: file, roots });
      assertEqual(verdict.ok, false,
        `the verifier accepted ${what}. Every check below this one asserts that it said yes, so a verifier ` +
        "that cannot say no makes all of them pass over an estate with no trust anchor at all");
      assertEqual(verdict.code, "E_TRUST_UNPROVISIONED", `${what} was refused under the wrong code`);
    }
    // And the sets THIS module is about to use are not one of those absences.
    assert(compiled.keys.length >= 1,
      "bot/lib/roots.mjs compiles in no root key, so the check below would be verifying the anchor against " +
      "nothing and reporting it as sound");
    assert(published.keys.length >= 1,
      `${ROOT_REL} publishes no root key, so the check below would be verifying the anchor against nothing`);
  });

  await test("the COMMITTED trust anchor is signed by a root the bot compiles in", () => {
    // The subject has to exist before it can be sound. A `git show` that
    // failed, or that came back empty, is not a green anchor.
    assert(show.ok,
      `${TRUST_REL} could not be read out of HEAD, so the document a merge would carry was never looked at: ` +
      `${show.ok ? "" : show.error}`);
    assert(show.out.length > 0,
      `HEAD holds a zero-byte ${TRUST_REL}. That is the anchor a publication would carry`);

    const verdict = loadWorkflowAllowlist({ trustFile: committedFile, roots: compiled });
    assertEqual(verdict.ok, true,
      "the root of this estate's trust does not verify at HEAD, so a merge would carry an anchor the bot " +
      `refuses and every signed document checked against it is checked against a forgery. ` +
      `${why(verdict, `HEAD:${TRUST_REL}`, compiled)}. This is the one document with nothing above it: it is ` +
      "not repaired by re-running anything, and it is never re-signed by an agent — hand it to the operator, " +
      "who holds the root key offline (SECURITY.md's ceremony)");
    assert(typeof verdict.key_id === "string" && verdict.key_id.length > 0,
      "the anchor verified and the verifier could not name the key that did it, so a red here would not be able " +
      "to say which root to go and look at");
    assert(compiled.keys.some((k) => k.key_id === verdict.key_id),
      `HEAD:${TRUST_REL} verified under a key the compiled set does not name (${verdict.key_id}); ` +
      "`verifyEnvelope` returns the key that verified and never the one the document claimed, so this would " +
      "mean the two disagree about what that key is called");
  });

  await test("the committed anchor also verifies under the roots root.json publishes", () => {
    assert(show.ok, `${TRUST_REL} could not be read out of HEAD: ${show.ok ? "" : show.error}`);
    const verdict = loadWorkflowAllowlist({ trustFile: committedFile, roots: published });
    assertEqual(verdict.ok, true,
      `a client that fetches ${ROOT_REL} beside the anchor and verifies with it would refuse this estate's ` +
      `trust document. ${why(verdict, `HEAD:${TRUST_REL}`, published)}. ` +
      `roots.mjs holds the published set and the compiled set equal, so if that check is green and this one is ` +
      "red then the anchor is signed by neither and the damage is to the anchor, not to the key sets");
  });

  await test("the working tree's anchor, which every other check in this suite compares against", () => {
    // The finding's own mutation was a working-tree one, and it is the state a
    // reviewer is actually in: a file edited, not yet committed, with 300
    // checks comparing other documents against it and none of them looking at
    // it. A red here and a green above means the damage is local and a
    // checkout undoes it, which is worth saying in the message rather than
    // leaving a reader to work out from two results.
    const file = path.join(REPO_ROOT, TRUST_REL);
    const verdict = loadWorkflowAllowlist({ trustFile: file, roots: compiled });
    const committedIsSound = show.ok && loadWorkflowAllowlist({ trustFile: committedFile, roots: compiled }).ok;
    assertEqual(verdict.ok, true,
      `the trust anchor in the working tree does not verify, and the rest of this suite has spent its whole run ` +
      `comparing signed documents against it. ${why(verdict, TRUST_REL, compiled)}. ` +
      (committedIsSound
        ? `HEAD's copy of the same file IS sound, so this is a local edit and `
          + `\`git checkout -- ${TRUST_REL}\` restores it`
        : "HEAD's copy does not verify either, so this is committed damage — see the check above"));
  });
}
