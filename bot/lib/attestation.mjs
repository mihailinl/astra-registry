// Build provenance: who produced these bytes, and were they allowed to.
//
// This is the check that turns the bot from a consistency checker into a trust
// boundary. Everything before it says "the listing describes the archive"; this
// says "the archive came out of a GitHub Actions run, in the repository being
// listed, executing a release workflow this registry has agreed to trust".
//
// ── the two halves, and why the second one is not optional ──────────────────
//
// `gh attestation verify` alone proves that *some* workflow in *some*
// repository built these bytes and that Sigstore recorded it. That is a real
// fact and it is not enough: an attacker who can run any workflow in the
// repository can produce a perfectly valid attestation for a bundle they built
// by hand in a step called `curl | sh`. So the signer is pinned twice:
//
//   * `--repo` and `--signer-workflow` are passed to `gh`, which refuses the
//     verification outright if the certificate names anything else;
//   * the RESOLVED reusable-workflow commit SHA is read back out of the
//     certificate and asserted against `reusable_workflow_shas` in the
//     root-signed `trust.json`.
//
// The second is what makes `@v1` unusable as a supply chain: a mutable tag can
// be repointed at any commit, and the attestation would still say "release.yml
// from the right repository". Changing the allowlist is a root-key ceremony
// (PRODUCTION_PLAN §5.5), which is the property the whole arrangement is for.
//
// ── where the roots come from, and why not from a file ─────────────────────
//
// The roots are COMPILED IN, in `bot/lib/roots.mjs` (registry plan B-T1.5,
// BOT-7), and `loadWorkflowAllowlist` verifies against those unless a caller
// hands it another set — which nothing the bot runs does.
// They used to be read out of `registry/v1/root.json` — a file in this
// repository, in the same tree as this code, rewritten by the bot's own
// `publish` job — which put the anchor inside the thing it anchors: a commit
// that added a key to that file moved what this function would accept, in the
// same breath as the trust.json signed by it. `bot/lib/roots.mjs` has the
// whole argument, and `bot/check-roots.mjs` alarms when the published file and
// the compiled set stop agreeing.
//
// The file is still read, on purpose, and only the suites read it through
// `loadRootKeys` below. `check-roots.mjs` parses it itself and hands the
// document to `rootFileProblems` in `bot/lib/roots.mjs`, which compares it with
// the compiled set; it never builds a key set out of it. `loadRootKeys` is
// called by `tools/selftest/trust-anchor.mjs`, which loads the published set to
// ask whether the committed anchor also verifies under it, and by the bot's
// tests, which build a roots document out of the clearly-labelled TEST keys in
// `tools/testkeys/` and hand it in through the injection seam — exactly as the
// daemon's tests do behind `insecure-test-trust-roots`. Nothing the bot runs
// hands `loadWorkflowAllowlist` a set, and the bot has no flag that would let
// it.
//
// ── failing closed ─────────────────────────────────────────────────────────
//
// A key set with nothing in it verifies nothing, not everything, and says
// `E_TRUST_UNPROVISIONED`. That was the state of this registry until
// `b13759a` published the two roots the ceremony in SECURITY.md produced, and
// it remains the state of any verifier handed an empty set — which is what
// `astra-daemon` compiles in when `PRODUCTION_ROOT_KEYS` is empty. The message
// below said the ceremony "has not been run" as a fact about the world; it now
// says it as a fact about the key set it was given, because the first version
// outlived its truth by a month and told a reader to go and run a ceremony
// that had already happened.

import { execFile } from "node:child_process";
import fs from "node:fs";
import { promisify } from "node:util";

import { checkCertificateRows, readCertificateFields } from "./certificate.mjs";
import { compiledRootKeys } from "./roots.mjs";
import { publicKeyFromBase64, verifyEnvelope, TRUST_SCHEMA } from "./sign.mjs";

const execFileAsync = promisify(execFile);

/**
 * Load a root key set out of a `root.json`-shaped document.
 *
 * Not the bot's path: nothing the bot runs calls it. Its callers are the
 * suites' — `tools/selftest/trust-anchor.mjs` loads the published
 * `registry/v1/root.json` with it, and the bot's tests build a set from
 * `tools/testkeys` with it. `bot/check-roots.mjs` compares the published file
 * with the compiled set without it, through `rootFileProblems` in
 * `bot/lib/roots.mjs`. `loadWorkflowAllowlist` defaults to the compiled set and
 * no caller in the bot names a file.
 *
 * @param {string} file `registry/v1/root.json`, or a test roots file
 * @returns {{keys: {key_id: string, publicKey: import("node:crypto").KeyObject}[], status: string}}
 */
export function loadRootKeys(file) {
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  const roots = Array.isArray(doc.roots) ? doc.roots : [];
  return {
    status: doc.status ?? (roots.length ? "provisioned" : "unprovisioned"),
    keys: roots.map((r) => ({ key_id: r.key_id, publicKey: publicKeyFromBase64(r.public_key) })),
  };
}

/**
 * Read the workflow allowlist out of a root-signed `trust.json`.
 *
 * The signature is checked here rather than assumed, against the domain
 * constant this repository holds — never against the `schema` string inside the
 * file being read. A document that names its own domain can be replayed from
 * one document type to another by editing one field.
 *
 * @param {{trustFile: string, roots?: {status: string, keys: object[]}}} opts
 *   `roots` is the injection seam the tests hand a `tools/testkeys` set
 *   through. Production passes it not at all, and gets the compiled set.
 * @returns {{ok: true, allowlist: string[], serial: number, key_id: string} |
 *           {ok: false, code: string, message: string}}
 */
export function loadWorkflowAllowlist({ trustFile, roots = compiledRootKeys() }) {
  if (roots.keys.length === 0) {
    return {
      ok: false,
      code: "E_TRUST_UNPROVISIONED",
      message:
        `this verifier was given no root keys (status: ${roots.status}), so there is no key a signed ` +
        "trust.json could be checked against and no reusable-workflow allowlist to hold a build to. " +
        "Nothing is listed until there is one.",
    };
  }
  if (!fs.existsSync(trustFile)) {
    return {
      ok: false,
      code: "E_TRUST_UNPROVISIONED",
      message: `${trustFile} does not exist; the roots are provisioned but nothing has been signed with them yet.`,
    };
  }

  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(trustFile, "utf8"));
  } catch (e) {
    return { ok: false, code: "E_TRUST_UNPROVISIONED", message: `${trustFile}: ${e.message}` };
  }
  const verdict = verifyEnvelope(doc, TRUST_SCHEMA, roots.keys);
  if (!verdict.ok) {
    return {
      ok: false,
      code: "E_TRUST_UNPROVISIONED",
      message: `${trustFile} is not signed by a root key (${verdict.reason}; it offers ${verdict.offered.join(", ") || "nothing"})`,
    };
  }
  const allowlist = Array.isArray(doc.signed?.reusable_workflow_shas) ? doc.signed.reusable_workflow_shas : [];
  return { ok: true, allowlist, serial: doc.signed?.serial ?? 0, key_id: verdict.key_id };
}

/**
 * The signer facts — **from the certificate, and from nothing else**.
 *
 * This used to fall back to the in-toto predicate for four of the five fields:
 * `externalParameters.workflow.repository` stood in for the source repository,
 * `resolvedDependencies[0].digest.gitCommit` for the signer digest, and so on.
 * Those fallbacks are gone (registry plan B-T1.1; ID-28: read each field "from
 * the certificate extensions of every bundle, never the predicate or a name
 * lookup"). The predicate is a statement the BUILDER composed; the certificate
 * is one Fulcio would not have issued unless the OIDC token said so. Reading
 * the two into one variable meant an attestation whose certificate had been
 * stripped could still answer "which repository built this" with a string the
 * builder chose — which is the one question the certificate exists to answer.
 *
 * `bot/lib/certificate.mjs` owns the reading, the DER fallback included. **A
 * field that is not found is `null`, never a default**: "we could not find out
 * which workflow signed this" and "the right workflow signed this" must not
 * produce the same outcome.
 *
 * @param {object|object[]} results gh's parsed `--format json`
 * @param {string} [artifactSha256] the digest THESE bytes hash to. Given, it
 *   selects the attestation covering them and ignores every other one in the
 *   array — a release-file bundle naming other ids contributes no field here.
 */
export function extractSignerFacts(results, artifactSha256 = null) {
  const read = readCertificateFields({ parsed: results, artifactSha256 });
  const { fields } = read;
  return {
    signerDigest: fields.job_workflow_sha,
    signerUri: fields.job_workflow_ref,
    sourceRepo: fields.source_repository_uri,
    sourceDigest: fields.sha,
    runUri: fields.run,
    subjectDigests: read.seenDigests,
    /** The ten ID-28 fields, under the contract's names. */
    fields,
    /** `certificate` or `der`, per field, so a report can say where it read. */
    fieldSource: read.source,
    /** Whether an attestation in the array actually covered these bytes. */
    matched: read.matched,
    /** Values of the wrong TYPE — the SCOPE-5 refusal, before any coercion. */
    problems: read.problems,
  };
}

/**
 * What a failed `gh attestation verify` actually said, in three readings.
 *
 * `gh` exits 1 for every one of them, so the exit code answers nothing and the
 * text is the only evidence there is. The three differ in **who has to do
 * something**, and collapsing any two sends a person to fix the wrong thing:
 *
 *   * `missing` — there is genuinely no attestation. The author adds one.
 *   * `unavailable` — the verifier could not run at all: Sigstore's trust root
 *     unreachable, a timeout, no network. **Nobody's bytes are wrong.** The
 *     answer is to run it again, and — this is the part that matters for a
 *     once-only run — it is emphatically NOT evidence that the artifact is
 *     unattested.
 *   * neither — the attestation exists and does not satisfy the policy.
 *     `policyRefusal` additionally says gh gave its one-line refusal with no
 *     named check, which is a flags-versus-certificate disagreement.
 *
 * Extracted to one owner on 2026-09-20 because there were two readers and only
 * one reading. `bot/baseline.mjs`'s `verifyOne` had a bare `catch` that turned
 * all three into `{outcome: "unverified"}` — and that value is written into
 * MIG-20's migration record, which is written **once** and can never be
 * corrected. So a runner with no network, or a five-minute Sigstore outage,
 * would have recorded the whole catalogue as permanently unattested, with a
 * green exit code, and detector A1, MIG-28 and TRUST-23 all read that record.
 *
 * This is the estate's four-verdicts rule at the place it was most expensive
 * to collapse: *measured absent* and *could not ask* are different answers,
 * and only one of them is a fact about the artifact.
 *
 * @param {string} text stderr and message of the failed run, concatenated
 * @returns {{missing: boolean, policyRefusal: boolean, unavailable: boolean}}
 */
export function classifyVerifyFailure(text) {
  const s = String(text ?? "");
  const missing = /no attestation|could not find any attestations|HTTP 404|404: Not Found/i.test(s);
  const policyRefusal = /verifying with issuer/i.test(s);
  const unavailable = /verifier is not available|initializ|trust(ed)? root|tuf|timeout|timed out|connection|network|temporar/i.test(s);
  // `missing` wins: a 404 is a fact about the artifact, and the word "network"
  // appearing somewhere in the same stderr does not make it less of one.
  return { missing, policyRefusal, unavailable: unavailable && !missing };
}

/**
 * Run `gh attestation verify` and check what it says.
 *
 * **The signer flag is not optional, and the reason is measured.** B-T1.2's
 * survey (O:notes/state.md, 2026-09-19) ran the obvious command —
 * `gh attestation verify <file> --repo <source.repo> --format json`, with no
 * signer flag — against all 18 listings and it FAILED on 12 of them, on
 * attestations that are perfectly good: gh derives its SAN matcher from
 * `--repo`, and the SAN is the REUSABLE workflow's URI, so only the six ids
 * released out of `mihailinl/AstraPlugins` itself match. What it says when it
 * refuses is `Error: verifying with issuer "sigstore.dev"` — exit 1, nothing
 * on stdout, and not one word about which check refused. A genuinely missing
 * attestation says `HTTP 404: Not Found (…/attestations/sha256:…)`. **The two
 * differ in the message and never in the exit code**, so this function
 * classifies on the text and never on the status, and the flags below are the
 * flags the survey verified all 18 pass under.
 *
 * @param {{file: string, repo: string, signerWorkflow: string, allowlist: string[],
 *          artifactSha256: string, tag?: string|null,
 *          runner?: (args: string[]) => Promise<{stdout: string}>}} opts
 * @returns {Promise<{findings: {level: string, code: string, message: string}[], facts: object|null}>}
 */
export async function verifyAttestation(opts) {
  const { file, repo, signerWorkflow, allowlist, artifactSha256 } = opts;
  const tag = opts.tag ?? null;
  const findings = [];
  const run = opts.runner ?? (async (args) =>
    // `gh` is given an argument array, never a shell string: the repository and
    // the tag come from an issue form, and a bot that interpolates a stranger's
    // text into a shell is a bot with a command-injection hole in its most
    // security-critical step.
    execFileAsync("gh", args, { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 }));

  const args = [
    "attestation", "verify", file,
    "--repo", repo,
    "--signer-workflow", signerWorkflow,
    "--format", "json",
  ];

  let parsed;
  try {
    const { stdout } = await run(args);
    parsed = JSON.parse(stdout);
  } catch (e) {
    const text = `${e.stderr ?? ""}${e.message ?? ""}`;
    const { missing, policyRefusal, unavailable } = classifyVerifyFailure(text);
    // "no attestations found" is a different answer from "the attestation is
    // wrong", and an author fixes them differently.
    //
    // The 404 is the only thing that means "there is no attestation", and it
    // is matched on the text because the exit code says 1 either way. gh's
    // policy refusal — `verifying with issuer "sigstore.dev"` — is deliberately
    // NOT in this pattern: it means the flags and the certificate disagree,
    // which is the registry's bug or the author's workflow, never "no
    // attestation exists". Telling an author to add an attestation they
    // already have is the failure B-T1.2's first pass made, on 12 of 18.
    //
    // "The verifier could not start" is not "the bytes are wrong", and telling
    // an author the second when the first happened sends them to rebuild a
    // release that was never broken. Seen in the wild: `gh` failed with
    // "public good verifier is not available (initialization…)" — it could not
    // fetch Sigstore's trust root — and the same bundle verified from another
    // machine, unchanged, minutes later.
    //
    // Still blocking here, because an unverified artifact must not be listed.
    // What changes is what it says and who it points at: retry, not rebuild.
    //
    // The three-way reading itself lives in `classifyVerifyFailure` above,
    // because `bot/baseline.mjs` needs the same one and had a bare `catch`.
    const first = text.trim().split("\n")[0] || "failed";
    findings.push({
      level: "error",
      code: missing
        ? "E_ATTESTATION_MISSING"
        : unavailable
          ? "E_ATTESTATION_UNCHECKED"
          : "E_ATTESTATION_INVALID",
      message:
        `gh attestation verify --repo ${repo} --signer-workflow ${signerWorkflow}: ${first}` +
        (policyRefusal && !missing
          ? ". gh refuses with that one line whenever its verification policy and the certificate " +
            "disagree, and names no check; it is NOT a missing attestation (the 404 is)."
          : ""),
    });
    return { findings, facts: null };
  }

  const facts = extractSignerFacts(parsed, artifactSha256);

  // A field of the wrong type, refused before anything reads it (SCOPE-5).
  for (const p of facts.problems) {
    findings.push({ level: "error", code: "E_ATTESTATION_INVALID", message: p.message });
  }

  // The digest, in the third of its three places (§5.2: attestation subject,
  // index record, and what the daemon hashes — one number).
  if (facts.subjectDigests.length && !facts.subjectDigests.includes(artifactSha256)) {
    findings.push({
      level: "error",
      code: "E_ATTESTATION_SUBJECT_MISMATCH",
      message:
        `the attestation covers ${facts.subjectDigests.join(", ")} and the asset hashes to ` +
        `${artifactSha256}`,
    });
  }

  if (facts.sourceRepo) {
    const expected = `https://github.com/${repo}`;
    if (facts.sourceRepo.toLowerCase() !== expected.toLowerCase()) {
      findings.push({
        level: "error",
        code: "E_ATTESTATION_REPO_MISMATCH",
        message: `the attestation names ${facts.sourceRepo} as the source repository, not ${expected}`,
      });
    }
  }

  // ID-28's rows, from the certificate: presence of all ten, plus .9, .11,
  // .14 and .20. `.10` is the next branch (only this function knows the
  // allowlist) and `.13` is compared with the Release at ingest step 10 (only
  // that function has the Release). `.15`, `.17` and `.12`'s name are read
  // here and compared from R3.
  findings.push(...checkCertificateRows({ fields: facts.fields, tag, signerWorkflow }));

  // The pin that makes the rest mean something. Its ABSENCE is reported by the
  // row check above, which states every missing field in one finding; this
  // branch is about a signer commit that is present and not allowed.
  if (facts.signerDigest && !allowlist.includes(facts.signerDigest)) {
    findings.push({
      level: "error",
      code: "E_WORKFLOW_NOT_ALLOWED",
      message:
        `the build was signed by ${facts.signerUri ?? "an unnamed workflow"} at commit ` +
        `${facts.signerDigest}, which is not in the root-signed allowlist ` +
        `(${allowlist.length} entr${allowlist.length === 1 ? "y" : "ies"}). Pin the reusable ` +
        "workflow by commit SHA rather than by tag.",
    });
  }

  return { findings, facts };
}
