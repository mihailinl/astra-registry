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
// BOT-7), and `loadWorkflowAllowlist` verifies against those and nothing else.
// They used to be read out of `registry/v1/root.json` — a file in this
// repository, in the same tree as this code, rewritten by the bot's own
// `publish` job — which put the anchor inside the thing it anchors: a commit
// that added a key to that file moved what this function would accept, in the
// same breath as the trust.json signed by it. `bot/lib/roots.mjs` has the
// whole argument, and `bot/check-roots.mjs` alarms when the published file and
// the compiled set stop agreeing.
//
// The file is still read, by `loadRootKeys` below: by `check-roots.mjs`, which
// is comparing the two on purpose, and by the tests, which build a roots
// document out of the clearly-labelled TEST keys in `tools/testkeys/` and hand
// it in through the injection seam — exactly as the daemon's tests do behind
// `insecure-test-trust-roots`. Production names no file and has no flag that
// would let it.
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

import { compiledRootKeys } from "./roots.mjs";
import { publicKeyFromBase64, verifyEnvelope, TRUST_SCHEMA } from "./sign.mjs";

const execFileAsync = promisify(execFile);

/**
 * Load a root key set out of a `root.json`-shaped document.
 *
 * Not the production path. `bot/check-roots.mjs` uses it to compare the
 * published file with the compiled set, and the tests use it to build a set
 * from `tools/testkeys`; `loadWorkflowAllowlist` defaults to the compiled set
 * and no caller in the bot names a file.
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
 * The signer facts, dug out of whatever shape `gh` produced.
 *
 * `gh attestation verify --format json` has changed its envelope more than once,
 * and this has to keep working across the versions a runner might have. So every
 * field is looked for in each of the places it has lived, and **a field that is
 * not found anywhere is `null`, never a default** — the caller treats a missing
 * signer digest as a failed verification, because "we could not find out which
 * workflow signed this" and "the right workflow signed this" must not produce
 * the same outcome.
 */
export function extractSignerFacts(results) {
  const list = Array.isArray(results) ? results : [results];
  const first = (...vals) => vals.find((v) => typeof v === "string" && v.length > 0) ?? null;

  for (const r of list) {
    const cert = r?.verificationResult?.signature?.certificate ?? r?.signature?.certificate ?? {};
    const statement = r?.verificationResult?.statement ?? r?.statement ?? {};
    const predicate = statement.predicate ?? {};
    const ext = predicate.buildDefinition?.externalParameters ?? {};

    const signerDigest = first(
      cert.buildSignerDigest,
      cert.build_signer_digest,
      predicate.buildDefinition?.resolvedDependencies?.[0]?.digest?.gitCommit,
    );
    const signerUri = first(cert.buildSignerURI, cert.build_signer_uri, ext.workflow?.path);
    const sourceRepo = first(cert.sourceRepositoryURI, cert.source_repository_uri, ext.workflow?.repository);
    const sourceDigest = first(cert.sourceRepositoryDigest, cert.source_repository_digest, ext.workflow?.ref);
    const runUri = first(cert.runInvocationURI, cert.run_invocation_uri, predicate.runDetails?.metadata?.invocationId);

    const subjects = Array.isArray(statement.subject) ? statement.subject : [];
    const subjectDigests = subjects.map((s) => s?.digest?.sha256).filter(Boolean);

    if (signerDigest || signerUri || subjectDigests.length) {
      return { signerDigest, signerUri, sourceRepo, sourceDigest, runUri, subjectDigests };
    }
  }
  return { signerDigest: null, signerUri: null, sourceRepo: null, sourceDigest: null, runUri: null, subjectDigests: [] };
}

/**
 * Run `gh attestation verify` and check what it says.
 *
 * @param {{file: string, repo: string, signerWorkflow: string, allowlist: string[],
 *          artifactSha256: string, runner?: (args: string[]) => Promise<{stdout: string}>}} opts
 * @returns {Promise<{findings: {level: string, code: string, message: string}[], facts: object|null}>}
 */
export async function verifyAttestation(opts) {
  const { file, repo, signerWorkflow, allowlist, artifactSha256 } = opts;
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
    // "no attestations found" is a different answer from "the attestation is
    // wrong", and an author fixes them differently.
    const missing = /no attestation|could not find any attestations|404/i.test(text);
    // "The verifier could not start" is not "the bytes are wrong", and telling
    // an author the second when the first happened sends them to rebuild a
    // release that was never broken. Seen in the wild: `gh` failed with
    // "public good verifier is not available (initialization…)" — it could not
    // fetch Sigstore's trust root — and the same bundle verified from another
    // machine, unchanged, minutes later.
    //
    // Still blocking, because an unverified artifact must not be listed. What
    // changes is what it says and who it points at: retry, not rebuild.
    const unavailable = /verifier is not available|initializ|trust(ed)? root|tuf|timeout|timed out|connection|network|temporar/i.test(text);
    findings.push({
      level: "error",
      code: missing
        ? "E_ATTESTATION_MISSING"
        : unavailable
          ? "E_ATTESTATION_UNCHECKED"
          : "E_ATTESTATION_INVALID",
      message: `gh attestation verify --repo ${repo} --signer-workflow ${signerWorkflow}: ${text.trim().split("\n")[0] || "failed"}`,
    });
    return { findings, facts: null };
  }

  const facts = extractSignerFacts(parsed);

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

  // The pin that makes the rest mean something.
  if (!facts.signerDigest) {
    findings.push({
      level: "error",
      code: "E_ATTESTATION_INVALID",
      message:
        "the attestation carries no resolved signer-workflow commit. Without it, this proves only " +
        "that GitHub built something — not which workflow did.",
    });
  } else if (!allowlist.includes(facts.signerDigest)) {
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
