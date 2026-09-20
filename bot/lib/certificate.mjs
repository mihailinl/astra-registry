// The ten certificate fields, and nothing that stands in for them.
//
// Registry plan B-T1.1 (ID-28, ID-29, INV-4, SCOPE-5, AV-2). Every identity
// fact the registry acts on comes out of the Fulcio certificate of the
// attestation that verified the DOWNLOADED digest. Not out of the in-toto
// predicate, not out of a name lookup, and not out of an `.sigstore.jsonl`
// nobody verified: a predicate is a claim the builder wrote, and the whole
// point of the certificate is that Fulcio would not have issued it for a claim
// the OIDC token did not carry.
//
// ── where the values come from, measured rather than assumed ───────────────
//
// B-T1.2's survey (O:notes/state.md, 2026-09-19, `gh 2.100.0`, 18 bundles /
// 24 artifacts / 18 listings) answered the question B-T1.1 was gated on: **all
// ten OIDs are present as certificate fields in `gh attestation verify
// --format json` on every bundle in the catalogue**. So the first branch — read
// them out of `verificationResult.signature.certificate` — is the branch that
// runs, and `GH_JSON_KEYS` below is the mapping that survey confirmed field by
// field against `openssl x509 -text` on the DER of every bundle.
//
// **The DER fallback below is dead code for today's catalogue, and it is kept
// anyway.** It fires for one thing only: a certificate that carries an
// extension gh's JSON has no key for. The survey found a live example of that
// class — `.24` (`repo:<owner>/<name>:ref:<ref>`, the OIDC `sub`) is on every
// certificate and in nobody's JSON — so the class is real even though no field
// this file reads is in it today. A reader who deletes it should know they are
// deleting the answer to "gh renamed a key" and "gh dropped one", not an
// unused branch. It is exercised by a fixture in `bot/tests/ingest.test.mjs`
// and was run once, by hand, against a real Fulcio certificate.
//
// ── present, absent, and not-asked-for ─────────────────────────────────────
//
// A field that is not found is `null`, never a default and never an empty
// string, and ID-28 makes a missing field `E_ATTESTATION_INVALID`. "We could
// not find out which repository built this" and "the right repository built
// this" must never produce the same outcome — which is the same rule
// `extractSignerFacts` in `attestation.mjs` states for the signer digest, for
// the same reason.
//
// ── the ids are strings, and that is not a style choice (SCOPE-5) ──────────
//
// `.15` and `.17` are base-10 STRINGS. A repository id past 2^53 arriving as a
// JSON number has already lost its last digits by the time any code here sees
// it, and `String(n)` then makes the loss unreadable — so a number is refused
// by TYPE rather than coerced and pattern-matched. `bot/baseline.mjs` makes the
// same refusal about the same two members, one layer up, and for the same
// reason; this is the layer that can still tell what arrived.

/**
 * The ten OIDs ID-28 names, by the name the contract's table uses.
 *
 * `.16`, `.18`, `.19` and `.22` are on every certificate too (survey,
 * 2026-09-19) and no rule reads them, so they are not here: a field this file
 * returns is a field something compares.
 */
export const FULCIO_OIDS = Object.freeze({
  job_workflow_ref: "1.3.6.1.4.1.57264.1.9",
  job_workflow_sha: "1.3.6.1.4.1.57264.1.10",
  runner_environment: "1.3.6.1.4.1.57264.1.11",
  source_repository_uri: "1.3.6.1.4.1.57264.1.12",
  sha: "1.3.6.1.4.1.57264.1.13",
  ref: "1.3.6.1.4.1.57264.1.14",
  repository_id: "1.3.6.1.4.1.57264.1.15",
  repository_owner_id: "1.3.6.1.4.1.57264.1.17",
  event_name: "1.3.6.1.4.1.57264.1.20",
  run: "1.3.6.1.4.1.57264.1.21",
});

/**
 * gh's JSON key for each, and the snake_case spelling older versions used.
 *
 * Confirmed OID-by-OID against the DER of all 18 bundles by B-T1.2's survey
 * with `gh 2.100.0`. Whoever re-reads this with a different `gh` re-checks the
 * key names first — that instruction is in the survey and it is repeated here
 * because this object is where it would bite.
 */
export const GH_JSON_KEYS = Object.freeze({
  job_workflow_ref: ["buildSignerURI", "build_signer_uri"],
  job_workflow_sha: ["buildSignerDigest", "build_signer_digest"],
  runner_environment: ["runnerEnvironment", "runner_environment"],
  source_repository_uri: ["sourceRepositoryURI", "source_repository_uri"],
  sha: ["sourceRepositoryDigest", "source_repository_digest"],
  ref: ["sourceRepositoryRef", "source_repository_ref"],
  repository_id: ["sourceRepositoryIdentifier", "source_repository_identifier"],
  repository_owner_id: ["sourceRepositoryOwnerIdentifier", "source_repository_owner_identifier"],
  event_name: ["buildTrigger", "build_trigger"],
  run: ["runInvocationURI", "run_invocation_uri"],
});

/** The field names, in ID-28's order, for messages that list them. */
export const CERTIFICATE_FIELDS = Object.freeze(Object.keys(FULCIO_OIDS));

const BASE10_RE = /^[0-9]+$/;
const SHA1_RE = /^[0-9a-f]{40}$/;

/**
 * Every result `gh attestation verify --format json` returned, flattened.
 *
 * gh has shipped the result as a bare object and as an array, and the
 * certificate under two different parents; both shapes are read here so that
 * one gh upgrade is not a registry outage.
 */
function resultList(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === "object") return [parsed];
  return [];
}

function certificateOf(result) {
  return result?.verificationResult?.signature?.certificate ?? result?.signature?.certificate ?? {};
}

function statementOf(result) {
  return result?.verificationResult?.statement ?? result?.statement ?? {};
}

/** The subject digests one result covers. One release's bundle carries several. */
export function subjectDigestsOf(result) {
  const subjects = statementOf(result).subject;
  return (Array.isArray(subjects) ? subjects : []).map((s) => s?.digest?.sha256).filter(Boolean);
}

/**
 * Pick the result that verified THESE bytes.
 *
 * A release with several assets can hand `gh` an array in which only one
 * attestation names the digest in front of us — and B-T1.1's canary "a
 * release-file bundle naming other ids is ignored" is exactly this: an
 * attestation for another file in the same release must contribute no field to
 * this artifact's identity.
 *
 * A result carrying no subject at all is not "the one that matched"; it is
 * only usable when nothing in the array carries a subject, which is the shape
 * a hand-written fixture has.
 *
 * @returns {{result: object|null, matched: boolean, seen: string[]}}
 */
export function selectResult(parsed, artifactSha256) {
  const results = resultList(parsed);
  const seen = [];
  for (const r of results) {
    const digests = subjectDigestsOf(r);
    seen.push(...digests);
    if (artifactSha256 && digests.includes(artifactSha256)) return { result: r, matched: true, seen };
  }
  const subjectless = results.find((r) => subjectDigestsOf(r).length === 0) ?? null;
  return { result: seen.length ? null : subjectless, matched: false, seen };
}

// ── DER, for the certificate gh has no key for ──────────────────────────────

/**
 * One DER TLV at `offset`.
 *
 * Enough of X.690 to walk a certificate: definite lengths only, which is what
 * DER permits, and a hard refusal of anything longer than the buffer rather
 * than a silent truncation.
 */
function readTlv(buf, offset) {
  if (offset + 2 > buf.length) throw new Error("DER ends inside a tag");
  let tag = buf[offset];
  let pos = offset + 1;
  if ((tag & 0x1f) === 0x1f) throw new Error("DER high-tag-number form is not parsed here");
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("DER indefinite or over-long length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos++];
  }
  const end = pos + len;
  if (end > buf.length) throw new Error("DER length runs past the buffer");
  return { tag, start: offset, contentStart: pos, end, content: buf.subarray(pos, end) };
}

/** Decode an OBJECT IDENTIFIER's contents to dotted form. */
function decodeOid(bytes) {
  if (bytes.length === 0) return "";
  const out = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      out.push(value);
      value = 0;
    }
  }
  return out.join(".");
}

/**
 * Every extension in a DER certificate, as `{oid: string}` → string value.
 *
 * Fulcio's `.9` and up hold a DER-encoded UTF8String inside the extension's
 * OCTET STRING (the v2 encoding); `.1`–`.8` hold the raw string. Both are
 * handled: an inner UTF8String/IA5String/PrintableString is unwrapped, and
 * anything else is returned as UTF-8 text, which is what the older spelling
 * needs.
 *
 * @param {Buffer} der the certificate, DER
 * @returns {Map<string, string>}
 */
export function extensionsFromDer(der) {
  const out = new Map();
  const cert = readTlv(der, 0);            // Certificate ::= SEQUENCE
  const tbs = readTlv(der, cert.contentStart); // TBSCertificate ::= SEQUENCE
  // Walk TBSCertificate's members looking for [3] EXPLICIT Extensions.
  let off = tbs.contentStart;
  let extensions = null;
  while (off < tbs.end) {
    const member = readTlv(der, off);
    if (member.tag === 0xa3) {
      extensions = readTlv(der, member.contentStart); // SEQUENCE OF Extension
      break;
    }
    off = member.end;
  }
  if (!extensions) return out;

  let eoff = extensions.contentStart;
  while (eoff < extensions.end) {
    const ext = readTlv(der, eoff);
    let ioff = ext.contentStart;
    const oidNode = readTlv(der, ioff);
    ioff = oidNode.end;
    let valueNode = readTlv(der, ioff);
    if (valueNode.tag === 0x01) {          // the optional `critical` BOOLEAN
      ioff = valueNode.end;
      valueNode = readTlv(der, ioff);
    }
    const oid = decodeOid(oidNode.content);
    if (valueNode.tag === 0x04) {
      let text;
      try {
        const inner = readTlv(der, valueNode.contentStart);
        const isString = inner.tag === 0x0c || inner.tag === 0x16 || inner.tag === 0x13;
        text = isString && inner.end === valueNode.end
          ? inner.content.toString("utf8")
          : valueNode.content.toString("utf8");
      } catch {
        text = valueNode.content.toString("utf8");
      }
      out.set(oid, text);
    }
    eoff = ext.end;
  }
  return out;
}

/**
 * The certificate `gh` embedded in its own output, if it embedded one.
 *
 * `--format json` carries the signing certificate's DER under
 * `attestation.bundle.verificationMaterial.certificate.rawBytes` (and, in
 * older bundles, as the first entry of an `x509CertificateChain`). Both are
 * looked for; neither is required.
 */
export function derOf(result) {
  const material =
    result?.attestation?.bundle?.verificationMaterial ??
    result?.bundle?.verificationMaterial ??
    result?.verificationMaterial ??
    null;
  const raw =
    material?.certificate?.rawBytes ??
    material?.x509CertificateChain?.certificates?.[0]?.rawBytes ??
    null;
  if (typeof raw !== "string" || raw.length === 0) return null;
  try {
    return Buffer.from(raw, "base64");
  } catch {
    return null;
  }
}

// ── the ten fields ──────────────────────────────────────────────────────────

/**
 * Read the ten ID-28 fields out of the result that verified `artifactSha256`.
 *
 * @param {{parsed: object, artifactSha256: string}} opts `parsed` is whatever
 *   `gh attestation verify --format json` printed, already JSON-parsed.
 * @returns {{
 *   fields: Record<string, string|null>,
 *   source: Record<string, "certificate"|"der"|null>,
 *   matched: boolean,
 *   seenDigests: string[],
 *   problems: {field: string, message: string}[],
 * }}
 */
export function readCertificateFields({ parsed, artifactSha256 }) {
  const { result, matched, seen } = selectResult(parsed, artifactSha256);
  const fields = {};
  const source = {};
  const problems = [];
  for (const name of CERTIFICATE_FIELDS) {
    fields[name] = null;
    source[name] = null;
  }
  if (!result) return { fields, source, matched, seenDigests: seen, problems };

  const cert = certificateOf(result);
  let der = null;
  let derExtensions = null;

  for (const name of CERTIFICATE_FIELDS) {
    let value = null;
    for (const key of GH_JSON_KEYS[name]) {
      const candidate = cert?.[key];
      if (typeof candidate === "string" && candidate.length > 0) {
        value = candidate;
        source[name] = "certificate";
        break;
      }
      // A number here is the SCOPE-5 hazard, and it is refused rather than
      // coerced: by the time a value arrives as a JSON number its last digits
      // are already gone, and `String(n)` would hand the caller plausible
      // digits that name a different repository.
      if (typeof candidate === "number") {
        problems.push({
          field: name,
          message:
            `gh reported ${name} (${FULCIO_OIDS[name]}) as the JSON number ${candidate}, not a string. ` +
            "A repository id past 2^53 loses its last digits in JSON.parse, so the value is refused " +
            "rather than coerced (SCOPE-5).",
        });
      }
    }
    if (value === null) {
      // The fallback the survey says nothing in today's catalogue needs.
      if (derExtensions === null) {
        der = derOf(result);
        derExtensions = der ? safeExtensions(der, problems) : new Map();
      }
      const fromDer = derExtensions.get(FULCIO_OIDS[name]);
      if (typeof fromDer === "string" && fromDer.length > 0) {
        value = fromDer;
        source[name] = "der";
      }
    }
    fields[name] = value;
  }

  return { fields, source, matched, seenDigests: seen, problems };
}

function safeExtensions(der, problems) {
  try {
    return extensionsFromDer(der);
  } catch (e) {
    problems.push({ field: "certificate", message: `the embedded certificate could not be DER-parsed: ${e.message}` });
    return new Map();
  }
}

/**
 * `bot/baseline.mjs`'s one ask: the two ids, as base-10 strings or null.
 *
 * The name and the shape are fixed by `resolveCertificateReader` there
 * (B-T3.7b), which refuses to write a baseline until this function exists —
 * MIG-20 records a null id as "this certificate did not verify", so a missing
 * READER writing null would have recorded a registry-wide attestation failure
 * that never happened, once, permanently.
 *
 * @param {{bundle: object, artifactSha256: string}} opts `bundle` is gh's
 *   parsed `--format json` output.
 */
export function certificateIds({ bundle, artifactSha256 }) {
  const { fields } = readCertificateFields({ parsed: bundle, artifactSha256 });
  const id = fields.repository_id;
  const ownerId = fields.repository_owner_id;
  return {
    repository_id: typeof id === "string" && BASE10_RE.test(id) ? id : null,
    repository_owner_id: typeof ownerId === "string" && BASE10_RE.test(ownerId) ? ownerId : null,
  };
}

/** `https://github.com/owner/name` → `owner/name`; anything else → null. */
export function repoFromUri(uri) {
  if (typeof uri !== "string") return null;
  const m = /^https:\/\/github\.com\/([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)\/?$/.exec(uri.trim());
  return m ? m[1] : null;
}

/**
 * ID-28's rows, against one bundle's fields.
 *
 * Which rows are ENFORCED here, and why now: B-T1.1 makes `.9`, `.10`, `.11`,
 * `.13`, `.14` and `.20` blocking "only if the survey found every listing
 * passing" (ID-29). It did — 18/18, 2026-09-19 — so they block. `.15`, `.17`
 * and `.12`'s name are READ here and compared from R3 (B-T3.2, B-T3.3a),
 * because the thing to compare them against (MIG-20's baseline, an identity
 * record) does not exist until then.
 *
 * `.10` is not re-checked here: `verifyAttestation` holds it against the
 * root-signed allowlist, which is the only place that knows the allowlist, and
 * two checks emitting `E_WORKFLOW_NOT_ALLOWED` would be two answers to one
 * question. `.13` is compared with the Release at ingest step 10, where the
 * Release is. This function owns the rows nothing else was checking: presence,
 * `.9`, `.11`, `.14` and `.20`.
 *
 * **`.9`'s suffix is a commit, and this matcher does not say so.** The survey
 * measured every bundle in the catalogue: the suffix after `@` is always a
 * 40-hex SHA, never a symbolic ref. ID-28's row says "@ any ref" and a matcher
 * written `@refs/…` would refuse all 18 listings — so the rule stays "any
 * suffix", the observation is recorded here, and the fixture below pins the
 * shape that exists today without making it the rule.
 *
 * @param {{fields: Record<string, string|null>, tag: string|null,
 *          signerWorkflow: string}} opts
 * @returns {{level: string, code: string, message: string}[]}
 */
export function checkCertificateRows({ fields, tag, signerWorkflow }) {
  const findings = [];
  const invalid = (message) => findings.push({ level: "error", code: "E_ATTESTATION_INVALID", message });

  const missing = CERTIFICATE_FIELDS.filter((n) => fields[n] === null);
  if (missing.length) {
    invalid(
      `the certificate carries no ${missing.map((n) => `${n} (${FULCIO_OIDS[n]})`).join(", ")}. ` +
      "ID-28 reads every identity fact from the certificate extensions; a predicate field may not stand " +
      "in for one, so a build whose certificate omits one cannot be listed." +
      (missing.includes("job_workflow_sha")
        ? " Without the resolved signer-workflow commit in particular, this attestation proves only that " +
          "GitHub built something — not which workflow did."
        : ""),
    );
  }

  // .9 — the reusable workflow's path, at any ref.
  if (fields.job_workflow_ref !== null) {
    const expected = `https://github.com/${signerWorkflow}@`;
    if (!fields.job_workflow_ref.startsWith(expected)) {
      invalid(
        `job_workflow_ref (.9) is ${fields.job_workflow_ref}, and a listed build is signed by ` +
        `${expected}<ref>. gh was asked for that workflow, so a value that disagrees means the ` +
        "certificate and the verification policy are reading two different fields.",
      );
    }
  }

  // .11 — a self-hosted runner is a runner the registry cannot reason about.
  if (fields.runner_environment !== null && fields.runner_environment !== "github-hosted") {
    invalid(
      `runner_environment (.11) is ${JSON.stringify(fields.runner_environment)} and a listed build runs ` +
      "`github-hosted`. A self-hosted runner is a machine the registry knows nothing about.",
    );
  }

  // .14 — the ref that built it is the tag being listed.
  if (fields.ref !== null && tag) {
    const expected = `refs/tags/${tag}`;
    if (fields.ref !== expected) {
      invalid(
        `ref (.14) is ${JSON.stringify(fields.ref)} and this submission names ${tag}, so the bytes were ` +
        `built from ${expected.startsWith("refs/tags/") ? "another ref" : "elsewhere"}. A release is listed ` +
        "from the tag its artifacts were built at.",
      );
    }
  }

  // .20 — a push of that tag, not a dispatch somebody typed.
  if (fields.event_name !== null && fields.event_name !== "push") {
    invalid(
      `event_name (.20) is ${JSON.stringify(fields.event_name)} and a listed build is produced by a ` +
      "`push` of the tag. A `workflow_dispatch` build is one somebody started by hand against an " +
      "arbitrary ref.",
    );
  }

  // .13 and .15/.17 are shaped here even though they are compared elsewhere: a
  // value of the wrong shape is a broken certificate wherever it is read.
  if (fields.sha !== null && !SHA1_RE.test(fields.sha)) {
    invalid(`sha (.13) is ${JSON.stringify(fields.sha)}, which is not a 40-hex commit`);
  }
  for (const name of ["repository_id", "repository_owner_id"]) {
    if (fields[name] !== null && !BASE10_RE.test(fields[name])) {
      invalid(`${name} (${FULCIO_OIDS[name]}) is ${JSON.stringify(fields[name])}, which is not a base-10 id`);
    }
  }
  if (fields.source_repository_uri !== null && repoFromUri(fields.source_repository_uri) === null) {
    invalid(
      `source_repository_uri (.12) is ${JSON.stringify(fields.source_repository_uri)}, which is not ` +
      "`https://github.com/<owner>/<name>` — and .12 is the name BOT-21 writes into the listing.",
    );
  }

  return findings;
}

/**
 * ID-28's cross-bundle rule: the bundles of one release agree, or none of them
 * is usable.
 *
 * ID-28 names `.13`, `.14`, `.15` and `.17`. `.12` is added here and flagged
 * for the contract (B-T1.1): two bundles of one release naming two source
 * repositories is the same failure as two naming two repository ids, and .12
 * is the field BOT-21 writes into the listing.
 *
 * **Today's catalogue cannot produce this, and that is measured, not assumed.**
 * B-T1.2 found ONE bundle per RELEASE, not per artifact: the six listings that
 * ship two artifacts verify both against the same attestation, which carries
 * both as subjects, so the two per-file JSON outputs are byte identical. There
 * is no tree a reader could point this at to see it fire. It is a fixture-only
 * canary until a release publishes two separate runs, and anybody who "tests
 * it against the real catalogue" will conclude, wrongly, that it does nothing.
 *
 * @param {{where: string, fields: Record<string, string|null>}[]} bundles
 */
export function checkBundlesAgree(bundles) {
  const findings = [];
  if (bundles.length < 2) return findings;
  const compared = ["sha", "ref", "repository_id", "repository_owner_id", "source_repository_uri"];
  const [first, ...rest] = bundles;
  for (const b of rest) {
    for (const name of compared) {
      if (first.fields[name] === b.fields[name]) continue;
      findings.push({
        level: "error",
        code: "E_ATTESTATION_INVALID",
        where: b.where,
        message:
          `${first.where} attests ${name} (${FULCIO_OIDS[name]}) ${JSON.stringify(first.fields[name])} and ` +
          `${b.where} attests ${JSON.stringify(b.fields[name])}. One release is one build of one tree; two ` +
          "bundles of it disagreeing about where it came from means at least one of them is not this release.",
      });
    }
  }
  return findings;
}
