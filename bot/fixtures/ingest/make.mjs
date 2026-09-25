// The corpus the ingest pipeline is tested against.
//
// Two sources, deliberately:
//
//   * `tests/vectors/` — the 27 cross-repo golden bundles, vendored from
//     AstraPlugins/testdata/bundles. Those are the archive-shaped failures, and
//     they are shared with the CLI's suite and the daemon's, so a disagreement
//     between the three implementations shows up as a red build in whichever
//     one drifted. bot/tests/ingest.test.mjs runs the WHOLE pipeline over every
//     one of them and asserts the verdict already recorded in `vectors.json`.
//
//   * this file — the failures the golden set does not and should not carry,
//     because they are not properties of an archive: a squatted name, a
//     trademark, a licence nobody allowed, a bidi override in a display name,
//     an undeclared host RPC, a version that goes backwards. Each is built by
//     mutating one field of a bundle that is otherwise conforming, so the test
//     that rejects it is a test about that field and nothing else.
//
// Everything here is generated in memory and never written anywhere. No
// synthetic fixture is committed: a `.astraplugin` in git is bytes nobody
// re-derives, and this file is shorter than the bundles it produces. The golden
// corpus is the exception, and it is committed precisely because three
// repositories have to agree on those exact bytes.

import crypto from "node:crypto";

import { writeZip } from "../../../tools/lib/zip.mjs";
import { permissionsHash } from "../../lib/bundle.mjs";

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

/** A tiny stand-in for a compiled plugin. Not an ELF; nothing executes it. */
const BINARY = Buffer.from("#!/usr/bin/env node\nprocess.exit(0);\n", "utf8");

/**
 * Build one `.astraplugin`.
 *
 * @param {{id?: string, name?: string, version?: string, license?: string,
 *          description?: string, author?: string, capabilities?: string[],
 *          permissions?: object, os?: string, arch?: string,
 *          extraFiles?: {name: string, data: Buffer|string, mode?: number}[],
 *          command?: string, permissionsHash?: string,
 *          manifestBytes?: (bytes: Buffer) => Buffer}} spec
 *
 * `permissionsHash` and `manifestBytes` are the two ways to build a manifest
 * no packer writes: a hand-made one, whose author computed the hash over
 * whatever canonical form they liked, and one whose bytes were edited after it
 * was serialised. The first is how a `\ud800` escape in a permission reason
 * arrives with a matching hash; the second is how a literal lone surrogate
 * (`ED A0 80`) arrives at all, since encoding a JavaScript string never writes
 * those bytes.
 */
export function makeBundle(spec = {}) {
  const id = spec.id ?? "dice-roller";
  const name = spec.name ?? "Dice Roller";
  const version = spec.version ?? "0.2.0";
  const license = spec.license ?? "MIT";
  const description = spec.description ?? "Rolls dice when you ask it to.";
  const author = spec.author ?? "A Stranger";
  const capabilities = spec.capabilities ?? ["tools"];
  const permissions = spec.permissions ?? {};
  const command = spec.command ?? "./bin/plugin";

  const toml = Buffer.from(
    [
      "[plugin]",
      `id = ${JSON.stringify(id)}`,
      `name = ${JSON.stringify(name)}`,
      `version = ${JSON.stringify(version)}`,
      ...(spec.minAstraVersion ? [`min_astra_version = ${JSON.stringify(spec.minAstraVersion)}`] : []),
      `description = ${JSON.stringify(description)}`,
      `author = ${JSON.stringify(author)}`,
      `license = ${JSON.stringify(license)}`,
      "",
      "[entry]",
      `command = ${JSON.stringify(command)}`,
      "",
      "[capabilities]",
      ...capabilities.map((c) => `${c} = true`),
      "",
      "[platform]",
      `os = [${JSON.stringify(spec.os ?? "linux")}]`,
      `arch = [${JSON.stringify(spec.arch ?? "x86_64")}]`,
      "",
    ].join("\n"),
    "utf8",
  );

  const payload = [
    { name: "bin/plugin", data: BINARY, mode: 0o755 },
    { name: "plugin.toml", data: toml, mode: 0o644 },
    ...(spec.extraFiles ?? []),
  ].sort((a, b) => (a.name < b.name ? -1 : 1));

  const manifest = {
    schema: "astra.bundle/2",
    plugin_id: id,
    version,
    platform: { os: spec.os ?? "linux", arch: spec.arch ?? "x86_64" },
    protocol: 2,
    min_astra_version: "",
    capabilities,
    permissions,
    permissions_hash: spec.permissionsHash ?? permissionsHash(permissions),
    entry: { command, args: [] },
    files: payload.map((f) => {
      const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, "utf8");
      return {
        path: f.name,
        sha256: sha256(data),
        size: data.length,
        mode: `0${(f.mode ?? 0o644).toString(8)}`,
      };
    }),
  };

  // A bundle from before `permissions` was a manifest member. `permissions_hash`
  // stays, because sha256("{}") is what an absent member hashes to — spec §7,
  // `null` and `{}` are the same value. This is the only way to build the third
  // state the daemon distinguishes, and it exists so a test can assert that
  // deriving normalises it rather than passing the absence through.
  if (spec.omitPermissionsMember) delete manifest.permissions;

  const serialised = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const manifestBytes = spec.manifestBytes ? spec.manifestBytes(serialised) : serialised;
  return writeZip([{ name: "MANIFEST.json", data: manifestBytes, mode: 0o644 }, ...payload]);
}

/**
 * A GitHub that answers from a table instead of the network.
 *
 * Written as one object so a test says what the world looks like and then asks
 * one question about it — rather than stubbing four functions and hoping they
 * agree with each other about, say, the asset's size.
 */
export function fakeGitHub({ repo, tag, assets, author = "a-stranger", commit = FIXTURE_COMMIT }) {
  const prefix = `https://github.com/${repo}/releases/download/${tag}/`;
  const table = new Map(
    assets.map((a) => [a.url ?? `${prefix}${a.name}`, a.bytes]),
  );
  return {
    release: {
      tag_name: tag,
      published_at: "2026-08-10T09:00:00Z",
      target_commitish: commit,
      author: { login: author },
      assets: assets.map((a) => ({
        name: a.name,
        // `apiSize` lets a test say the release API and the bytes disagree,
        // which is what an asset replaced after publication looks like.
        size: a.apiSize ?? a.bytes.length,
        browser_download_url: a.url ?? `${prefix}${a.name}`,
      })),
    },
    async fetchRelease(r, t) {
      if (r !== repo || t !== tag) throw new Error(`no release tagged ${t} in ${r} (404)`);
      return this.release;
    },
    async headAsset(url) {
      const bytes = table.get(url);
      if (!bytes) throw new Error(`HTTP 404 for HEAD ${url}`);
      // `headSize` lets a test say "the origin claims this is enormous" without
      // producing 256 MiB of it. The size cap is enforced from the HEAD for
      // exactly this reason: a bot that has to download something to find out
      // it is too big has no size cap.
      const declared = assets.find((a) => (a.url ?? `${prefix}${a.name}`) === url)?.headSize;
      return { size: declared ?? bytes.length, finalUrl: url, etag: null };
    },
    async downloadAsset(url) {
      const bytes = table.get(url);
      if (!bytes) throw new Error(`HTTP 404 for ${url}`);
      return bytes;
    },
  };
}

/**
 * The commit the fixture release was cut at AND the commit its attestation
 * names, because in a healthy release those are the same commit — the listing
 * records it as provenance and every relative README image is pinned to it.
 * They used to be two different strings here ("aaa…" and "bbb…"), which is how
 * a whole suite stayed green while nothing compared them.
 */
export const FIXTURE_COMMIT = "a".repeat(40);

/** The reusable workflow the fixtures are built by. The real filename. */
export const FIXTURE_SIGNER_WORKFLOW =
  "mihailinl/AstraPlugins/.github/workflows/plugin-release.yml";

/**
 * A `gh attestation verify` that answers the way GitHub does.
 *
 * `signerDigest` is what the whole check turns on: the resolved commit of the
 * reusable workflow. A test that wants `E_WORKFLOW_NOT_ALLOWED` changes this
 * one string and nothing else.
 *
 * **`--signer-workflow` is read, not ignored.** It used to be: this stub looked
 * at `--repo` and nothing else, so the 95-test ingest suite and the 45-test
 * policy suite were both green against a `DEFAULT_SIGNER_WORKFLOW` that pointed
 * at a workflow file which does not exist. Real `gh` matches attestations on
 * that path and exits non-zero when none match, so the stub does too — and a
 * transposed filename is now a test failure rather than a production outage.
 */
/**
 * The two ids the fixture certificate carries, as base-10 STRINGS.
 *
 * Strings here and not numbers on purpose: gh prints them as strings, the
 * registry records them as strings (SCOPE-5), and a fixture that used numbers
 * would be a fixture in which the one hazard those rules exist for — a
 * repository id past 2^53 losing its last digits in `JSON.parse` — cannot
 * happen. One test below hands the bot a number deliberately.
 */
export const FIXTURE_REPOSITORY_ID = "1203676452";
export const FIXTURE_OWNER_ID = "193032699";

/** ID-28's ten, by the name the contract's table gives each OID. */
const CERT_KEY_BY_FIELD = {
  job_workflow_ref: "buildSignerURI",
  job_workflow_sha: "buildSignerDigest",
  runner_environment: "runnerEnvironment",
  source_repository_uri: "sourceRepositoryURI",
  sha: "sourceRepositoryDigest",
  ref: "sourceRepositoryRef",
  repository_id: "sourceRepositoryIdentifier",
  repository_owner_id: "sourceRepositoryOwnerIdentifier",
  event_name: "buildTrigger",
  run: "runInvocationURI",
};

const OID_BY_FIELD = {
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
};

// ── a certificate, in DER, for the fallback nothing in the catalogue needs ──

function derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function encodeOid(dotted) {
  const parts = dotted.split(".").map(Number);
  const body = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [];
    let v = part;
    do {
      chunk.unshift(v & 0x7f);
      v >>>= 7;
    } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    body.push(...chunk);
  }
  return tlv(0x06, Buffer.from(body));
}

/**
 * A certificate-shaped DER carrying Fulcio extensions and nothing else.
 *
 * Not a valid X.509 certificate and not signed by anything — it is bytes in
 * the SHAPE `bot/lib/certificate.mjs` walks: `SEQUENCE { SEQUENCE { …, [3]
 * SEQUENCE OF Extension } }`, each extension being `SEQUENCE { OID, OCTET
 * STRING { UTF8String } }`, which is Fulcio's v2 encoding for `.9` and up.
 * Nothing here verifies a signature, so nothing here needs one; what is being
 * tested is the reader.
 *
 * @param {Record<string, string>} fields field name → value
 */
export function fakeCertificateDer(fields) {
  const extensions = Object.entries(fields)
    .filter(([name, value]) => OID_BY_FIELD[name] && typeof value === "string")
    .map(([name, value]) => tlv(0x30, Buffer.concat([
      encodeOid(OID_BY_FIELD[name]),
      tlv(0x04, tlv(0x0c, Buffer.from(value, "utf8"))),
    ])));
  const tbs = tlv(0x30, Buffer.concat([
    tlv(0x02, Buffer.from([0x01])),                    // a member to walk past
    tlv(0xa3, tlv(0x30, Buffer.concat(extensions))),   // [3] extensions
  ]));
  return tlv(0x30, Buffer.concat([tbs, tlv(0x03, Buffer.from([0x00]))]));
}

export function fakeGh({
  repo,
  signerDigest,
  subjectDigest,
  signerUri,
  certRepo = null,
  fail = null,
  signerWorkflow = FIXTURE_SIGNER_WORKFLOW,
  // The commit the CERTIFICATE names (.13). A test that wants
  // `E_RELEASE_COMMIT_MISMATCH` moves this one and leaves the Release alone.
  sourceCommit = FIXTURE_COMMIT,
  // ── the rest of ID-28's ten ─────────────────────────────────────────────
  //
  // Measured, not invented: each default is what B-T1.2's survey read off all
  // 18 bundles on 2026-09-19, and the KEY NAMES are `gh 2.100.0`'s, confirmed
  // against the DER of every bundle. `.9`'s suffix is a 40-hex commit on all
  // 24 artifacts, so the fixture's is too — the bot accepts any suffix (ID-28:
  // "@ any ref") and this fixture must not be why somebody believes otherwise.
  tag = null,
  ref = undefined,
  runnerEnvironment = "github-hosted",
  eventName = "push",
  repositoryId = FIXTURE_REPOSITORY_ID,
  repositoryOwnerId = FIXTURE_OWNER_ID,
  runId = "1",
  /** Field NAMES to leave out of the certificate — ID-28's missing row. */
  omitFields = [],
  /** Field names to put in the DER ONLY, never in gh's JSON. */
  derOnlyFields = [],
  /** Replace the certificate object wholesale, for a malformed value. */
  certificateOverrides = {},
  /** Extra attestations in the array — another file of the same release. */
  extraResults = [],
  /** Put a complete, correct build predicate beside the certificate. */
  predicateFacts = false,
  /** A predicate and NO certificate at all — the pre-B-T1.1 fallback's food. */
  predicateOnly = false,
}) {
  return async (args) => {
    if (fail) {
      const e = new Error(fail);
      e.stderr = fail;
      throw e;
    }
    const idx = args.indexOf("--repo");
    const asked = idx >= 0 ? args[idx + 1] : null;
    if (asked !== repo) {
      const e = new Error(`no attestations found for ${asked}`);
      e.stderr = `no attestations found for ${asked}`;
      throw e;
    }
    const widx = args.indexOf("--signer-workflow");
    const askedWorkflow = widx >= 0 ? args[widx + 1] : null;
    if (askedWorkflow !== null && askedWorkflow !== signerWorkflow) {
      const message =
        `no attestations found for ${asked} matching --signer-workflow ` +
        `${askedWorkflow} (this build was signed by ${signerWorkflow})`;
      const e = new Error(message);
      e.stderr = message;
      throw e;
    }

    const fields = {
      job_workflow_ref: signerUri ?? `https://github.com/${signerWorkflow}@${"c".repeat(40)}`,
      job_workflow_sha: signerDigest,
      runner_environment: runnerEnvironment,
      source_repository_uri: `https://github.com/${certRepo ?? repo}`,
      sha: sourceCommit,
      ref: ref ?? (tag ? `refs/tags/${tag}` : null),
      repository_id: repositoryId,
      repository_owner_id: repositoryOwnerId,
      event_name: eventName,
      run: `https://github.com/${repo}/actions/runs/${runId}`,
    };

    const certificate = {};
    for (const [name, value] of Object.entries(fields)) {
      if (omitFields.includes(name) || derOnlyFields.includes(name)) continue;
      if (value === null || value === undefined) continue;
      certificate[CERT_KEY_BY_FIELD[name]] = value;
    }
    Object.assign(certificate, certificateOverrides);

    // The DER gh embeds beside its JSON. It carries every field the JSON does
    // — as the real one does — plus whichever fields a test asked to hide from
    // the JSON, which is the only way the fallback branch is ever reached.
    const derFields = {};
    for (const [name, value] of Object.entries(fields)) {
      if (omitFields.includes(name) || value === null || value === undefined) continue;
      derFields[name] = String(value);
    }

    const result = {
      verificationResult: {
        signature: { certificate },
        statement: {
          _type: "https://in-toto.io/Statement/v1",
          subject: [{ name: "bundle", digest: { sha256: subjectDigest } }],
          // The predicate a builder composes. Nothing in the bot may read an
          // identity fact out of it (ID-28), and a fixture that carries a
          // richer one than the certificate is how that is proved.
          predicate: predicateOnly || predicateFacts
            ? {
              buildDefinition: {
                externalParameters: { workflow: { repository: `https://github.com/${repo}`, path: signerWorkflow } },
                resolvedDependencies: [{ digest: { gitCommit: sourceCommit } }],
              },
              runDetails: { metadata: { invocationId: `https://github.com/${repo}/actions/runs/${runId}` } },
            }
            : { buildDefinition: { externalParameters: {} } },
        },
      },
      attestation: {
        bundle: {
          verificationMaterial: {
            certificate: { rawBytes: fakeCertificateDer(derFields).toString("base64") },
          },
        },
      },
    };
    if (predicateOnly) delete result.verificationResult.signature;
    if (predicateOnly) delete result.attestation;

    return { stdout: JSON.stringify([...extraResults, result]) };
  };
}

/** An ownership prover that says yes, or says no with a reason. */
export function fakeOwnership(ok = true, method = "collaborator-permission") {
  return async ({ repo, login }) =>
    ok
      ? { ok: true, method, detail: `GitHub reports @${login} has \`admin\` on ${repo}`, tried: [] }
      : { ok: false, method: null, detail: `nothing proves @${login} controls ${repo}`, tried: [] };
}
