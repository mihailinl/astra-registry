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
 *          command?: string}} spec
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
    permissions_hash: permissionsHash(permissions),
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

  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return writeZip([{ name: "MANIFEST.json", data: manifestBytes, mode: 0o644 }, ...payload]);
}

/**
 * A GitHub that answers from a table instead of the network.
 *
 * Written as one object so a test says what the world looks like and then asks
 * one question about it — rather than stubbing four functions and hoping they
 * agree with each other about, say, the asset's size.
 */
export function fakeGitHub({ repo, tag, assets, author = "a-stranger" }) {
  const prefix = `https://github.com/${repo}/releases/download/${tag}/`;
  const table = new Map(
    assets.map((a) => [a.url ?? `${prefix}${a.name}`, a.bytes]),
  );
  return {
    release: {
      tag_name: tag,
      published_at: "2026-08-10T09:00:00Z",
      target_commitish: "a".repeat(40),
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
export function fakeGh({
  repo,
  signerDigest,
  subjectDigest,
  signerUri,
  certRepo = null,
  fail = null,
  signerWorkflow = FIXTURE_SIGNER_WORKFLOW,
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
    return {
      stdout: JSON.stringify([{
        verificationResult: {
          signature: {
            certificate: {
              buildSignerURI: signerUri ?? `https://github.com/${signerWorkflow}@refs/heads/main`,
              buildSignerDigest: signerDigest,
              sourceRepositoryURI: `https://github.com/${certRepo ?? repo}`,
              sourceRepositoryDigest: "b".repeat(40),
              runInvocationURI: `https://github.com/${repo}/actions/runs/1`,
            },
          },
          statement: {
            _type: "https://in-toto.io/Statement/v1",
            subject: [{ name: "bundle", digest: { sha256: subjectDigest } }],
            predicate: { buildDefinition: { externalParameters: {} } },
          },
        },
      }]),
    };
  };
}

/** An ownership prover that says yes, or says no with a reason. */
export function fakeOwnership(ok = true, method = "collaborator-permission") {
  return async ({ repo, login }) =>
    ok
      ? { ok: true, method, detail: `GitHub reports @${login} has \`admin\` on ${repo}`, tried: [] }
      : { ok: false, method: null, detail: `nothing proves @${login} controls ${repo}`, tried: [] };
}
