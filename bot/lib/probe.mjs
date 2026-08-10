// Talking to the Rust half.
//
// `bot/manifest-probe` links `astra-plugin-manifest` — the crate the DAEMON
// parses `plugin.toml` with — and answers one JSON object per bundle. This
// module finds it, feeds it, and refuses to guess when it is not there.
//
// **A missing probe is a failed run, not a skipped check.** The alternative is
// a bot that quietly stops validating manifests on a runner where the build
// step failed, and reports success. `E_PROBE_UNAVAILABLE` is an error level for
// that reason, and its remedy says plainly that it is the registry's bug rather
// than the author's.
//
// Nothing is written to disk on the way: `plugin.toml` and `MANIFEST.json` are
// lifted out of the archive in memory and handed over on stdin. A hostile
// bundle never reaches a filesystem here.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BOT_DIR = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/** Where the compiled probe might be, best first. */
export function probeCandidates(botDir = BOT_DIR) {
  const explicit = process.env.ASTRA_MANIFEST_PROBE;
  const exe = process.platform === "win32" ? ".exe" : "";
  return [
    explicit,
    path.join(botDir, "manifest-probe", "target", "release", `astra-manifest-probe${exe}`),
    path.join(botDir, "manifest-probe", "target", "debug", `astra-manifest-probe${exe}`),
  ].filter(Boolean);
}

export function findProbe(botDir = BOT_DIR) {
  for (const c of probeCandidates(botDir)) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

/**
 * @param {{pluginToml: string, manifestJson?: string|null, hostAstraVersion?: string|null,
 *          botDir?: string}} opts
 * @returns {Promise<{findings: {level: string, code: string, message: string}[], manifest: object|null}>}
 */
export async function runProbe(opts) {
  const botDir = opts.botDir ?? BOT_DIR;
  const bin = findProbe(botDir);
  if (!bin) {
    return {
      findings: [{
        level: "error",
        code: "E_PROBE_UNAVAILABLE",
        message:
          "the manifest probe is not built, so plugin.toml was parsed by nothing. Build it with " +
          "`bot/manifest-probe/link-deps.sh && cargo build --release --manifest-path " +
          "bot/manifest-probe/Cargo.toml`. Looked in: " +
          probeCandidates(botDir).join(", "),
      }],
      manifest: null,
    };
  }

  const request = JSON.stringify({
    plugin_toml: opts.pluginToml,
    manifest_json: opts.manifestJson ?? null,
    host_astra_version: opts.hostAstraVersion ?? null,
  });

  const { stdout, error } = await new Promise((resolve) => {
    const child = execFile(bin, [], { maxBuffer: 8 * 1024 * 1024, timeout: 30_000 },
      (error, stdout, stderr) => resolve({ error, stdout, stderr }));
    child.stdin.end(request);
  });

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return {
      findings: [{
        level: "error",
        code: "E_PROBE_UNAVAILABLE",
        message: `the manifest probe produced no readable answer${error ? ` (${error.message})` : ""}`,
      }],
      manifest: null,
    };
  }

  return { findings: parsed.findings ?? [], manifest: parsed.manifest ?? null };
}
