// The platform vocabulary, in one place.
//
// The same four strings have to mean the same thing in four programs: the
// CLI's `--target` (AstraPlugins astra-plugin-cli), the bundle's
// `MANIFEST.platform` (an {os, arch} pair, not a key), this registry's artifact
// keys, and the daemon's platform lookup (Astra registry_client.rs). Nothing in
// any type system connects them, which is exactly how a macOS host ended up
// resolving to `linux-x64` and downloading an ELF. So: one table, and a
// conversion that FAILS on anything not in it rather than falling through to a
// plausible-looking default.

// `macos-arm64` since 2026-11-10: Astra main carries the crate's mapping for
// it (`platform_key_for("macos", "aarch64")`) and AstraPlugins' CLI builds for
// it, so a Mac on Apple silicon is a host — and until this list said so, a
// Mac-native bundle was refused at ingest and its version record by the
// validator. (A noarch plugin installs there through FLAT_PROJECTION_KEYS's
// fallback below, which needs nothing from this list.)
export const SUPPORTED_KEYS = ["linux-x64", "windows-x64", "macos-arm64", "noarch"];

// The keys a noarch artifact is ALSO written under in the catalogue's flat
// `platform_downloads` (tools/build-index.mjs): the hosts a daemon that reads
// only the flat fields runs on. FROZEN, and not SUPPORTED_KEYS minus `noarch`.
// Every host added after `releases[]` existed has only daemons that resolve
// their artifact from `releases[].artifacts` with the noarch fallback (Astra
// `RegistryRelease::artifact_for`: its own key, else `noarch`; the flat path
// `resolve_download_url` falls back to `download_url`). So a Mac on Apple
// silicon installs a noarch plugin with no `macos-arm64` row here, and adding
// a host does not move the catalogue at an unchanged serial (TRUST-28).
export const FLAT_PROJECTION_KEYS = ["linux-x64", "windows-x64"];

// Reserved in the schema so nobody else claims the names, refused in practice:
// Astra's release workflow ships no daemon for these hosts (Intel Macs, and
// arm64 Linux and Windows). `tools/validate.mjs`
// refuses an artifact under one of them by reading this list, and knows the
// vocabulary as SUPPORTED_KEYS and this together; until 2026-09-22 it kept two
// literals of its own and nothing at run time read this one.
export const RESERVED_KEYS = ["linux-arm64", "windows-arm64", "macos-x64"];

const FROM_MANIFEST = new Map([
  ["linux/x86_64", "linux-x64"],
  ["windows/x86_64", "windows-x64"],
  ["any/any", "noarch"],
  ["linux/aarch64", "linux-arm64"],
  ["windows/aarch64", "windows-arm64"],
  ["macos/x86_64", "macos-x64"],
  ["macos/aarch64", "macos-arm64"],
]);

/**
 * MANIFEST.json's {os, arch} -> the registry's platform key.
 * @returns {string|null} null when the pair has no key at all
 */
export function platformKeyFromManifest(platform) {
  if (!platform || typeof platform !== "object") return null;
  return FROM_MANIFEST.get(`${platform.os}/${platform.arch}`) ?? null;
}
