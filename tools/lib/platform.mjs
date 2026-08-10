// The platform vocabulary, in one place.
//
// The same three strings have to mean the same thing in four programs: the
// CLI's `--target` (AstraPlugins astra-plugin-cli), the bundle's
// `MANIFEST.platform` (an {os, arch} pair, not a key), this registry's artifact
// keys, and the daemon's platform lookup (Astra registry_client.rs). Nothing in
// any type system connects them, which is exactly how a macOS host ended up
// resolving to `linux-x64` and downloading an ELF. So: one table, and a
// conversion that FAILS on anything not in it rather than falling through to a
// plausible-looking default.

export const SUPPORTED_KEYS = ["linux-x64", "windows-x64", "noarch"];

// Reserved in the schema so nobody else claims the names, refused in practice:
// Astra's release workflow ships no daemon for these hosts.
export const RESERVED_KEYS = ["linux-arm64", "windows-arm64", "macos-x64", "macos-arm64"];

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
