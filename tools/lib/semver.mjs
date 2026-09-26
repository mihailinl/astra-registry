// Just enough semver to order releases and reject nonsense. No dependency.
// Grammar per semver.org 2.0.0, plus one rule semver.org does not have: a
// length (contract §0.7, since 2.16.0).

const GRAMMAR =
  /(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?/
    .source;

/**
 * The longest version this registry admits, pre-release and build included.
 *
 * Contract §0.7's version row, since 2.16.0. The plugins service refuses
 * `len() > 256` before it splits a version (minice-e4, 2026-09-25), and a
 * record on `main` is write-once, so a version one character longer would be
 * a record the service could never mirror, for good. The grammar is ASCII, so
 * characters, UTF-16 units and bytes are one count here.
 */
export const SEMVER_MAX_LENGTH = 256;

/**
 * The grammar with the bound in front of it, as one pattern. The bound is a
 * lookahead inside the pattern, not a length test beside it, because four bot
 * modules (`bot/baseline.mjs`, `bot/export-issues.mjs`, `bot/lib/decisions.mjs`,
 * `bot/lib/service-decide.mjs`) compile this string themselves and never call
 * parseSemver. A bound in the function alone would reach none of them. The
 * schemas say the same bound as `maxLength`, and tools/selftest/validation.mjs
 * finds every schema member that carries a version and holds it to 256.
 */
export const SEMVER_PATTERN = `^(?=.{0,${SEMVER_MAX_LENGTH}}$)${GRAMMAR}$`;

const RE = new RegExp(SEMVER_PATTERN);

export function parseSemver(v) {
  const m = typeof v === "string" ? RE.exec(v) : null;
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ? m[4].split(".") : [],
    build: m[5] ?? null,
  };
}

function comparePre(a, b) {
  // A version with a prerelease has lower precedence than one without.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    } else if (nx !== ny) {
      return nx ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/** -1 / 0 / 1, build metadata ignored (semver.org §10). */
export function compareSemver(a, b) {
  const x = parseSemver(a);
  const y = parseSemver(b);
  if (!x || !y) throw new Error(`not a semver: ${!x ? a : b}`);
  for (const k of ["major", "minor", "patch"]) {
    if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  }
  return comparePre(x.prerelease, y.prerelease);
}
