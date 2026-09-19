// Two helpers the decision and the SLA both need, in one place so that neither
// owns the other.
//
// NOT re-exported by `bot/lib/policy.mjs`: these were never part of that
// module's public surface, and the split is only honest if it keeps the same
// 26 exports it had before. `tools/selftest.mjs` asserts that count.

export const HOUR_MS = 3600 * 1000;
export const iso = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;
