# The ROLL-60 rehearsal series, cut at T0 = 2026-09-26

> **Everything here is signed with the throwaway keys in `../../`, whose
> private halves are committed to a public git repository on purpose.** No
> production daemon trusts these roots, no shipped Astra build can compile them
> in, and nothing a user installs may be signed with them. See
> [`../../README.md`](../../README.md).

This is [`../rehearsal-r2/`](../rehearsal-r2/README.md)'s series, cut again
at a later T0. The generator, the steps, the keys, the signer runs and the
rules are the same. Everything that README says holds here too, with these
differences:

- **T0 is `2026-09-26T00:00:00Z`.** Every `now`, every commit date and the
  fixture advisories' `published` date move with it, so every sha differs.
  trust.json and root.json do not. Their dates are fixed, not offsets from T0,
  so they are byte for byte the first cut's.
- **The withdrawal lists expire on 2026-10-03**, from 00:00Z for step 0 to
  11:00Z for step 5. After that nothing here can be served again.
- **It is served on `mihailinl/astra-registry-canary-2` only.**
  `tools/testkeys/rehearsal-push.mjs` refuses this cut on the first canary and
  the first cut here. The two are told apart by name (`--fixtures`), and a
  cut's commits are foreign to the other canary's `signed`.

## Why a second cut

The first cut's lists expire on 2026-09-29. The walk it was made for slipped
towards that date. A `signed` that has served a step cannot be rewound
(SERVE-18). The plugins service compiles the branch name `signed` in, so a
second branch in the same repository is not an option. So a slip past
2026-09-29 needs the same series at a later T0, on a `signed` that has never
carried the first. That is a second repository. The test roots are the same
deterministic pair, so the service's three root-set images do not change.

The first cut stays where it was, unchanged, as the record of what the first
canary serves.

```sh
node tools/testkeys/make-rehearsal-r2.mjs --check --fixtures rehearsal-r2b
node tools/testkeys/rehearsal-push.mjs --list    # this cut on canary-2, the default
```
