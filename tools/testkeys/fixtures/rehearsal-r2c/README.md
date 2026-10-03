# The ROLL-60 rehearsal series, cut at T0 = 2026-10-24

> **Everything here is signed with the throwaway keys in `../../`, whose
> private halves are committed to a public git repository on purpose.** No
> production daemon trusts these roots, no shipped Astra build can compile them
> in, and nothing a user installs may be signed with them. See
> [`../../README.md`](../../README.md).

This is [`../rehearsal-r2/`](../rehearsal-r2/README.md)'s series, cut a third
time. The generator, the steps, the keys, the signer runs and the rules are the
same. Everything that README says holds here too, with these differences:

- **T0 is `2026-10-24T00:00:00Z`.** Every `now`, every commit date and the
  fixture advisories' `published` date move with it, so every sha differs.
  trust.json and root.json do not. Their dates are fixed, not offsets from T0,
  so they are byte for byte the first and second cuts'.
- **The withdrawal lists expire on 2026-10-31**, from 00:00Z for step 0 to
  11:00Z for step 5. That date is `hard_end` in the generator's `REHEARSALS`,
  and the judge holds the lists to it.
- **It is served on `mihailinl/astra-registry-canary-3` only**, the default of
  `tools/testkeys/rehearsal-push.mjs`. The tool refuses this cut on the other
  two canaries and their cuts here.

## Why a third cut, and why its T0 is in the future

The second cut's lists expired on 2026-10-03, before the plugins service's
publisher had served its step 0. The service then asked for a fresh T0 on a
new repository, because a first serve of a fresh step 0 is what ROLL-60's R2
half must show, and canary-2's history would make it a re-serve. It also asked
for a step 0 that still serves on 2026-10-31, because its serve is no earlier
than 2026-10-06.

A list expires `REVOCATION_TTL_DAYS` (7) after the signer run that made it.
That number is production policy, so this cut does not stretch it. The only
way to a hard end of 2026-10-31 is therefore a T0 of 2026-10-24. **Served
before 2026-10-24, every document here is dated after the day it is served:**
`issued_at` 2026-10-24T00:00:00Z on step 0's catalogue and list, and commit
dates to match. The contract bounds `expires_at` (SERVE-22) and has no rule
about an `issued_at` ahead of the reader's clock. Whether the plugins service
accepts one is for the service to say before it serves this.

```sh
node tools/testkeys/make-rehearsal-r2.mjs --check --fixtures rehearsal-r2c
node tools/testkeys/rehearsal-push.mjs --list    # this cut on canary-3, the default
```
