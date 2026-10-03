# The ROLL-60 rehearsal series, cut at T0 = 2026-10-03, re-signed

> **Everything here is signed with the throwaway keys in `../../`, whose
> private halves are committed to a public git repository on purpose.** No
> production daemon trusts these roots, no shipped Astra build can compile them
> in, and nothing a user installs may be signed with them. See
> [`../../README.md`](../../README.md).

This is [`../rehearsal-r2/`](../rehearsal-r2/README.md)'s series, cut a fourth
time. The generator, the steps, the keys, the signer runs and the rules are the
same, and everything that README says holds here too, with these differences:

- **T0 is `2026-10-03T00:00:00Z`.** trust.json and root.json are byte for byte
  the other cuts'.
- **It is served on `mihailinl/astra-registry-canary-4` only**, the default of
  `tools/testkeys/rehearsal-push.mjs`, and **step 0 only.** The tool refuses
  every later step there.
- **Step 0 is kept fresh by a rolling re-sign.** canary-4's hourly workflow
  runs `tools/testkeys/rehearsal-resign.mjs` from this repository at a pinned
  commit. Once step 0's catalogue and list are 20 hours old, the real signer
  re-signs both at their serials, with a fresh `issued_at` and `expires_at`,
  and the tool pushes that one commit onto canary-4's `signed`. So the list
  Pages serves is never more than about a day and a half old. Step 0's own
  list expires on 2026-10-10 (`hard_end`), and the first re-sign replaces it.

## Why a fourth cut

The third cut (`../rehearsal-r2c/`, canary-3) was dated 2026-10-24, so that a
step 0 served from 2026-10-06 would still be valid on 2026-10-31. The plugins
service's publisher refuses it, on purpose: it bounds a list by
`min(issued_at, judged_at) + 8 days`. That bound refuses a list dated after
the day it is read, and it refuses a longer one. So a step 0 the service may
meet on any day has to be fresh on that day. That is a re-sign, which is what
production does, and canary-3 is abandoned.

Every later rotation step's parent is the fixture's step 0, and a re-signed
head is past it. So canary-4 serves ROLL-60's R2 half (one serve of step 0) and
not the rotation. R9a's walk needs a canary of its own.

```sh
node tools/testkeys/make-rehearsal-r2.mjs --check --fixtures rehearsal-r2d
node tools/testkeys/rehearsal-resign.mjs --status    # canary-4's head, its list's age, and Pages
```
