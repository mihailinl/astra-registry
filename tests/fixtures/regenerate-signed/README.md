# `regenerate-signed` — the no-network fixture tree

Three listings and one publisher record, used by `tools/selftest/regenerate.mjs`
to exercise `tools/regenerate-signed.mjs` end to end without touching this
repository's own history.

**Every listing carries an icon and a README**, and that is the point of the
tree rather than decoration. The no-network claim OPEN-MBE-27 needs is about the
two files a generator reads off disk and inlines into a signed document — a
picture and some prose, the only listing content that is bytes rather than
JSON. A fixture with neither would run the presentation path over nothing and
report a clean bill of health about code it never entered. The selftest asserts
the coverage before it asserts the isolation, so the isolation cannot be proved
over an empty room.

The three are deliberately not alike:

| listing | icon | releases | what it is here for |
|---|---|---|---|
| `fixture-alpha` | `icon.svg` | `0.1.0` yanked, `0.2.0` listed | text bytes inlined; a yanked release that must not appear; a locale block; a publisher badge |
| `fixture-beta` | `icon.png` | `1.4.2` | binary bytes inlined as base64; two platform artifacts |
| `fixture-gamma` | `icon.webp` | `0.9.0`, staging | binary bytes again, and the branch where no flat download URL may be emitted |

**Every record here is one the registry's own judges would accept**, and that
is asserted rather than hoped. `fixture-owner.json` carried `"tier": "community"`
from the day this tree was written until 2026-09-22 — a value
`schema/publisher-v1.json` has never allowed — and the regeneration shipped it
into `signed.publishers`, where `schema/index-v1.json` refuses it as well, with
every test in the module green. A proof about the bytes a generator makes from a
tree no registry could publish is a proof about the wrong tree. So
`tools/selftest/regenerate.mjs` now judges the publisher records with the
function `tools/validate.mjs` runs on `publishers/`, and the regenerated
catalogue with the index schema. The record is `astra_team` because its
evidence is `first-party`, which is what that tier's evidence is.

Nothing here is a real plugin. Every repository named is under
`fixture-owner/`, every URL is on `example.invalid`, and every digest is a
literal nobody can resolve to bytes — a fixture that pointed at a live host
would be a fixture whose result depends on that host being up, which is the
opposite of what this tree is for.

The tree holds no generator code. `tools/selftest/regenerate.mjs` copies
`tools/build-index.mjs`, `tools/lib/` and `bot/lib/` out of this repository's
checkout into the temporary clone it builds, so the fixture is inputs only and
cannot go stale against a generator it does not contain.
