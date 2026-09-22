# The ROLL-60 rehearsal series

> **Everything here is signed with the throwaway keys in `../../`, whose
> private halves are committed to a public git repository on purpose.** No
> production daemon trusts these roots, no shipped Astra build can compile them
> in, and nothing a user installs may be signed with them. See
> [`../../README.md`](../../README.md).

ROLL-60 is an R2 exit condition:

> R2 MUST NOT exit until a staging service on `tools/testkeys` roots, and a
> debug 0.2.x daemon built with `insecure-test-trust-roots` and pointed at it,
> accept a testkey-signed trust.json at serial + 1 and a new index key under
> SERVE-30, with a dual-signed withdrawal list that an idle daemon, one that
> never fetches the catalogue, also accepts; and the staging service accepts a
> root.json change under SERVE-16 and SERVE-92 while the daemon keeps accepting
> the trust.json and catalogue that follow.

**This directory is the registry's half of it (RC-R2-5), and only that half.**
The walk itself — the staging service, the debug build, the idle daemon — is
the client plan's R2 daemon walk, recorded as `astra.2a`. Until these bytes
existed, that walk had nothing to accept.

## Generated, never edited

```sh
node tools/testkeys/make-rehearsal-r2.mjs            # rewrite this directory
node tools/testkeys/make-rehearsal-r2.mjs --check    # verify the committed bytes, write nothing
node tools/testkeys/make-rehearsal-r2.mjs --print-commands
```

Every document is produced by **the real signer** — `tools/signer/run.mjs
--step sign`, the program `sign.yml` runs, driven with `--test-key` — against a
throwaway registry with real git history. A rotation is not a property of a
document: which key may sign the catalogue yet, which keys sign the list and in
what order, whether a document may be carried, and whether every document
verifies against the trust.json beside it are decisions `signRun` makes about
four files at once, out of `signed`'s own history. A fixture assembled by
calling a signature function five times would agree with itself and say nothing
about the program that will do this for real.

`manifest.json` records, per step, the command that produced it, the signer's
own record, and what the step is for. `tools/selftest/rehearsal-r2.mjs` re-derives
every verdict from the bytes — root keys out of each step's own `root.json`,
index keys out of each step's own `trust.json` — so the suite is not reading the
generator's opinion back to itself.

## The keys

| role | published `key_id` | bytes |
|---|---|---|
| root, active at the start | `TEST-ONLY-DO-NOT-TRUST-root-a` | its own |
| root, active after the root change | `TEST-ONLY-DO-NOT-TRUST-root-b` | its own |
| index, outgoing | **`astra-index-2026a`** | `TEST-ONLY-DO-NOT-TRUST-index-2026a` |
| index, incoming | `TEST-ONLY-DO-NOT-TRUST-index-2026b` | its own |

**The outgoing key's id is borrowed, and it has to be.**
`tools/signer/key-window.mjs`'s `WINDOW_EXEMPT_KEY_IDS` is keyed on the literal
string `astra-index-2026a`. Without the exemption the run that *creates*
`signed` is the one run that cannot succeed: no commit has delegated anything,
so every key's window reads as having started this instant, so the catalogue may
not be signed, so there is nothing to carry, so the branch is never created.
`tools/selftest/signer-run.mjs`'s `BOOTSTRAP` borrows the same id for the same
reason. The public key under that id is a **test** key's, and the trust.json
carrying it is signed by a **test** root, so no production daemon will look at
it twice.

## The series

Two lines. `rotation/` is linear; `compromise/` forks from
`rotation/02-mid-window` and is one commit (plus one record of a run that makes
none).

| step | `now` | mode | trust.json | catalogue signed by | list signed by |
|---|---|---|---|---|---|
| `rotation/00-baseline` | T0 | normal | serial 2, delegates the outgoing key | outgoing | outgoing |
| `rotation/01-delegate` | T0+1h | normal | **serial 3 — serial + 1**, delegates both | outgoing alone | **both, outgoing first** |
| `rotation/02-mid-window` | T0+4h | normal | serial 3 | outgoing alone (3 h < 7) | both |
| `compromise/00-drop-2026a` | T0+5h | **compromise** | **serial 4 — serial + 2**, drops the outgoing key | **incoming, re-signed** | incoming alone |
| `compromise/01-trust-only-blocked` | T0+5h | compromise | serial 4 | — *nothing is committed* | — |
| `rotation/03-window-open` | T0+9h | normal | serial 3 | **both** (8 h ≥ 7) | both |
| `rotation/04-root-change` | T0+10h | normal | serial 3, re-signed by root-b | both | both |
| `rotation/05-after-root` | T0+11h | normal | serial 3 | both | both |

T0 is `2026-09-22T00:00:00Z`. Each step directory holds D2's four documents
under `registry/v1/`, the `commit-message.txt` that step's `signed` commit
carried, and `record.json`, the signer's own account of the run.

### What each part of the series is for

- **`01-delegate` is ROLL-60's "trust.json at serial + 1 and a new index key
  under SERVE-30".** The list is dual-signed with the outgoing signature
  **first**, because a shipped client checks only the first signature that
  verifies against its own window.
- **`02-mid-window` and `03-window-open` are the seven hours.** Three hours in
  the catalogue is still signed by the outgoing key alone; eight hours in it
  carries both. A rehearsal that only showed one side of that boundary would not
  show the rule.
- **The idle daemon** — ROLL-60's "one that never fetches the catalogue" — is a
  client still holding `00-baseline`'s trust.json. Every list in `rotation/`
  verifies for it. That is what the dual signature buys, and it is asserted in
  the selftest.
- **`04-root-change` is SERVE-16 and SERVE-92.** `root.json` drops the retiring
  root, and the trust.json beside it is re-signed by the new active root at an
  **unchanged serial with a byte-identical `signed` payload**, which is the only
  thing SERVE-20 permits at an unchanged serial. `05-after-root` is ROLL-60's
  "the trust.json and catalogue that follow": the daemon keeps accepting them
  because it compiles both test roots and reads `root.json` never.
- **`compromise/00-drop-2026a` is D10, as one commit that verifies whole.**
  trust.json at serial + 2 dropping the outgoing key, a list signed by the
  incoming key alone, and the catalogue **re-signed** with the incoming key in
  that same commit. All three verify under the new trust.json, which is what
  SERVE-15 and SERVE-91 require.

### Why the compromise forks from inside the window, and not after it

Both of D10 step 4's waivers are only load-bearing there. At
`rotation/02-mid-window` the served catalogue is signed by the outgoing key
**alone**, so a carried catalogue would not verify under a trust.json that has
just dropped that key, and SERVE-91 would refuse the whole commit — withholding
the new trust.json and the repaired list along with it, and leaving the
compromised key's last bytes served. Fork after the window instead and the head
is already dual-signed: the carry verifies, nothing refuses it, and the fixture
would demonstrate a rule that cannot bite. That is the case
`tools/signer/key-window.mjs`'s header calls the R9b retirement.

### `compromise/01-trust-only-blocked`: a step with no documents

**D10's own inputs, run as written, commit nothing.** A compromise is repaired
by a root ceremony that publishes a trust.json and nothing else — and on that
Source-Commit neither the catalogue nor the list has changed, so D4 calls both
`unchanged`, `unchanged` re-commits `signed`'s head bytes exactly as a carry
does, those bytes are signed by the key being dropped, and SERVE-95 refuses the
run. D10's "no carry" (`carryCatalogueAllowed`) is consulted only where the
*gates* failed, so it never reaches that path.

That is why `00-drop-2026a`'s Source-Commit also carries D10 step 5's advisory
and a release: those make both documents `changed`. **An operator must not read
that as a property of the procedure.** The blocked run is kept beside it, with
the signer's own record as the evidence, and the selftest asserts it — so the
day the signer or D10 is amended, it goes red and says so.

## Replaying it onto a staging service

The service reads a `signed` branch whose every commit holds D2's four
documents. To replay:

```sh
# one orphan commit per step, in this order, each with the step's four documents
#   rotation/00-baseline
#   rotation/01-delegate
#   rotation/02-mid-window
#   rotation/03-window-open
#   rotation/04-root-change
#   rotation/05-after-root
# and, on a branch forked from rotation/02-mid-window's commit:
#   compromise/00-drop-2026a
```

Each step's `commit-message.txt` is the message that step's commit carried,
trailers included, so `tools/served-set/provenance.mjs` recognises it.
`compromise/01-trust-only-blocked` has no documents and is not replayed; it is a
record.

**SERVE-92's order is the service's, not this directory's.** Before
`rotation/04-root-change` is served, the service build must already compile
`TEST-ONLY-DO-NOT-TRUST-root-b` as its **next** root set, or SERVE-16 refuses
the commit. Only after the service has accepted that commit may it drop the old
set. Steps 1 and 3 of SERVE-92 are the plugins-service plan's.

The debug daemon leg needs `insecure-test-trust-roots`, which compiles **both**
test roots — that is what lets it keep accepting across the root change, and it
is also why the daemon leg cannot show SERVE-16: the daemon reads `root.json`
never.

## What this directory does not prove

- **Nothing here has been served to anything.** These are bytes. ROLL-60 is met
  by a staging service and a debug daemon accepting them, recorded with the
  build tag, profile and run URLs in the ops notes (`astra.2a`; `ops.21`).
- **The compromise series follows D10 *as proposed*.** OPEN-OWNER-25's
  compromise half is open, and the answer is published as SERVE-30's amendment
  G10. `manifest.json`'s `open_questions` records precisely which steps a
  different answer re-cuts.
