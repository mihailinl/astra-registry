# The signed-set vectors

`signed-set-v1.json` is one corpus of signed documents with their expected
verdicts, read by four programs in three repositories. It exists because
"the registry signs it and the daemon verifies it" is two implementations of
one rule, in two languages, and each side's own test suite can only ever prove
that it agrees with itself.

**It is generated, never edited.** `../regenerate.mjs` writes it from the test
keys in the directory above; `node tools/testkeys/regenerate.mjs --check`
verifies the committed bytes and writes nothing. A hand edit here will be a hand
edit to another repository's fixtures on the day Astra vendors them — which it
does not yet; see *Who reads it*.

```sh
node tools/testkeys/regenerate.mjs          # rewrite the keys and this corpus
node tools/testkeys/regenerate.mjs --check  # verify them, write nothing
```

Everything in it is signed with the TEST keys whose private halves are published
in `../README.md`. Nothing a user will ever install may be signed with them, and
no shipped Astra build can compile them in.

## Who reads it

| reader | where | how it gets the file |
|---|---|---|
| the signer's selftest | `tools/selftest/index-signature.mjs` | imports `loadSignedSetVectors` from `../regenerate.mjs` |
| the ROLL-15 probe | `astra-registry` | the same path in this checkout |
| the plugins service | minice-be | **not yet** — this repository at a commit it will pin (ROLL-61) |
| `astra-daemon` | `Astra` | **not yet** — to be vendored into `astra-daemon/testdata/signed-set-vectors/` with `SHA256SUMS` and `SOURCE` (client plan C1.8) |

**One of the three reads it today.** The table said "vendored" and "at a pinned
commit" in the present tense when this file was written, and both were false:
measured at Astra `2d68bd6f`, `astra-daemon/testdata/signed-set-vectors/` does
not exist and nothing under `astra-rs/` names it, and minice CI does not yet pin
this repository. Until C1.8 and ROLL-61 land, **a corpus built so that two
languages must agree proves that this repository agrees with itself** — the
closed vocabulary, the floor and the two copies of the daemon column are all
real and all on one side. `O:dev/couplings.md` gap 18 holds the other two.

The tense mattered more than it looks. This table is what a reader consults
before changing a verdict name, and "vendored" told them a rename here would be
caught over there. It would not be.

Astra will vendor rather than read a sibling checkout because Astra CI has no
registry checkout, so a sibling-checkout reader there would check nothing.

## The shape

Fixed here, because two independent implementations read it. Without a stated
shape both canaries can be green on incompatible readings of the same bytes.

```
{ "version": 1,
  "vectors": [ { "id": 1,
                 "name": "valid",
                 "document_kind": "index" | "revocations",
                 "document": { … the whole envelope, inline … },
                 "trust_json": { … },
                 "root_json": { … },
                 "prior_state": { "serial": n, "issued_at": "…", "entry_count": n } | null,
                 "now": "…",
                 "verdict": "accepted" } ] }
```

- **`document` is the whole envelope**, `signed` and `signatures` both — vector
  6's verdict is about the `signatures` array, so a corpus carrying only the
  `signed` member could not express it.
- **Every vector carries its own roots.** `root_json` and `trust_json` are the
  vector's, so a reader needs nothing from this repository but this file, and no
  third copy of the test roots exists anywhere.
- **`prior_state` is the accepted state the vector is judged against**, which
  vectors 7, 8 and 9 need: all three are judgements about something already
  accepted rather than about the document alone. It is `null` — present and
  null, never absent — where the vector needs none.
  - `entry_count` is `signed.plugins.length` for an `index` and
    `signed.revocations.length` for a `revocations`.
- **`now` is the clock the verifier is given**, which vector 4's key window
  needs. A verifier that reads the wall clock cannot be tested against a fixed
  corpus at all: every window case would pass or fail by the date it ran.
- **`verdict` is one of the nine below and nothing else.**

### The order the rules are applied in

Stated, because more than one rule can be true of one document and the two
readers must name the same one. Reading down:

1. the document cannot be canonicalised — `unsafe_integer`;
2. nothing is offered — `no_signatures`;
3. no delegated key signed it — `bad_domain` if the same bytes verify under the
   other document's domain, otherwise `unknown_key`;
4. a delegated key signed it outside the window `trust.json` gave it —
   `key_outside_window`;
5. against `prior_state` at an **equal** serial: `older_issued_at`, then
   `entries_shrank`, then `serial_reused` (the content grew without the serial
   rising);
6. otherwise `accepted`.

## The mapping table

Each verdict against the daemon's symbol and against the JS verifier's outcome.
Both readers assert this table, so a rename on either side is a test failure and
not a silent disagreement.

| verdict | astra-daemon | the JS verifier |
|---|---|---|
| `accepted` | `SignatureState::Verified` | `verifyEnvelope ok` |
| `bad_domain` | `SignatureState::Invalid` | `verifyEnvelope refuses; the same bytes verify under the other domain` |
| `unknown_key` | `SignatureState::Invalid` | `verifyEnvelope refuses under every delegated key` |
| `key_outside_window` | `SignatureState::KeyOutsideWindow` | `verifyEnvelope ok; now is outside the verifying key's window` |
| `unsafe_integer` | `EnvelopeError::Malformed` | `verifyEnvelope throws out of jcs()` |
| `no_signatures` | `UnsignedReason::NoSignatures` | `signatures is empty; nothing was offered` |
| `serial_reused` | `TrustError::SerialReused` | `equal serial; entry_count above the accepted state` |
| `entries_shrank` | `RevocationSet::merged_with` | `equal serial; entry_count below the accepted state` |
| `older_issued_at` | `(none today)` | `equal serial; issued_at before the accepted state` |

Where each daemon symbol lives, read at Astra `2d68bd6f` (2026-09-17):

| symbol | file | line |
|---|---|---|
| `SignatureState::Verified` / `KeyOutsideWindow` / `Invalid` | `astra-daemon/src/plugins/trust.rs` | 1356, 1361, 1368 |
| `UnsignedReason::NoSignatures` | `astra-daemon/src/plugins/trust.rs` | 1344 |
| `TrustError::SerialReused` | `astra-daemon/src/plugins/trust.rs` | 437 |
| `RevocationSet::merged_with` | `astra-daemon/src/plugins/trust.rs` | 3238 |
| `EnvelopeError::Malformed` | `astra-core/src/trust_envelope.rs` | 36 |

### What the daemon column does not claim

Three rows are weaker than they look, and saying so here is cheaper than a
reader discovering it from a green test:

- **`entries_shrank` is not an error at all.** `RevocationSet::merged_with`
  unions an equal-or-lower serial into what it already holds, so a shrunken list
  removes nothing — the withdrawal stays in force and nothing is raised. The
  verdict names the outcome, which is that the document does not win; it does
  not name a refusal.
- **`serial_reused` names a variant that only `trust.json` can raise today.**
  `TrustError::SerialReused` is produced by the trust store's equal-serial
  branch. For a catalogue the daemon's floor is `index.serial >= floor`
  (`astra-daemon/src/plugins/registry_client.rs:1398`), so an equal serial with
  different bytes is accepted there. The registry is the only side enforcing
  this on a catalogue, through the signer's own gate (SERVE-89).
- **`older_issued_at` has no daemon symbol at all.** It is a registry-side rule:
  the signer refuses to publish a changed document whose `issued_at` is not
  later than the head's. The daemon does not compare a catalogue's `issued_at`
  against the one it already holds.

The two gaps are real coupling gaps, not bookkeeping. Whoever closes them
changes this table on both sides in one pass, and both readers go red until they
agree again — which is the only reason the table is written down twice.

## Which side asserts which column

Neither CI has the other repository checked out, so neither can compile the
other's column. The split is deliberate and is the whole content of "both
readers assert the same table":

- **here**, `tools/selftest/index-signature.mjs` asserts the verdict column
  equals the closed vocabulary in order, asserts the JS column equals what
  `bot/lib/sign.mjs`'s verifier actually produced for each verdict, and pins the
  daemon column against a literal list so an edit to one side of the table goes
  red on the other;
- **in Astra**, C1.8's Rust test asserts the same verdict column, iterates the
  corpus by vector id, and maps each verdict to the symbol in the daemon column.

A rename on either side therefore fails in both repositories rather than in
neither.

## The eleven vectors

| id | name | kind | verdict |
|---:|---|---|---|
| 1 | valid | index | `accepted` |
| 2 | wrong domain | index | `bad_domain` |
| 3 | unknown key | index | `unknown_key` |
| 4 | key outside its window | index | `key_outside_window` |
| 5 | unsafe integer | index | `unsafe_integer` |
| 6 | empty signatures | index | `no_signatures` |
| 7 | serial reused | index | `serial_reused` |
| 8 | equal serial, fewer entries | revocations | `entries_shrank` |
| 9 | equal serial, older issued_at | index | `older_issued_at` |
| 10 | dual-signed, outgoing key first | index | `accepted` |
| 11 | incoming key alone after the outgoing key was dropped | revocations | `accepted` |

Eleven is a **floor**, asserted by both readers before either looks at a single
vector. Adding a vector is an ordinary act and must not turn the other
repository red on a commit it cannot see; losing one is not ordinary, and a
reader that iterates whatever it finds reports PASS over the remainder.

If OPEN-OWNER-25's compromise answer changes vector 11, this file is regenerated
here and Astra re-vendors it in its own commit, naming this repository's SHA.
