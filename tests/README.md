# `tests/` — the corpora that cross a repository boundary

Everything in this directory is a **set of vectors that more than one program
is judged against**, which is what makes it different from `bot/tests/` and
`tools/selftest/`. Those ask whether this repository agrees with itself. These
ask whether it agrees with somebody else's implementation of the same sentence.

| | |
|---|---|
| `moderation-reasons.json` | MOD-41's and MOD-48's public-reason vectors. Read by this repository's two validators and, from R3, vendored by the plugins service's `plugins-testkit` at a pinned registry commit. **This page is its documentation.** |
| `vectors/` | The `.astraplugin` bundle corpus, **vendored** from `AstraPlugins/testdata/bundles/`. It has [its own README](vectors/README.md) and is not edited here. |
| `shared-vectors.mjs` | How this repository reads `vectors/`. |
| `fixtures/` | Two hand-built trees for the id checks. Not a cross-repository corpus. |

---

## `moderation-reasons.json`

### What a public reason is

The one string a moderator types that reaches git, a transparency page and a
user's screen. DEC-14: *no panel-typed field enters git at launch, except a
moderator's public reason.* Everything else on a moderation entry is derived —
the plugin id, the versions, the advisory, the dates — and this is the sentence
somebody wrote.

Two programs decide whether one is acceptable:

| Leg | Where | What it refuses |
|---|---|---|
| **the registry's validators** | `reasonProblems` in `bot/lib/moderation.mjs`, read by the moderation log and by `checkAdvisory` in `tools/lib/revocations.mjs` | MOD-41 |
| **the service's entry check** | the plugins service, at the moment a decision is recorded | MOD-48: what MOD-41 refuses, **and** a reason naming a Minice account |

They are written in different languages, by different people, in different
repositories, against the same paragraph. This file is what stops them from
agreeing with the paragraph and disagreeing with each other.

### The unit is CODE POINTS

MOD-41 says "outside 10 to 300 characters" and names no unit. There are two
plausible readings of "characters" and they differ:

| Reading | Where it comes from | `"Снято🔥🚨🛑"` |
|---|---|---|
| **code points** | Postgres `char_length`, Python `len`, Rust `chars().count()`, JavaScript `[...s].length` | 8 |
| UTF-16 code units | JavaScript `String.length`, Java `String.length()`, C# `string.Length` | 11 |

**Every length in this file is code points, counted over the trimmed reason.**

The reason it is worth a table is the direction the disagreement fails in. A
299-code-point Russian reason carrying four emoji is 303 UTF-16 units. If the
service accepts it and the registry refuses it, the service records the
decision, the bot routes it to `refused` with `reason_refused`, `report` posts
that back, and the decision settles as refused with nothing for the moderator
to act on — **a takedown that stalls**, which is the one direction §7 calls
unsafe, because only a withdrawal reaches a machine that already has the plugin
on it.

`unit-299-cp-303-units` and `unit-9-cp-12-units` are that failure, one at each
bound, and they are the two vectors in this file whose whole job is to be red
against a validator that counts `String.length`. `unit-300-cp-ascii` and
`floor-9-cp-ascii` pin the same bounds in the case where the two readings
agree, so a red run says which of the two things broke.

The unit itself goes to the contract as a PATCH to MOD-41 and MOD-48. **This
corpus is written with the unit stated whether or not that PATCH has landed**;
the PATCH only makes the other side read the same sentence.

### The host-like clause, pinned by example

MOD-41 refuses "a URI scheme, `www.`, `@`, an email or a host-like token", and
requires that names such as `plugin.toml` pass. "Host-like token" is not a
regex anybody can write down once and be finished with, so it is pinned here
instead:

- a dotted token is host-like when its **last** label is two or more ASCII
  letters and is **not** in `file_suffixes`;
- `plugin.toml`, `astra-chess.json`, `README.md`, `Cargo.lock`, `payload.exe`
  pass;
- `v1.2.3-rc.1` passes, because its last label is a digit;
- `evil.example`, `tracker.co.uk`, `evil.io` do not.

`file_suffixes` is the judgement call, and each entry on it is a hole: several
are real top-level domains, so `evil.md` passes. It is kept short for that
reason, and `.so`, `.sh` and `.py` are deliberately off it — a reason can say
"a shared library" instead. What the clause is for is keeping a **clickable
host** out of a sentence a stranger wrote; `payload.exe` is not one.

### The two places the legs are not symmetrical

Write these down rather than discover them in a stalled takedown:

1. **`unsafe_text` is the registry's alone.** Control characters, zero-width
   characters, bidi overrides and unpaired surrogates are refused here and are
   not one of MOD-41's clauses. It pre-dates MOD-41 (`unsafeDisplayText` in
   `tools/lib/ids.mjs`) and it is load-bearing for more than display: an
   unpaired surrogate makes the whole signed catalogue unparseable in every
   daemon that fetches it. A service that accepts one will have its decision
   refused here. Vectors `bidi-override` and `zero-width-joiner` carry the
   class, marked `registry-only`.
2. **"names a Minice account" is the service's alone.** MOD-48 adds it, the
   registry cannot check it — it holds no account data and PRIV-2 forbids it
   from holding any — and so there is no vector for it here. Its absence from
   this file is not a gap; it is the boundary.

### The shape of a vector

```json
{
  "name": "probe-evil-example",
  "reason": "evil.example",
  "verdict": "refuse",
  "classes": ["host_like"],
  "code_points": 12,
  "utf16_units": 12,
  "why": "…"
}
```

`classes` is **every** clause that fires, not the first. A reason refused for
its length that also carries a host would come back green the moment somebody
shortened it, and a corpus that recorded only the first refusal would not have
noticed. A vector with two classes is an honest vector, and several of the
short probes have two: `https://x` is nine code points as well as a scheme.

`classes` is empty exactly when `verdict` is `accept`.

### Adding one

1. Add the vector, with `why` saying what it is a statement about — not what it
   contains, which the `reason` already says.
2. Recompute `code_points` and `utf16_units`. `bot/tests/moderation.test.mjs`
   recomputes both and fails on a mismatch, so a hand-counted vector is caught
   rather than believed.
3. If it is a new refusal class, add it to `classes` at the top of the file and
   to `REASON_CLASSES` in `bot/lib/moderation.mjs`. The suite asserts the two
   lists are equal **and** that every class has at least one vector — a class
   nobody exercises is a clause nobody has tested.
4. If it is a new accepted file suffix, add it to `file_suffixes` there and in
   `REASON_FILE_SUFFIXES`, and say in `why` why that suffix is not a host.

### The floors

`bot/tests/moderation.test.mjs` carries them, written before the mutations that
were watched against them, because every assertion over this file is a loop and
a loop over an empty array is green about nothing:

- at least 30 vectors, at least 10 accepted and at least 15 refused;
- at least one vector per class in `REASON_CLASSES`, both directions;
- at least 6 tracked files under `bot/moderation/`, counted with `git ls-files`
  rather than `readdir`, so an untracked stray cannot pad the count and a lost
  directory cannot empty it.

### Who else reads this file

`dev/couplings.md` carries the row — *"MOD-41/MOD-48 reason vectors: bot
validator vs service entry check"* — and it names both legs. The service's half
is `plugins-testkit`, which vendors this file at a named registry commit with a
`SOURCE` file and `SHA256SUMS` beside it, the way it vendors `tests/results/`
and `tests/binding-line/`. Until that vendoring lands, **this corpus binds one
leg**: it proves the registry's two validators agree with each other and with
this file, and it proves nothing about the service. That is a real gap and it is
what the couplings row exists to keep visible.
