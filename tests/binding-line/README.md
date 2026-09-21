# `tests/binding-line` — the binding-line corpus

Thirty-one files a stranger could commit, each with the outcome the contract
requires, for the three programs that read `.well-known/astra-plugin-owner` and
have to agree about it.

| | implementation | what it decides |
|---|---|---|
| **bot** | `astra-registry/bot/lib/binding.mjs` | whether a release's attested commit binds a repository |
| **CLI** | `AstraPlugins/astra-plugin-cli/src/binding.rs` (AP-8) | what `init-ci --binding` writes, and what `check --tag` predicts |
| **service** | the plugins service's ID-59 read of the default branch | whether a `minted` or `seen` token may still expire (ID-16) |

They are three implementations of one grammar, in three languages, in three
repositories that release on three schedules, and the failure is quiet in both
directions: a reader that is stricter than the others refuses a repository its
author bound correctly, and a reader that is laxer binds one on a line the
others cannot see. **This directory is the shared fact all three are measured
against.** Until it existed, each side's suite could only prove it agreed with
itself.

## Direction, and who may change it

`astra-registry:tests/binding-line/vectors.json` is **canonical** (registry plan
B-T2.4). AstraPlugins mirrors it byte for byte as
`testdata/binding-line/vectors.json` under `tools/check-registry-mirrors.py`
rule C31 (AP-6), and its README header names the registry SHA the copy was
taken from. The plugins service pins it through `plugins-testkit` beside
`contract-tokens-v1.json`'s pin.

So a change here is a change to two other repositories' fixtures, and the
commit that makes one **states whether any entry a minice reader pins changed**
— which is the same discipline `§1.4` already applies to token-file
regenerations, and the reason the pin move is its own numbered record
(`ops.26a`).

## `MBE-PENDING`: five things this corpus decides that the contract does not

Contract 0.13.0 states ID-23 and ID-24 and leaves five edges open. They are
written down as questions in the registry plan (`§1.3` row 5) and marked on the
cases below with a `proposal` member. **minice-be pins this corpus only after a
contract PATCH records them, or after minice-be records its agreement.** Until
then, a disagreement between the two parsers shows up first as a vector failure
in minice CI, which is exactly what a corpus is for.

| | the question | what this corpus answers | cases |
|---|---|---|---|
| **Q1** | the 4096-byte window | **bytes of the file as delivered**, a BOM included; a line counts only when it *and its terminator* are inside it | 11, 12, 13, 14a, 15 |
| **Q2** | does ID-24 count only lines inside the window | yes — a near miss past 4096 is not a malformed line, it is not a line | 14b |
| **Q3** | is `\r\r` malformed | yes — exactly one `\r` is stripped, the second survives, `[ \t]*$` cannot match it, ID-24 fires | 6 |
| **Q4** | is the BOM ignored only at the start of the file | yes — anywhere else it is an ordinary character and the line matches nothing | 7, 8, 25b |
| **Q5** | does the service's ID-59 read give the bot's `none`, `one` or `malformed` | yes — one vocabulary, three answers, no fourth | the whole file |

**Q2 has no case among B-T2.4's numbered twenty-five.** It is added here as a
second case under vector 14 rather than as a twenty-sixth vector, because the
numbering is read by three tasks. Without it Q2 would be a proposal this corpus
asserts nothing about, and a reader that scanned the *whole file* for ID-24
candidates while scanning the *window* for ID-23 matches would pass every other
case here.

## The unit is bytes, and it is stated because it has been got wrong

`4096` with no unit is the shape of a defect this estate has met before. The
number is **bytes**, and three readings are all different:

* 4096 **bytes** — the rule. Vector 15 is 1400 × U+4E00 followed by a binding
  line: 4200 bytes and 1400 UTF-16 code units, so the line begins at byte 4201
  and at unit 1401. Outcome `none`.
* 4096 **UTF-16 code units** — what `String.prototype.slice` gives, and what
  `astra-registry/bot/lib/ownership.mjs:283` does today when it reads logins off
  the default branch. It finds vector 15's line and binds the repository.
* 4096 **code points** — different again for any astral character.

A reader that slices UTF-16 units passes every other case in this file.

## Reading it

```js
const doc = JSON.parse(fs.readFileSync("tests/binding-line/vectors.json", "utf8"));
for (const c of doc.cases) {
  const file = Buffer.from(c.file_b64, "base64");   // the stranger's bytes
  // c.outcome is "none" | "one" | "malformed"; c.token is set iff "one"
}
```

| member | |
|---|---|
| `case` | `NN-name`, unique; `NN` is B-T2.4's vector number |
| `vector` | B-T2.4's number, 1 to 25. Several cases may share one |
| `title`, `why` | what the file is, and what breaks if a reader gets it wrong |
| `bytes` | the file's length, so a reader that mis-decoded base64 is caught before it parses |
| `file_b64` | the file, base64. **Not** a UTF-8 string: four cases exceed 4 KiB, one is not valid UTF-8, three carry a BOM and one carries a bare CR mid-line |
| `outcome` | `none`, `one` or `malformed` — never `B_UNBOUND`, which is a different question (ID-25, and `bot/lib/listing-state.mjs` decides it) |
| `token` | the token for `one`, `null` otherwise |
| `cli_write` | `"refuse"` where **FLOW-50 differs from ID-23**: the bot recognises the token and `init-ci --binding` will not write it. Absent everywhere else, deliberately — a column that repeated the reader's answer on every row would be a column nothing could disagree with |
| `proposal` | `Q1`…`Q4` where this case is the evidence for an unagreed question |

`outcome` and `token` are two members rather than the plan's `one:<token>`
spelling: splitting a string on a colon is a thing two languages do differently,
and the token charset contains no colon only because ID-23 says so.

## Floors

Asserted by `bot/tests/binding.test.mjs` **before it looks at a single case**,
because a walk that lost its file finds no disagreement and passes:

* **25 vector numbers**, 1 to 25, none missing;
* **31 cases**;
* **at least one case per outcome** — 31 cases and one outcome would be a
  corpus that has never watched a refusal;
* **at least one case on each side of byte 4096**: one whose file is ≥ 4096
  bytes and still answers `one`, and one whose file is > 4096 bytes and answers
  `none` because of the window;
* at least one case that is not valid UTF-8, and at least one that carries a
  BOM.

## Generated, never hand-written

```sh
node tests/binding-line/generate.mjs           # rewrite vectors.json and SHA256SUMS
node tests/binding-line/generate.mjs --check   # verify the committed bytes — the CI step
```

`generate.mjs` **never imports `bot/lib/binding.mjs`**. Every outcome is written
down from the contract and from B-T2.4's list; the parser is then measured
against them. A generator that asked the parser what it does would produce a
corpus that agrees with the parser by construction, pass for ever, and say
nothing about whether either matches the rule — and the CLI and the service
would then be measured against this repository's bugs.

`SHA256SUMS` covers `vectors.json` and nothing else. It is the pin that travels:
this README is prose, and the AstraPlugins copy deliberately differs from it by
naming the registry SHA in its header, so covering it would make the mirror
impossible to state honestly. `bot/tests/binding.test.mjs` verifies the sum at
run time, before it reads a case.

## Why this directory is not `tests/vectors/`

`AstraPlugins/tools/vendor-testdata.sh` refreshes `astra-registry/tests/vectors/`
and then sweeps it: everything in that directory that is not in the bundle
corpus's own file list, and is not `SHA256SUMS` or `README.md`, is `rm -f`'d
(`tools/vendor-testdata.sh:101-112`, read 2026-09-20). That directory belongs to
the bundle corpus, which travels the other way — AstraPlugins is canonical and
this repository holds a copy. This one travels *from* here, so it lives beside
it and not in it. `bot/tests/binding.test.mjs` asserts that `tests/vectors/`
holds no subdirectory, so the day somebody tidies this corpus into it the sweep
is a red test rather than a silent deletion.
