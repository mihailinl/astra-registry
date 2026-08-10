# Security

This document describes the keys that make the Astra plugin catalogue
trustworthy, who holds them, what happens when one is lost, and — the part most
documents of this kind omit — what this design does **not** protect against.

Reporting a vulnerability: open a private security advisory on this repository,
or email the address in the repository profile. Please do not open a public
issue for anything that would let someone ship code to a user.

---

## 1. The one-sentence version

Astra believes this catalogue because a **root key** signed a `trust.json` that
names the key allowed to sign `index.json`, and because every artifact is pinned
by SHA-256 in a record that key signed. Astra does **not** believe it because of
the hostname it was fetched from.

That distinction is load-bearing. `plugins.registry_url` is ordinary
configuration; the catalogue can move to another host, another CDN, a
`file://` path on a developer's disk, or a mirror, and not one trust decision
changes. The daemon's verification path contains no hostname check and must
never grow one. A cached copy records which URL it came from so that a staging
cache is not served to a production build — that is cache hygiene, and it is
deliberately incapable of rejecting a correctly-signed catalogue.

---

## 2. The keys

| Key | Custody | Signs | Rotation |
|---|---|---|---|
| **Root** — two public keys ship in every Astra binary, one active, one reserve | One person, two copies (§3). Generated offline by `tools/keygen-root.sh`. | `trust.json`, and nothing else | The reserve is already in every shipped binary, so replacing a root is a signature rather than a flag day |
| **Index** | GitHub Environment secret on this repository, with the maintainer as a required reviewer on the `publish` environment | `index.json`, `revocations.json`, per-release countersignatures | Quarterly, and immediately on suspicion, by publishing a root-signed `trust.json` with a **30-day overlap** between the outgoing and incoming key |
| **Author** (optional) | The author's own repository secret | the `.astraplugin.minisig` sidecar | Losing it is a non-event: Astra pins the author's *repository identity*, not their key |

Two roots exist for one reason. A single root that has to be replaced — because
the laptop it was generated on turned out to be compromised, because the paper
backup burned, because it is simply old — would otherwise require every user in
the world to install a new Astra before any new catalogue could be verified.
Shipping the reserve from day one turns that flag day into a document.

**A root signs `trust.json` only.** It never appears on `index.json`, on
`revocations.json`, or on a plugin bundle. That is what keeps the root offline:
day-to-day publishing needs the index key, and the index key is replaceable.

### What is signed, exactly

```
sig = Ed25519(key, SHA-256( domain ‖ 0x00 ‖ JCS(signed) ))
```

`JCS` is RFC 8785 canonical JSON over the document's `signed` member, and
`domain` is the document's schema string — `astra.registry.trust/1` for
`trust.json`, `astra.registry.index/1` for `index.json`. The verifier supplies
`domain` from a constant compiled into it, **never** from the `schema` field of
the file it is reading, so a signature over one document type can never be
replayed as a signature over another.

The canonicaliser is `tools/lib/canonical.mjs`. It refuses any number that is
not a safe integer rather than implementing RFC 8785 §3.2.2's floating-point
rules approximately; `astra-daemon`'s Rust implementation refuses the same
inputs, and a fixture signed by the JS side is embedded byte-for-byte in a Rust
test so the two cannot drift apart in silence.

---

## 3. Custody: one person, two copies

There is one maintainer. This section describes what that person actually does,
because a ceremony that does not happen is worse than an honest one that does:
it makes the design's central claim — *a CI compromise is bounded* — quietly
false while everyone believes it is true.

So: **not** a two-person threshold ceremony with hardware tokens and an air-gapped
signing room. One person, two copies of one key.

1. **A physical offline copy.** The root private keys, printed or stamped onto
   paper or steel, stored where a house fire and a burglary are different
   events. Verified by transcribing it back and diffing — a backup that has
   never been restored is not a backup.
2. **An encrypted copy in a password manager**, attached as a *file*, not pasted
   into a note field (most managers sync note bodies into a search index).

Both copies are made **before** the ceremony machine's copy is wiped, and the
ceremony machine's copy is wiped once both are verified. `tools/keygen-root.sh`
prints these steps in this order and refuses to write keys into a git working
tree.

KMS, a YubiKey, or a second custodian are **upgrades written into
`docs/RUNBOOK.md`**, not requirements. When the team is two people, revisit this
section first.

### What this does not mitigate, stated plainly

**Compromise of the maintainer's GitHub account is unmitigated at this team
size.** An attacker holding that account can approve the `publish` environment,
change required reviewers, merge to `main`, and publish a signed index. No
amount of root-key hygiene helps, because the root's job is to delegate to the
index key and the index key lives in the account that has been taken.

**Hardware 2FA on that one account is the real control here** — a physical
security key, not TOTP, not SMS. Everything else in this document is
defence-in-depth behind it.

Two consequences follow, and the plan takes both:

- The daemon **pins each installed plugin's identity on first install** (TOFU) and
  hard-blocks a change to it with no user override, so a compromised index key
  cannot silently take over a plugin someone already has.
- The daemon **checks that the download URL lives under the pinned repository's
  release namespace**, so the bytes must at least come from the author's repo
  even if the catalogue says otherwise.

Neither helps against a *new* plugin the attacker publishes. That is trusted by
construction, and the mitigation is auditability: the index quotes verifiable
provenance and can be diffed against the public transparency log after the fact.

---

## 4. The ceremony

Run once, by hand, on a machine with no network.

```sh
tools/keygen-root.sh --i-am-offline --out /run/media/$USER/ASTRA-ROOT/keys
```

The script:

- refuses to run without `--i-am-offline`, and prints what to disconnect first;
- refuses to write keys inside a git working tree;
- creates everything under `umask 077`, writes each private key mode `0600`, and
  **verifies the mode afterwards** rather than assuming the umask was honoured;
- sign/verify self-tests both keys before you rely on them;
- prints the two **public** keys and their SHA-256 fingerprints, and nothing
  derived from a private key — no `cat`, no clipboard, no shell-history exposure;
- writes a `root.json` ready to commit;
- prints the backup, paste, and wipe steps in the order they must happen.

Afterwards, two things must be updated together:

1. `registry/v1/root.json` in this repository — the public copy, so a third party
   can read the roots without disassembling a binary.
2. `PRODUCTION_ROOT_KEYS` in `astra-rs/astra-daemon/src/plugins/trust.rs` — the
   copy that actually decides anything.

They are two copies of the same fact on purpose: a difference between them is
visible to anyone, and `root.json` alone is unsigned and proves nothing.

Until the ceremony runs, both are empty and Astra **fails closed**: no
`trust.json` verifies, so no catalogue signature is believed. That is the
correct state for a chain with no anchor. It is not a hole to be plugged with
the test keys in `tools/testkeys/`, which no shipped Astra can compile in
(see that directory's README).

---

## 5. Compromise playbook

Severity is decided by one question: *can the attacker produce a signature Astra
will accept?*

### 5.1 Index key compromised, or suspected

The blast radius is bounded by design — this is the case the two-key split
exists for.

1. **Rotate within the hour.** Sign a new `trust.json` with the **active root**
   whose `index_keys` contains only the new key, with a serial strictly greater
   than the current one. Publish it. Daemons pick it up on their next refresh and
   stop accepting anything the old key signs after its `not_after`.
   *Do not* give the compromised key an overlap window. Overlaps are for planned
   rotations.
2. **Re-sign the catalogue** with the new index key and bump `index.json`'s
   serial. The daemon refuses a serial lower than one it has already seen, so an
   attacker cannot replay the last good index either.
3. **Revoke anything the attacker published**, by artifact digest, via
   `revocations.json`. Digest-keyed revocation reaches a bundle however it
   arrived — store, local import, or a copy from a friend.
4. **Audit the whole index** against the public provenance log for records added
   while the key was out. `git log registry/v1/index.json` is the timeline;
   every record's digest is in it.
5. Write down when the key was created, when you believe it was taken, and what
   was published in between. That interval is what everyone will ask about.

### 5.2 Active root key compromised

Serious, but survivable without touching a single user's machine.

1. Sign a `trust.json` with the **reserve root**, with a serial strictly greater
   than the current one, naming a fresh index key.
2. Publish it. Every shipped Astra already contains the reserve public key, so it
   verifies immediately, with no update and no flag day. This is the whole reason
   the reserve exists.
3. Ship an Astra release that drops the compromised root from
   `PRODUCTION_ROOT_KEYS` and adds a **new** reserve, so the two-key invariant
   holds again. Until that release is broadly installed you are operating with
   one root.
4. Publish an advisory naming the compromised key's fingerprint. Users can check
   it against the fingerprint their daemon logs.

### 5.3 Both roots compromised

There is no cryptographic recovery, and this document will not pretend
otherwise. Both keys are generated in the same ceremony, on the same machine,
and backed up by the same person to the same two places — so the realistic way
to lose one is the way that loses both.

The response is an out-of-band Astra release with a new root pair, announced
through channels that are not this repository (the website, the Steam page, the
Discord), plus a signed statement from the old keys if they are merely *lost*
rather than *stolen*. Treat this as the reason §3's backup discipline is
non-negotiable.

### 5.4 Root private key lost (not stolen)

Not an emergency. Promote the reserve: sign the next `trust.json` with it, and
ship a release that replaces the lost key with a freshly generated reserve.
Nothing a user holds becomes untrustworthy.

### 5.5 An author's GitHub account is compromised

The provenance will be **perfect** and will attest a malicious build. There is
no cryptographic defence, and `POLICY.md` says so in the same words.

What actually applies: the 24-hour publication delay on any release of a plugin
holding a high-risk permission, out-of-band notification to the author on every
publish (so a takeover victim sees it happen), permission-diff re-consent, and
revocation once it is noticed.

### 5.6 This repository is compromised, but no key is

The attacker can edit files. They cannot produce a signature. A daemon rejects
the tampered index and keeps serving the last catalogue it verified; installs of
already-verified, digest-pinned records keep working. Fix the repository, re-sign,
bump the serial.

---

## 6. Deliberate non-goals

- **No hostname is ever a trust input.** See §1.
- **No Sigstore verification in the daemon.** `.sigstore.json` bundles ship with
  every release and any third party can re-verify them with
  `gh attestation verify`, but the daemon does Ed25519 and nothing else: one
  algorithm, one code path, identical on Windows and Linux. Attestations are
  verified in this repository's CI, where a bad one blocks a listing.
- **No user override on a registry-path verification failure.** The only thing an
  override can ever buy is the right to run code from a source Astra has not
  vetted. It can never buy a permission that a verified plugin would have had to
  ask for.
- **A plugin is not sandboxed.** It runs as your user, with your files. Signing
  proves *who shipped it*, never *what it does*. Astra's UI is written to never
  imply otherwise, and this is the largest open item in the security model.
