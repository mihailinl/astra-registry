// What sign-update-manifest.mjs promises when it signs: the 180/365-day expiry
// rules, --renew carrying an unmodelled `repo` and a second artefact byte for
// byte, refusing a previous document a client would refuse, renewing only the
// newest record with --withdraw-to as the one way back, strictly-later signing
// instants, the desk clock beside the signature, the content flags,
// unknown/repeated/stray arguments, never writing over its input or under
// releases/, re-checking every claim, and SemVer 2.0.0 in the filename.

import crypto from "node:crypto";
import path from "node:path";

import { jcs } from "../lib/canonical.mjs";
import {
  CONTENT_FLAGS, DEFAULT_EXPIRY_DAYS, MAX_EXPIRY_DAYS, artefactProblems, renewSigned,
} from "../sign-update-manifest.mjs";
import { rfc3339 } from "../../bot/lib/sign.mjs";
import { test, assert, assertEqual } from "./harness.mjs";
import { TRUST_ROOT_A } from "./fixtures.mjs";
import {
  DAY_MS, UPDATE_NOTES_EN, UPDATE_SIGNER,
  assertRefused, bytesButDates, freshArgs, hoursFromNow, pretty, readText,
  updateDoc, updateSandbox, updateSigner, updateTmp,
  withDuplicateVersion, withUnpaddedSignature, writeUpdateDoc, writeUpdateText,
} from "./update-fixtures.mjs";

export async function run() {
  // ── the update manifest ─────────────────────────────────────────────────────
  //
  // `sign-update-manifest.mjs` is the other tool that holds a root key. Its renewal
  // is what `release.sh --resign` runs with the owner's passphrase already typed, so
  // what it promises is asserted here rather than trusted. Each test names the one
  // input that makes the check it is about fire on its own: a corpus that trips two
  // rules at once proves neither (the first version of this section had exactly that
  // hole, and eight mutations walked through it).

  console.log("\nupdate manifest (sign-update-manifest.mjs)");
  await test("the update manifest's default expiry is 180 days; --expires-days is a whole number from 1 to 365", () => {
    assertEqual(DEFAULT_EXPIRY_DAYS, 180, "DEFAULT_EXPIRY_DAYS (astra-rs UPDATES_0_2_6_PLAN.md D16)");
    assertEqual(MAX_EXPIRY_DAYS, 365, "MAX_EXPIRY_DAYS");
    const dir = updateSandbox();
    const out = updateTmp("fresh");
    const r = updateSigner([...freshArgs(), "--out", out], dir);
    assertEqual(r.status, 0, `a fresh signature failed: ${r.stderr}`);
    const doc = JSON.parse(readText(out));
    assertEqual(Date.parse(doc.signed.expires) - Date.parse(doc.signed.signedAt), 180 * DAY_MS, "expires - signedAt");
    // The closing message once promised a server check that does not exist, and later called a box check
    // that does exist (--check-manifest, minice eb9e379) planned. It names that one, and --stage as planned.
    assert(!r.stdout.includes("will refuse"), `the false server promise is back:\n${r.stdout}`);
    assert(r.stdout.includes("publish-release.sh --check-manifest <this file>"), `the box check is not named:\n${r.stdout}`);
    assert(r.stdout.includes("publish-release.sh --stage, is planned") && r.stdout.includes("does not exist yet"), r.stdout);
    for (const bad of ["0", "366", "1.5", "abc"]) {
      const o = updateTmp("bad-days");
      assertRefused(updateSigner([...freshArgs(), "--expires-days", bad, "--out", o], dir),
        "whole number of days between 1 and 365", o, `--expires-days ${bad}`);
    }
  });

  await test("--renew carries everything but signedAt and expires byte for byte: an unmodelled `repo`, a second artefact", () => {
    const prevDoc = updateDoc();
    const dir = updateSandbox([prevDoc]);
    const out = updateTmp("renewed");
    const r = updateSigner(["--renew", "releases/0.2.5/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", out], dir);
    assertEqual(r.status, 0, `the renewal failed: ${r.stderr}`);
    const text = readText(out);
    assertEqual(bytesButDates(text), bytesButDates(pretty(prevDoc)), "everything but the two dates");
    const doc = JSON.parse(text);
    assertEqual(doc.signed.latest.artifacts.length, 2, "artefacts");
    assertEqual(jcs(doc.signed.repo), jcs(prevDoc.signed.repo), "the unmodelled `repo`");
    assert(Date.parse(doc.signed.signedAt) > Date.parse(prevDoc.signed.signedAt), "signedAt did not move forward");
    assertEqual(Date.parse(doc.signed.expires) - Date.parse(doc.signed.signedAt), 180 * DAY_MS, "a renewal's expiry");
    assert(r.stdout.includes("newest record  releases/0.2.5/manifest.json"), `it did not say what it compared with:\n${r.stdout}`);
    const v = updateSigner(["--verify", out], dir);
    assertEqual(v.status, 0, `the renewal does not verify: ${v.stderr}`);
  });

  await test("--renew refuses a previous document a client would refuse, and writes nothing", () => {
    const dir = updateSandbox([updateDoc()]);
    // Claims root A's key_id; the verifier never believes a claimed key_id.
    const stranger = { key_id: UPDATE_SIGNER.key_id, privateKey: crypto.generateKeyPairSync("ed25519").privateKey };
    const tampered = updateDoc();
    tampered.signed.latest.artifacts[0].sizeBytes += 1;
    const cases = [
      ["signed by a key root.json does not publish", pretty(updateDoc({}, stranger)), "does not verify"],
      ["altered after it was signed", pretty(tampered), "does not verify"],
      ["a v2 body signed under the v1 domain", pretty(updateDoc({ mutate: (s) => { s.schema = "astra.update.v2"; } })), "declares schema"],
      ["a signature only Node's lenient base64 reads", withUnpaddedSignature(updateDoc()), "not canonical base64"],
      ["a key written twice", withDuplicateVersion(updateDoc()), "appears twice"],
    ];
    for (const [name, text, expect] of cases) {
      const out = updateTmp("x");
      assertRefused(updateSigner(["--renew", writeUpdateText(text), "--root-key", TRUST_ROOT_A.file, "--out", out], dir), expect, out, name);
    }
  });

  await test("--renew renews only the newest record, and --withdraw-to is the one named way back", () => {
    const older = updateDoc({ version: "0.2.4", signedAt: hoursFromNow(-48) });
    const newer = updateDoc({ version: "0.2.5", signedAt: hoursFromNow(-1) });
    const dir = updateSandbox([older, newer]);
    const key = ["--root-key", TRUST_ROOT_A.file];
    let out = updateTmp("x");
    assertRefused(updateSigner(["--renew", "releases/0.2.4/manifest.json", ...key, "--out", out], dir),
      "releases/0.2.5/manifest.json was signed later", out, "the superseded record");
    // Signed after every record, but offering less: a withdrawal already made, renewed as if it were not.
    const laterButOlder = writeUpdateDoc(updateDoc({ version: "0.2.4", signedAt: hoursFromNow(-0.5) }));
    out = updateTmp("x");
    assertRefused(updateSigner(["--renew", laterButOlder, ...key, "--out", out], dir),
      "offers 0.2.4, and releases/0.2.5/manifest.json offers 0.2.5", out, "a lower version");

    out = updateTmp("renewed");
    let r = updateSigner(["--renew", "releases/0.2.5/manifest.json", ...key, "--out", out], dir);
    assertEqual(r.status, 0, `renewing the newest record: ${r.stderr}`);
    assert(r.stdout.includes("(2 record(s) compared)"), r.stdout);

    out = updateTmp("withdrawn");
    r = updateSigner(["--withdraw-to", "releases/0.2.4/manifest.json", ...key, "--out", out], dir);
    assertEqual(r.status, 0, `the withdrawal: ${r.stderr}`);
    const w = JSON.parse(readText(out));
    assertEqual(w.signed.latest.version, "0.2.4", "the withdrawal offers");
    assert(Date.parse(w.signed.signedAt) > Date.parse(newer.signed.signedAt), "a withdrawal signed before the newest record");
    assert(r.stdout.includes("WITHDRAWAL"), r.stdout);
  });

  await test("--renew and --withdraw-to refuse when a record does not verify, or when there is none", () => {
    const bad = updateDoc({ version: "0.2.6", signedAt: hoursFromNow(-0.5) });
    bad.signed.latest.artifacts[0].sizeBytes += 1;
    const dir = updateSandbox([updateDoc({ version: "0.2.4", signedAt: hoursFromNow(-48) }), updateDoc(), bad]);
    for (const mode of ["--renew", "--withdraw-to"]) {
      const out = updateTmp("x");
      const prev = mode === "--renew" ? "releases/0.2.5/manifest.json" : "releases/0.2.4/manifest.json";
      assertRefused(updateSigner([mode, prev, "--root-key", TRUST_ROOT_A.file, "--out", out], dir),
        "releases/0.2.6/manifest.json, a committed release record, does not verify", out, `${mode} beside a broken record`);
    }
    const empty = updateSandbox();
    const out = updateTmp("x");
    assertRefused(updateSigner(["--renew", writeUpdateDoc(updateDoc()), "--root-key", TRUST_ROOT_A.file, "--out", out], empty),
      "there is no release record", out, "no records at all");
  });

  await test("--renew and --withdraw-to sign strictly later than the previous document and every record", () => {
    const t = new Date("2026-09-11T16:33:19Z");
    const prev = updateDoc({ signedAt: rfc3339(t) }).signed;
    const refused = (now) => {
      try {
        renewSigned(prev, now, DEFAULT_EXPIRY_DAYS);
        return false;
      } catch (e) {
        return /strictly later/.test(e.message);
      }
    };
    assert(refused(t), "the same instant was accepted");
    assert(refused(new Date(t.getTime() + 999)), "the same second was accepted, and signedAt is published in seconds");
    assert(refused(new Date(t.getTime() - 1000)), "an earlier instant was accepted");
    const next = renewSigned(prev, new Date(t.getTime() + 1000), DEFAULT_EXPIRY_DAYS);
    assertEqual(next.signedAt, "2026-09-11T16:33:20Z", "one second later");
    assertEqual(next.expires, "2027-03-10T16:33:20Z", "180 days after that");
    assertEqual(prev.signedAt, "2026-09-11T16:33:19Z", "the previous block was modified in place");

    // The only record is dated tomorrow.
    const future = updateSandbox([updateDoc({ signedAt: hoursFromNow(24) })]);
    let out = updateTmp("x");
    assertRefused(updateSigner(["--renew", "releases/0.2.5/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", out], future),
      "strictly later", out, "a record dated tomorrow");
    // A withdrawal to an old record, beside a newer record dated tomorrow.
    const ahead = updateSandbox([updateDoc({ version: "0.2.4", signedAt: hoursFromNow(-48) }), updateDoc({ signedAt: hoursFromNow(24) })]);
    out = updateTmp("x");
    assertRefused(updateSigner(["--withdraw-to", "releases/0.2.4/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", out], ahead),
      "is not strictly later than releases/0.2.5/manifest.json's", out, "a withdrawal behind the newest record");
  });

  await test("the desk clock is printed beside the signature it is compared with, and a renewal a year late is refused", () => {
    const ancient = updateDoc({ signedAt: rfc3339(new Date(Date.now() - 400 * DAY_MS)) });
    let dir = updateSandbox([ancient]);
    let out = updateTmp("x");
    const r = updateSigner(["--renew", "releases/0.2.5/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", out], dir);
    assertRefused(r, "more than 365 days after the newest signature", out, "a record 400 days old");
    assert(r.stdout.includes("desk clock") && r.stdout.includes(ancient.signed.signedAt), r.stdout);
    assert(/desk clock is \+400d /.test(r.stdout), r.stdout);
    // 364 days is inside the bound.
    dir = updateSandbox([updateDoc({ signedAt: rfc3339(new Date(Date.now() - 364 * DAY_MS)) })]);
    out = updateTmp("renewed");
    const ok = updateSigner(["--renew", "releases/0.2.5/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", out], dir);
    assertEqual(ok.status, 0, `364 days: ${ok.stderr}`);
    // Signing afresh prints the same line against the newest record.
    out = updateTmp("fresh");
    const fresh = updateSigner([...freshArgs(), "--out", out], dir);
    assertEqual(fresh.status, 0, fresh.stderr);
    assert(fresh.stdout.includes("desk clock") && fresh.stdout.includes("in releases/0.2.5/manifest.json"), fresh.stdout);
  });

  await test("--renew and --withdraw-to refuse every flag that would describe a different release", () => {
    const dir = updateSandbox([updateDoc({ version: "0.2.4", signedAt: hoursFromNow(-48) }), updateDoc()]);
    assertEqual(CONTENT_FLAGS.length, 10, "the list this loop covers");
    for (const [mode, prev] of [["--renew", "releases/0.2.5/manifest.json"], ["--withdraw-to", "releases/0.2.4/manifest.json"]]) {
      for (const flag of CONTENT_FLAGS) {
        const out = updateTmp("x");
        assertRefused(updateSigner([mode, prev, "--root-key", TRUST_ROOT_A.file, flag, "x", "--out", out], dir),
          `so ${flag} would describe a different release`, out, `${mode} ${flag}`);
      }
    }
  });

  await test("every mode refuses an unknown flag, a repeated flag and a stray word, and writes nothing", () => {
    const dir = updateSandbox([updateDoc()]);
    const cases = [
      ["a typo'd --expires-days when signing", [...freshArgs(), "--expires-day", "30"], "--expires-day is not a flag signing accepts"],
      ["a typo'd --expires-days when renewing", ["--renew", "releases/0.2.5/manifest.json", "--root-key", TRUST_ROOT_A.file, "--expires-day", "30"], "is not a flag --renew accepts"],
      ["an unknown flag when verifying", ["--verify", "releases/0.2.5/manifest.json", "--verbose"], "--verbose is not a flag --verify accepts"],
      ["an unknown flag when checking notes", ["--check-notes", "releases/0.2.5", "--strict"], "--strict is not a flag --check-notes accepts"],
      ["a repeated flag", [...freshArgs(), "--notes-en", UPDATE_NOTES_EN], "--notes-en is given twice"],
      ["a word that belongs to no flag", [...freshArgs(), "stray"], "unexpected argument \"stray\""],
      ["two modes", ["--verify", "a", "--renew", "b"], "are separate modes"],
    ];
    for (const [name, args, expect] of cases) {
      const out = updateTmp("x");
      assertRefused(updateSigner([...args, "--out", out], dir), expect, out, name);
    }
  });

  await test("the signer never writes over its input, nor anywhere under releases/", () => {
    const dir = updateSandbox([updateDoc()]);
    const record = path.join(dir, "releases", "0.2.5", "manifest.json");
    const before = readText(record);
    const prev = writeUpdateDoc(updateDoc());
    const prevBefore = readText(prev);
    assertRefused(updateSigner(["--renew", prev, "--root-key", TRUST_ROOT_A.file, "--out", prev], dir),
      "is the previous document itself", undefined, "--out = the input");
    assertEqual(readText(prev), prevBefore, "the input was overwritten");
    const intoRecord = path.join(dir, "releases", "0.2.5", "renewed.json");
    assertRefused(updateSigner(["--renew", "releases/0.2.5/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", "releases/0.2.5/renewed.json"], dir),
      "lies under releases/", intoRecord, "a renewal into releases/");
    const fresh = path.join(dir, "releases", "0.2.6", "manifest.json");
    assertRefused(updateSigner([...freshArgs(), "--out", "releases/0.2.6/manifest.json"], dir),
      "lies under releases/", fresh, "a fresh signature into releases/");
    assertEqual(readText(record), before, "the record changed");
  });

  await test("--renew re-checks every claim it carries against today's rules", () => {
    const dir = updateSandbox([updateDoc()]);
    const cases = [
      ["the inner Setup's name", (s) => { s.latest.artifacts[0].filename = "Astra-Setup-0.2.5.exe"; }, "outside the set"],
      ["a version the filename contradicts", (s) => { s.latest.version = "0.2.6"; }, "disagrees with the filename"],
      ["notes with a link", (s) => { s.latest.notes.en = "See https://minice.ai."; }, "markup or a link"],
      ["a platform the signer does not publish", (s) => { s.latest.artifacts[1].platform = "linux-x64"; }, 'platform "linux-x64"'],
      ["an uppercase digest", (s) => { s.latest.artifacts[0].sha256 = s.latest.artifacts[0].sha256.toUpperCase(); }, "not 64 lowercase hex"],
      ["a negative size", (s) => { s.latest.artifacts[0].sizeBytes = -1; }, "not a whole number of bytes"],
      ["an artefact without its digest", (s) => { delete s.latest.artifacts[1].sha256; }, "has no sha256"],
      ["a placeholder that is not a boolean", (s) => { s.latest.placeholder = "no"; }, "not a boolean"],
      ["a note that is not a string", (s) => { s.latest.notes.ru = 7; }, "not a string"],
    ];
    for (const [name, mutate, expect] of cases) {
      const out = updateTmp("x");
      assertRefused(updateSigner(["--renew", writeUpdateDoc(updateDoc({ mutate })), "--root-key", TRUST_ROOT_A.file, "--out", out], dir),
        expect, out, name);
    }
    // Sizes this repository's canonicaliser cannot even sign, so they are checked on the rule itself;
    // --verify's refusal of such a body, signed elsewhere, is asserted below.
    const entry = updateDoc().signed.latest.artifacts[0];
    for (const size of [1.5, 2 ** 53, -1, "88118552"]) {
      assert(
        artefactProblems({ ...entry, sizeBytes: size }, "0.2.5").some((p) => p.includes("not a whole number of bytes")),
        `sizeBytes ${JSON.stringify(size)} was accepted`,
      );
    }
  });

  await test("the filename's version is SemVer 2.0.0: no leading zeros, no empty pre-release identifier", () => {
    const entry = (v) => ({ platform: "windows-x64", filename: `Astra-Installer-${v}.exe`, sha256: "0".repeat(64), sizeBytes: 1 });
    for (const v of ["01.2.3", "0.02.3", "0.2.03", "0.2.3-", "0.2.3-rc..1", "0.2.3-01", "0.2.3.4", "0.2.3+build"]) {
      assert(artefactProblems(entry(v), v).some((p) => p.includes("outside the set")), `${v} was accepted`);
    }
    for (const v of ["0.2.6", "0.2.6-rc.1", "1.0.0-alpha.beta-2", "10.20.30-0"]) {
      assertEqual(artefactProblems(entry(v), v).join("; "), "", `${v} was refused`);
    }
    const dir = updateSandbox();
    let out = updateTmp("x");
    assertRefused(updateSigner([...freshArgs("0.02.6"), "--out", out], dir), "outside the set", out, "Astra-Installer-0.02.6.exe");
    out = updateTmp("x");
    assertRefused(updateSigner([...freshArgs(), "--platform", "linux-x64", "--out", out], dir), 'platform "linux-x64"', out, "--platform linux-x64");
  });
}
