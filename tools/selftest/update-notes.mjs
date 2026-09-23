// The notes corpus and the verify side: one verdict per server trigger taken
// alone, --check-notes on empty/missing-English/unknown/doubled locales, --verify
// saying ok only for a document a client would accept now, primary versus reserve
// root, signing afresh against the newest record, --verify --receipt bound to the
// exact bytes read, --receipt belonging to --verify alone, and every committed
// release manifest against the production roots.
//
// The two places that used to write `++updateSeq` call nextSeq() instead: the
// counter lives in ./update-fixtures.mjs and an imported binding cannot be
// assigned. Two counters would give both halves an `update-x-1.json` and
// assertRefused's "it wrote <out>" check would start reading another test's
// leftovers.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanEnv } from "../lib/git-env.mjs";

import { REPO_ROOT } from "../lib/sources.mjs";
import { contentProblems, envelopeProblems } from "../sign-update-manifest.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { UPDATE_SCHEMA, signEnvelope, verifyEnvelope } from "../../bot/lib/sign.mjs";
import { test, assert, assertEqual, neverAsk, tmp } from "./harness.mjs";
import { ROOT_B_KEY_ID, TRUST_ROOT_A } from "./fixtures.mjs";
import {
  PRODUCTION_ROOTS, TRUST_ROOT_B, UPDATE_NOTES_EN, UPDATE_SIGNER, UPDATE_SIGNER_PUB,
  assertRefused, freshArgs, hoursFromNow, nextSeq, pretty, readText,
  updateDoc, updateSandbox, updateSigner, updateSignerAt, updateTmp,
  withDuplicateVersion, withUnpaddedSignature, writeUpdateDoc, writeUpdateText,
} from "./update-fixtures.mjs";

export async function run() {
  await test("--check-notes and signing give one verdict on each server trigger, taken alone", () => {
    // minice api/crates/astra-server/src/updates.rs `load`: a note containing '<', "](",
    // "http://" or "https://" makes the server refuse the whole manifest. Nothing else does.
    const corpus = [
      ["a < b", false],
      ["x](y", false],
      ["http://x", false],
      ["https://x", false],
      ["a > b", true], // not a server trigger, and plain text as the client renders it
      ["HTTPS://x", true], // the server's rule is case-sensitive, and this one is the same rule
      ["plain words", true],
    ];
    const dir = updateSandbox();
    for (const [text, accepted] of corpus) {
      const notesDir = path.join(tmp, `update-corpus-${nextSeq()}`);
      fs.mkdirSync(notesDir, { recursive: true });
      fs.writeFileSync(path.join(notesDir, "notes.en.txt"), `${text}\n`);
      const check = updateSigner(["--check-notes", notesDir], REPO_ROOT);
      const out = updateTmp("corpus");
      const sign = updateSigner([...freshArgs("0.2.6", path.join(notesDir, "notes.en.txt")), "--out", out], dir);
      assertEqual(check.status, accepted ? 0 : 1, `--check-notes on ${JSON.stringify(text)}: ${check.stderr}`);
      assertEqual(sign.status, accepted ? 0 : 1, `signing with ${JSON.stringify(text)}: ${sign.stderr}`);
      if (!accepted) {
        assert(check.stderr.includes("markup or a link"), check.stderr);
        assert(sign.stderr.includes("markup or a link"), sign.stderr);
      }
    }
  });

  await test("--check-notes refuses empty notes, missing English, unknown or doubled locales; accepts files", () => {
    const notesDir = (name, files) => {
      const d = path.join(tmp, `update-notes-${name}-${nextSeq()}`);
      fs.mkdirSync(d, { recursive: true });
      for (const [f, t] of Object.entries(files)) fs.writeFileSync(path.join(d, f), t);
      return d;
    };
    // A README beside the notes is not a note, whatever it contains.
    const ok = notesDir("ok", { "notes.en.txt": "Plain.\n", "notes.ru.txt": "Просто.\n", "README.md": "<b>x</b>" });
    let r = updateSigner(["--check-notes", ok], REPO_ROOT);
    assertEqual(r.status, 0, `good notes refused: ${r.stderr}`);
    assert(r.stdout.includes("notes ok: en ru"), r.stdout);
    const refusals = [
      ["empty", [notesDir("empty", { "notes.en.txt": "Fine.", "notes.ru.txt": " \n\t\n" })], "are empty"],
      ["no-en", [notesDir("no-en", { "notes.ru.txt": "Только по-русски." })], "no English notes"],
      ["de", [notesDir("de", { "notes.en.txt": "Fine.", "notes.de.txt": "Gut." })], "not a locale the manifest carries"],
      ["twice", [ok, notesDir("again", { "notes.en.txt": "Again." })], "a second set of en notes"],
      ["no locale in the name", [path.join(ok, "README.md")], "cannot tell which locale"],
    ];
    for (const [name, paths, expect] of refusals) {
      assertRefused(updateSigner(["--check-notes", ...paths], REPO_ROOT), expect, undefined, name);
    }
    r = updateSigner(["--check-notes", path.join(ok, "notes.en.txt"), path.join(ok, "notes.ru.txt")], REPO_ROOT);
    assertEqual(r.status, 0, `the same notes as files: ${r.stderr}`);
    for (const v of ["0.2.4", "0.2.5"]) {
      r = updateSigner(["--check-notes", path.join("releases", v)], REPO_ROOT);
      assertEqual(r.status, 0, `releases/${v}: ${r.stderr}`);
    }
  });

  await test("--verify says ok only for a document a client would accept now", () => {
    // Not every refusal is asked HERE, and the rest are not unasked. Each was
    // measured on 2026-09-22 by breaking the rule in tools/sign-update-manifest.mjs
    // and reading which check went red. A signature that does not verify —
    // a key root.json does not publish, bytes altered after signing — reddens
    // `--verify --receipt binds…` and `--renew refuses a previous document…`,
    // which reach the same envelopeProblems. A v2 body under the v1 domain
    // reddens `--renew refuses…`. A byte only a lenient decoder reads, and a
    // byte-order mark, redden `--verify --receipt binds…`, which is this same
    // verifyFile with a receipt. The artefact and notes rules redden `--renew
    // re-checks every claim…`, over the same contentProblems. A version that is
    // not SemVer is refused by the filename rules as well as by its own — the
    // filename must carry a SemVer version equal to it — so deleting its own
    // changes only the message. The three at the end of the list below
    // were asked nowhere at all.
    const dir = updateSandbox();
    const verify = (text) => updateSigner(["--verify", writeUpdateText(text)], dir);
    let r = verify(pretty(updateDoc()));
    assertEqual(r.status, 0, `a good document: ${r.stderr}`);
    assert(r.stdout.includes("would accept it"), r.stdout);
    r = verify(pretty(updateDoc({ signedAt: hoursFromNow(23) })));
    assertEqual(r.status, 0, `23 hours ahead is inside the client's 24: ${r.stderr}`);
    const cases = [
      ["expired", pretty(updateDoc({ signedAt: hoursFromNow(-48), expires: hoursFromNow(-1) })), "expired at"],
      ["signed 25 hours ahead", pretty(updateDoc({ signedAt: hoursFromNow(25) })), "more than 24 hours ahead"],
      ["a key written twice", withDuplicateVersion(updateDoc()), "appears twice"],
      ["a signature only Node's lenient base64 reads", withUnpaddedSignature(updateDoc()), "not canonical base64"],
      ["notes the server refuses", pretty(updateDoc({ mutate: (s) => { s.latest.notes.ru = "x](y"; } })), "markup or a link"],
      ["an uppercase digest", pretty(updateDoc({ mutate: (s) => { s.latest.artifacts[0].sha256 = "A".repeat(64); } })), "not 64 lowercase hex"],
      ["a body this repository cannot canonicalise", (() => {
        const d = structuredClone(updateDoc());
        d.signed.latest.artifacts[0].sizeBytes = 1.5;
        return pretty(d);
      })(), "cannot be canonicalised"],
      // The three below are the repair. Each was deleted from
      // tools/sign-update-manifest.mjs on 2026-09-22 with all 317 checks green,
      // and each time `--verify` printed `ok` and "a client … would accept it"
      // over a document the client refuses — for the first, with `NaN days
      // left` in the reading an operator is told to trust.
      ["an expires that is not an instant", pretty(updateDoc({ expires: "2027-03-10" })),
        'expires "2027-03-10" is not an RFC 3339 instant'],
      ["a signedAt that is not an instant", pretty(updateDoc({ signedAt: "2026-09-21" })),
        'signedAt "2026-09-21" is not an RFC 3339 instant'],
      ["an artefact list that offers nothing", pretty(updateDoc({ mutate: (s) => { s.latest.artifacts = []; } })),
        "latest.artifacts offers nothing"],
    ];
    for (const [name, text, expect] of cases) assertRefused(verify(text), expect, undefined, name);
  });

  await test("the primary key is the active root; the reserve signs as the primary only with --reserve", () => {
    const dir = updateSandbox();
    const rest = freshArgs().slice(2);
    let out = updateTmp("x");
    assertRefused(updateSigner(["--root-key", TRUST_ROOT_B.file, ...rest, "--out", out], dir),
      "is the reserve root, and this needs the active one", out, "the reserve, by accident");
    out = updateTmp("x");
    assertRefused(updateSigner([...freshArgs(), "--reserve", "--out", out], dir),
      "is the active root, and this needs the reserve one", out, "--reserve with the active key");
    out = updateTmp("reserve");
    let r = updateSigner(["--root-key", TRUST_ROOT_B.file, "--reserve", ...rest, "--out", out], dir);
    assertEqual(r.status, 0, `the reserve, asked for: ${r.stderr}`);
    out = updateTmp("both");
    r = updateSigner([...freshArgs(), "--also-reserve", TRUST_ROOT_B.file, "--out", out], dir);
    assertEqual(r.status, 0, `both roots: ${r.stderr}`);
    assertEqual(JSON.parse(readText(out)).signatures.length, 2, "signatures");
  });

  await test("signing afresh refuses an older version than the newest record, and a signedAt not later than it", () => {
    const dir = updateSandbox([updateDoc()]);
    let out = updateTmp("x");
    assertRefused(updateSigner([...freshArgs("0.2.4"), "--out", out], dir), "--withdraw-to releases/0.2.4/manifest.json", out, "an older release");
    out = updateTmp("fresh");
    const r = updateSigner([...freshArgs("0.2.6"), "--out", out], dir);
    assertEqual(r.status, 0, `a newer release: ${r.stderr}`);
    const ahead = updateSandbox([updateDoc({ signedAt: hoursFromNow(24) })]);
    out = updateTmp("x");
    assertRefused(updateSigner([...freshArgs("0.2.6"), "--out", out], ahead),
      "not strictly later than releases/0.2.5/manifest.json", out, "a record dated tomorrow");

    // ── the repair: three cases the four above could not tell apart ──────────
    //
    // Measured 2026-09-22, each with all 317 checks green: the signedAt rule
    // in signFresh weakened from "strictly later" to "not earlier"; the
    // signedAt rule pointed at the record with the highest VERSION instead of
    // the one signed last; and the version rule pointed at the record signed
    // last instead of the highest version. The fixtures above hold one record
    // at a time, where the last-signed and the highest-versioned are the same
    // record, and dated a day ahead, where "earlier" and "equal" answer alike.

    // Equal at the seconds signedAt is published in, which no running clock
    // reaches on purpose. `updateSignerAt` stops the child's clock half a second
    // into the record's own second; a second later is the other side of the rule.
    const at = hoursFromNow(-1);
    const same = updateSandbox([updateDoc({ signedAt: at })]);
    out = updateTmp("x");
    assertRefused(updateSignerAt(Date.parse(at) + 500, [...freshArgs("0.2.6"), "--out", out], same),
      "not strictly later than releases/0.2.5/manifest.json", out, "signed in the record's own second");
    out = updateTmp("next-second");
    const next = updateSignerAt(Date.parse(at) + 1000, [...freshArgs("0.2.6"), "--out", out], same);
    assertEqual(next.status, 0, `one second after the record: ${next.stderr}`);

    // After a withdrawal the record signed LAST is not the one offering the
    // highest version, and each rule has its own: signedAt against the last
    // signed, the version against the highest offered.
    const withdrawnAhead = updateSandbox([
      updateDoc({ version: "0.2.5", signedAt: hoursFromNow(-48) }),
      updateDoc({ version: "0.2.4", signedAt: hoursFromNow(24) }),
    ]);
    out = updateTmp("x");
    assertRefused(updateSigner([...freshArgs("0.2.6"), "--out", out], withdrawnAhead),
      "not strictly later than releases/0.2.4/manifest.json", out, "a withdrawal signed after the highest version");
    const withdrawn = updateSandbox([
      updateDoc({ version: "0.2.5", signedAt: hoursFromNow(-48) }),
      updateDoc({ version: "0.2.4", signedAt: hoursFromNow(-24) }),
    ]);
    out = updateTmp("x");
    assertRefused(updateSigner([...freshArgs("0.2.4"), "--out", out], withdrawn),
      "is older than the 0.2.5 that releases/0.2.5/manifest.json offers", out, "the withdrawn-to version, signed afresh");
  });

  await test("--verify --receipt binds the verdict to the exact bytes it read, written only after every check passes", () => {
    const dir = updateSandbox();
    const hex = (b) => crypto.createHash("sha256").update(b).digest("hex");
    const B = loadTestRoot("TEST-ONLY-DO-NOT-TRUST-root-b");
    const both = signEnvelope({
      domain: UPDATE_SCHEMA,
      signed: updateDoc().signed,
      signers: [
        { key_id: UPDATE_SIGNER.key_id, privateKey: UPDATE_SIGNER.privateKey },
        { key_id: B.key_id, privateKey: B.privateKey },
      ],
    });
    // CRLF line ends and trailing whitespace: valid JSON whose re-serialisation hashes differently.
    const text = `${pretty(both).replace(/\n/g, "\r\n")}  `;
    const file = writeUpdateText(text);
    const bytes = fs.readFileSync(file);
    assert(hex(bytes) !== hex(pretty(JSON.parse(text))), "premise: the bytes are not their re-serialisation");
    const receipt = `${file}.verified`;
    const r = updateSigner(["--verify", file, "--receipt", receipt], dir);
    assertEqual(r.status, 0, `--verify --receipt: ${r.stderr}`);
    const got = JSON.parse(readText(receipt));
    assertEqual(Object.keys(got).join(","), "schema,file,sha256,bytes,version,signedAt,expires,key_ids,verified_at", "members, in order");
    assertEqual(got.schema, "astra.update-verify-receipt/1", "schema");
    assertEqual(got.file, path.basename(file), "file");
    assertEqual(got.sha256, hex(bytes), "sha256 of the exact bytes read");
    assertEqual(got.bytes, bytes.length, "bytes");
    assertEqual(got.version, both.signed.latest.version, "version");
    assertEqual(got.signedAt, both.signed.signedAt, "signedAt");
    assertEqual(got.expires, both.signed.expires, "expires");
    assertEqual(got.key_ids.join(","), `${UPDATE_SIGNER.key_id},${B.key_id}`, "every published root that signed");
    assert(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(got.verified_at), `verified_at ${got.verified_at}`);
    assert(Math.abs(Date.parse(got.verified_at) - Date.now()) < 120000, `verified_at ${got.verified_at} is not now`);
    assertEqual(
      fs.readdirSync(path.dirname(receipt)).filter((n) => n.startsWith(`.${path.basename(receipt)}.`)).length,
      0,
      "a temp file was left beside the receipt",
    );

    // Temp file plus rename: a hard link to the previous receipt keeps its bytes, where a rewrite in
    // place would change them under the reader.
    fs.writeFileSync(receipt, "stale\n");
    const link = `${receipt}.link`;
    fs.linkSync(receipt, link);
    const again = updateSigner(["--verify", file, "--receipt", receipt], dir);
    assertEqual(again.status, 0, again.stderr);
    assertEqual(readText(link), "stale\n", "the receipt was rewritten in place rather than replaced by a rename");
    assert(readText(receipt).startsWith('{"schema":'), "the new receipt");

    // Refused: nothing written. The last two are bytes only a lenient decoder would have accepted.
    const lenientOnly = (() => {
      const d = updateDoc({ mutate: (s) => { s.latest.notes.en = "Replacement \uFFFD kept."; } });
      const buf = Buffer.from(pretty(d));
      const at = buf.indexOf(Buffer.from([0xef, 0xbf, 0xbd]));
      assert(at > 0, "premise: U+FFFD is in the file");
      const raw = Buffer.concat([buf.subarray(0, at), Buffer.from([0xff]), buf.subarray(at + 3)]);
      assert(verifyEnvelope(JSON.parse(raw.toString("utf8")), UPDATE_SCHEMA, UPDATE_SIGNER_PUB).ok, "premise: it verifies once leniently decoded");
      return raw;
    })();
    const cases = [
      ["expired", pretty(updateDoc({ signedAt: hoursFromNow(-48), expires: hoursFromNow(-1) })), "expired at"],
      ["a bad signature", (() => { const d = updateDoc(); d.signed.latest.artifacts[0].sizeBytes += 1; return pretty(d); })(), "does not verify"],
      ["a key written twice", withDuplicateVersion(updateDoc()), "appears twice"],
      ["a byte only a lenient decoder reads", lenientOnly, "not valid UTF-8"],
      ["a byte-order mark", `\uFEFF${pretty(updateDoc())}`, "it is not JSON"],
    ];
    for (const [name, content, expect] of cases) {
      const f = updateTmp("refused");
      fs.writeFileSync(f, content);
      const rc = `${f}.verified`;
      assertRefused(updateSigner(["--verify", f, "--receipt", rc], dir), expect, rc, name);
    }

    const good = writeUpdateDoc(updateDoc());
    const goodBefore = readText(good);
    assertRefused(updateSigner(["--verify", good, "--receipt", good], dir), "is the verified file itself", undefined, "--receipt = the file");
    assertEqual(readText(good), goodBefore, "the verified file was overwritten");
    assertRefused(updateSigner(["--verify", good, "--receipt", "releases/0.2.5/manifest.json.verified"], dir),
      "lies under releases/", path.join(dir, "releases", "0.2.5", "manifest.json.verified"), "--receipt under releases/");
  });

  await test("--receipt belongs to --verify alone: every other mode refuses it and writes nothing", () => {
    const dir = updateSandbox([updateDoc({ version: "0.2.4", signedAt: hoursFromNow(-48) }), updateDoc()]);
    const receipt = updateTmp("receipt");
    const cases = [
      ["signing", [...freshArgs(), "--out", updateTmp("x")], "--receipt is not a flag signing accepts"],
      ["--renew", ["--renew", "releases/0.2.5/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", updateTmp("x")],
        "--receipt is not a flag --renew accepts"],
      ["--withdraw-to", ["--withdraw-to", "releases/0.2.4/manifest.json", "--root-key", TRUST_ROOT_A.file, "--out", updateTmp("x")],
        "--receipt is not a flag --withdraw-to accepts"],
      ["--check-notes", ["--check-notes", path.join(REPO_ROOT, "releases", "0.2.5")], "--receipt is not a flag --check-notes accepts"],
    ];
    for (const [name, args, expect] of cases) {
      assertRefused(updateSigner([...args, "--receipt", receipt], dir), expect, receipt, name);
    }
  });

  await test("every committed release manifest verifies against the production roots and carries the notes beside it", () => {
    // Not freshness: a record is history, and 0.2.4's expired document stays a correct record of it.
    const releases = path.join(REPO_ROOT, "releases");
    let seen = 0;
    for (const v of fs.readdirSync(releases).sort()) {
      const file = path.join(releases, v, "manifest.json");
      if (!fs.existsSync(file)) continue;
      seen++;
      const { doc, problems } = envelopeProblems(readText(file), PRODUCTION_ROOTS);
      assertEqual(problems.join("; "), "", `releases/${v}/manifest.json`);
      assertEqual(contentProblems(doc.signed).join("; "), "", `releases/${v}/manifest.json content`);
      assertEqual(doc.signed.latest.version, v, `releases/${v}: the directory and the signed version disagree`);
      const locales = fs.readdirSync(path.join(releases, v))
        .map((n) => /^notes\.([^.]+)\.txt$/.exec(n)?.[1])
        .filter(Boolean)
        .sort();
      assertEqual(Object.keys(doc.signed.latest.notes).sort().join(","), locales.join(","), `releases/${v}: locales`);
      for (const l of locales) {
        assertEqual(
          readText(path.join(releases, v, `notes.${l}.txt`)).trim(),
          doc.signed.latest.notes[l],
          `releases/${v}/notes.${l}.txt is not what was signed`,
        );
      }
    }
    assert(seen >= 2, `only ${seen} release manifests found; 0.2.4 and 0.2.5 are committed`);
  });

  await test("no release record ever committed has left the tree", () => {
    // The floor above is `seen >= 2`, and 2 is a hand-copy of today's count.
    // Measured 2026-09-22: deleting releases/0.2.4/manifest.json does redden
    // it — because the floor IS today's count, exactly. releases/0.2.6/ already
    // holds its notes; on the day its manifest lands, deleting any one of three
    // records leaves `seen` at 2 and that floor silent. (That is a prediction,
    // not a measurement: a third record that verifies needs a production root,
    // and this repository never holds one.)
    //
    // Deleting a record is not tidying. It is how an older release gets signed
    // afresh without `--withdraw-to`: the signer compares a new document with
    // the newest record it can find, and a record that is not there cannot be
    // newer. A record is history, so the second source for which records must
    // exist is the history, read here rather than copied into a number.
    const git = (...a) => execFileSync("git", ["-C", REPO_ROOT, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: cleanEnv() }).trim();
    if (git("rev-parse", "--is-shallow-repository") === "true") {
      neverAsk("this checkout is shallow, so the history that says which release records were ever committed is not in it",
        "a checkout with `fetch-depth: 0` asks it, as build-index.yml's does");
    }
    const ever = [...new Set(git("log", "--format=", "--name-only", "--diff-filter=A", "HEAD", "--", "releases/*/manifest.json")
      .split("\n").filter(Boolean))].sort();
    assert(ever.length >= 1, "git log finds no release record ever added under releases/, so the pathspec or the walk is broken");
    const gone = ever.filter((f) => !fs.existsSync(path.join(REPO_ROOT, f)));
    assertEqual(gone.join(", "), "",
      "a release record committed earlier is no longer in the tree; a record is what went live, and the signer's " +
      "newest-record comparison cannot see one that is gone");
  });
}
