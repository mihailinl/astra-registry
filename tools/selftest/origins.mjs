// Where artifacts may come from: release.kind "direct" expressible only behind
// --allow-direct, an artifact that wanders off its base_url, repo/tag borrowed
// onto a direct release, a GitHub release still pinned after the URL pattern was
// widened, and both spellings of a `..` traversal.

import fs from "node:fs";
import path from "node:path";

import { stableStringify } from "../lib/canonical.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp, validateTree, errorsMatching } from "./harness.mjs";

export async function run() {
  console.log("\nwhere artifacts may come from");
  // A listing has to be able to say "these bytes live here" for a here that is not
  // github.com. Astra's daemon was built for it — `artifact_download_policy` adds
  // the artifact URL's own host to the allow-list, in as many words, "a
  // self-hosted or staging catalogue serves its artifacts from its own origin" —
  // and until `release.kind: "direct"` existed the schema could not express what
  // the daemon already accepted. These four tests are the two halves of that:
  // the shape is expressible, and it is pinned exactly as tightly as the GitHub
  // shape, to a different anchor.

  const DIRECT_BASE = "https://catalogue.internal.example:8443/astra/";

  /** A one-plugin tree whose single release is served from a non-GitHub origin. */
  function directTree(name, mutate = () => {}) {
    const dir = path.join(tmp, name);
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
    const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
    const v = JSON.parse(fs.readFileSync(vf, "utf8"));
    v.release = { kind: "direct", base_url: DIRECT_BASE };
    v.artifacts["linux-x64"].url = `${DIRECT_BASE}${v.artifacts["linux-x64"].filename}`;
    mutate(v);
    fs.writeFileSync(vf, stableStringify(v));
    return dir;
  }

  await test("a self-hosted origin is expressible — and only behind --allow-direct", async () => {
    const dir = directTree("direct-ok");
    const { report } = await validateTree(dir, { allowDirect: true });
    assert(report.errors.length === 0,
      `a listing served from its own origin was refused:\n${report.errors.map((e) => `${e.where}: ${e.message}`).join("\n")}`);
    assert(report.warnings.some((w) => w.message.includes("accepted as a direct release")),
      "it passed silently; a non-GitHub origin is a thing a reviewer must see");

    // The public catalogue's guarantee is unchanged: the flag is what buys it,
    // exactly like --allow-staging, and nothing in this repository passes it.
    const strict = await validateTree(dir);
    assert(errorsMatching(strict.report, "release.kind is `direct`").length === 1,
      "a non-GitHub origin was accepted by default");
  });

  await test("a direct artifact that wanders off its base_url is rejected", async () => {
    // The whole value of the anchor. Without this check `direct` would mean "any
    // URL a submitter typed", which is the thing the hardcoded GitHub pattern was
    // there to prevent — the fix has to keep the rule, not drop it.
    const dir = directTree("direct-wander", (v) => {
      v.artifacts["linux-x64"].url = `https://elsewhere.example/${v.artifacts["linux-x64"].filename}`;
    });
    const { report } = await validateTree(dir, { allowDirect: true });
    const hits = errorsMatching(report, "does not sit under the declared release");
    assert(hits.length === 1, `an off-origin URL was accepted:\n${report.errors.map((e) => e.message).join("\n")}`);
    assert(hits[0].hint.includes(DIRECT_BASE), `the error does not name the base_url: ${hits[0].hint}`);
  });

  await test("a direct release cannot borrow a repo and tag it does not have", async () => {
    // `repo`/`tag` next to a URL those fields did not produce reads as provenance
    // the entry does not carry — a listing that looks attested and is not.
    const dir = directTree("direct-provenance", (v) => {
      v.release.repo = "someone/dice-roller";
      v.release.tag = "v1.0.0";
    });
    const { report } = await validateTree(dir, { allowDirect: true });
    assert(errorsMatching(report, "is set on a `direct` release").length === 2,
      `repo and tag were accepted on a direct release:\n${report.errors.map((e) => e.message).join("\n")}`);
  });

  await test("widening the URL pattern did not unpin a GitHub release", async () => {
    // The regression this pair of changes could plausibly have introduced. The
    // schema used to be the thing refusing a foreign host; now the schema allows
    // any https origin and the pin lives entirely in the release-prefix check.
    // This is the reviewer's exact case: a loopback URL under a github_release.
    const dir = path.join(tmp, "github-foreign-host");
    fs.cpSync(path.join(REPO_ROOT, "tests/fixtures/id-collision/plugins/dice-roller"), path.join(dir, "plugins/dice-roller"), { recursive: true });
    const vf = path.join(dir, "plugins/dice-roller/versions/1.0.0.json");
    const v = JSON.parse(fs.readFileSync(vf, "utf8"));
    v.artifacts["linux-x64"].url = `https://127.0.0.1:8443/${v.artifacts["linux-x64"].filename}`;
    fs.writeFileSync(vf, stableStringify(v));
    const { report } = await validateTree(dir, { allowDirect: true });
    const hits = errorsMatching(report, "does not sit under the declared release");
    assert(hits.length === 1,
      `a github_release listing served bytes from another host:\n${report.errors.map((e) => e.message).join("\n")}`);
    assert(hits[0].hint.includes("https://github.com/someone/dice-roller/releases/download/v1.0.0/"),
      `the error does not name the release prefix: ${hits[0].hint}`);
  });

  await test("a url that climbs back out of its own prefix is rejected", async () => {
    // `startsWith` is a string test and a path is not a string to the client that
    // fetches it. Both spellings, because `%2e%2e` reaches many servers undecoded.
    for (const [name, tail] of [["plain", "../../"], ["encoded", "%2e%2e/%2e%2e/"]]) {
      const dir = directTree(`traversal-${name}`, (v) => {
        v.artifacts["linux-x64"].url = `${DIRECT_BASE}${tail}${v.artifacts["linux-x64"].filename}`;
      });
      const { report } = await validateTree(dir, { allowDirect: true });
      assert(errorsMatching(report, "`..` path segment").length === 1,
        `a ${name} traversal resolved out of its prefix unnoticed:\n${report.errors.map((e) => e.message).join("\n")}`);
    }
  });

  // M-T6.3 step 1 (OPEN-OWNER-10). astra-chess is listed from KNICE-TECH, a
  // login freed by the organisation's rename, and KNICE's re-release from
  // MINICE-AI/astra-chess is held R_IDENTITY_CHANGED (issue #76). Approving it
  // moves `source.repo`, and the four versions already published still record
  // KNICE-TECH, which is where they were really built. Built from the COMMITTED
  // listing rather than a made-up one, so that this is the tree the approval
  // will actually meet: a fixture that had never contained the case would prove
  // nothing about it.
  //
  // PRE-MOVE versions are the ones whose release.repo is not MOVED_TO. Once the
  // re-release is ingested the listing also holds versions built from MINICE-AI
  // (the publish path runs this suite on the DERIVED tree, with the new version
  // file in it): those are not pre-move, the yank cases leave them as they are,
  // and they are never refused. Counting every file as pre-move made this test
  // refuse the very publish it exists to allow (2026-11-16, astra-chess 0.1.19:
  // "4 of 5 pre-move versions refused").
  await test("a listing that moves repository keeps its yanked history, and no live version of the old one", async () => {
    const MOVED_TO = "MINICE-AI/astra-chess";
    const src = path.join(REPO_ROOT, "plugins", "astra-chess");
    assert(fs.existsSync(src), "plugins/astra-chess is gone; this test is about that listing and must be rewritten or deleted");
    const moved = (name, yank) => {
      const dir = path.join(tmp, name);
      fs.cpSync(src, path.join(dir, "plugins", "astra-chess"), { recursive: true });
      const pf = path.join(dir, "plugins", "astra-chess", "plugin.json");
      const p = JSON.parse(fs.readFileSync(pf, "utf8"));
      p.source.repo = MOVED_TO;
      fs.writeFileSync(pf, stableStringify(p));
      const vdir = path.join(dir, "plugins", "astra-chess", "versions");
      const names = fs.readdirSync(vdir).filter((n) => n.endsWith(".json")).sort();
      const pre = names.filter((n) => JSON.parse(fs.readFileSync(path.join(vdir, n), "utf8")).release?.repo !== MOVED_TO);
      pre.forEach((n, i) => {
        const vf = path.join(vdir, n);
        const v = JSON.parse(fs.readFileSync(vf, "utf8"));
        if (yank(i, pre.length)) v.yanked = true; else delete v.yanked;
        fs.writeFileSync(vf, stableStringify(v));
      });
      return { dir, versions: pre.length, after: names.length - pre.length };
    };
    const mismatches = async (dir) => errorsMatching((await validateTree(dir)).report, "is not the listing's source repo");

    // Every old version still live: each one is refused. This is the rule doing
    // its job, and the reason the re-release cannot publish without step 1.
    const live = moved("moved-live", () => false);
    assert(live.versions >= 4, `astra-chess has ${live.versions} pre-move version(s); it had 4 when this was written`);
    const liveHits = await mismatches(live.dir);
    assertEqual(liveHits.length, live.versions,
      `${liveHits.length} of ${live.versions} pre-move versions refused; every live version from the old repository must be`);

    // Every old version yanked: none is refused, so the approval can publish.
    const yanked = await mismatches(moved("moved-yanked", () => true).dir);
    assertEqual(yanked.length, 0,
      "a yanked pre-move version was still refused, so the approved re-release cannot publish:\n" +
      yanked.map((e) => `${e.where}: ${e.message}`).join("\n"));

    // And the exemption is exactly as wide as a yank: one version left live is
    // one refusal.
    const one = await mismatches(moved("moved-one-live", (i, n) => i !== n - 1).dir);
    assertEqual(one.length, 1, `${one.length} refusal(s) with one pre-move version left live; the exemption is wider than a yank`);
  });

  // Owner, 2026-11-19 (F7): a repository renamed inside a first-party account,
  // both ids unchanged, publishes without a hold, and the versions it left
  // under the old name are the same repository's: nothing for a person to
  // yank. Accepted only with a `published` decision record naming that old
  // name with the identity record's ids, and only when the old name's owner
  // login is the listing's own; a renamed ORGANISATION frees its old login,
  // so those versions are still yanked, as astra-chess's were.
  await test("a first-party rename inside one account keeps its live history; an organisation rename does not", async () => {
    const src = path.join(REPO_ROOT, "plugins", "astra-chess");
    const records = path.join(REPO_ROOT, "log", "decisions");
    assert(fs.existsSync(src), "plugins/astra-chess is gone; this test is about that listing and must be rewritten or deleted");
    const astraChessRecords = [];
    for (const y of fs.readdirSync(records)) for (const m of fs.readdirSync(path.join(records, y))) {
      for (const f of fs.readdirSync(path.join(records, y, m))) {
        const doc = JSON.parse(fs.readFileSync(path.join(records, y, m, f), "utf8"));
        if (doc.plugin_id === "astra-chess" && doc.state === "published") astraChessRecords.push({ rel: path.join(y, m, f), doc });
      }
    }
    const tree = (name, { renameTo, withRecords = true, unyankOld = false, ownerId = null }) => {
      const dir = path.join(tmp, name);
      fs.cpSync(src, path.join(dir, "plugins", "astra-chess"), { recursive: true });
      const pdir = path.join(dir, "plugins", "astra-chess");
      const p = JSON.parse(fs.readFileSync(path.join(pdir, "plugin.json"), "utf8"));
      p.source.repo = renameTo;
      fs.writeFileSync(path.join(pdir, "plugin.json"), stableStringify(p));
      if (ownerId) {
        const ident = JSON.parse(fs.readFileSync(path.join(pdir, "identity.json"), "utf8"));
        ident.repository_owner_id = ownerId;
        ident.repo = renameTo;
        fs.writeFileSync(path.join(pdir, "identity.json"), stableStringify(ident));
      }
      if (unyankOld) {
        for (const n of fs.readdirSync(path.join(pdir, "versions"))) {
          const vf = path.join(pdir, "versions", n);
          const v = JSON.parse(fs.readFileSync(vf, "utf8"));
          delete v.yanked;
          fs.writeFileSync(vf, stableStringify(v));
        }
      }
      if (withRecords) {
        for (const { rel, doc } of astraChessRecords) {
          fs.mkdirSync(path.dirname(path.join(dir, "log", "decisions", rel)), { recursive: true });
          fs.writeFileSync(path.join(dir, "log", "decisions", rel), stableStringify(ownerId ? { ...doc, repository_owner_id: ownerId } : doc));
        }
      }
      return dir;
    };
    const mismatches = async (dir) => errorsMatching((await validateTree(dir)).report, "is not the listing's source repo");
    const RENAMED = "MINICE-AI/astra-chess-renamed";

    const renamed = await mismatches(tree("fp-rename", { renameTo: RENAMED }));
    assertEqual(renamed.length, 0, "a version left under the old name by a first-party rename was refused:\n" +
      renamed.map((e) => `${e.where}: ${e.message}`).join("\n"));

    const unrecorded = await mismatches(tree("fp-rename-unrecorded", { renameTo: RENAMED, withRecords: false }));
    assertEqual(unrecorded.length, 1, `${unrecorded.length} refusal(s) with no decision record naming the old name; a record is the evidence`);

    const third = await mismatches(tree("tp-rename", { renameTo: RENAMED, ownerId: "36719" }));
    assertEqual(third.length, 1, `${third.length} refusal(s) for an owner id that is not first party; the exemption is first-party only`);

    // The KNICE-TECH versions, unyanked: same ids, but the old login is free.
    const org = await mismatches(tree("org-rename", { renameTo: "MINICE-AI/astra-chess", unyankOld: true }));
    assert(org.length >= 4, `${org.length} refusal(s) for live versions under a renamed organisation's freed login; each must be refused`);
  });
}
