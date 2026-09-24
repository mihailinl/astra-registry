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
      names.forEach((n, i) => {
        const vf = path.join(vdir, n);
        const v = JSON.parse(fs.readFileSync(vf, "utf8"));
        if (yank(i, names.length)) v.yanked = true; else delete v.yanked;
        fs.writeFileSync(vf, stableStringify(v));
      });
      return { dir, versions: names.length };
    };
    const mismatches = async (dir) => errorsMatching((await validateTree(dir)).report, "is not the listing's source repo");

    // Every old version still live: each one is refused. This is the rule doing
    // its job, and the reason the re-release cannot publish without step 1.
    const live = moved("moved-live", () => false);
    assert(live.versions >= 4, `astra-chess has ${live.versions} version file(s); it had 4 when this was written`);
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
}
