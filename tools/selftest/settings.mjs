// The repository settings, held to a committed expectation — the comparison's
// own tests (ops `dev/couplings.md` gap 22).
//
// `tools/coverage/settings.mjs` reads GitHub and the workflow trees every
// fifteen minutes in the coverage canary and hands `tools/lib/settings.mjs`
// plain values. This module hands it FIXTURES, so each clause of the rule is
// watched red here with no network, in every lane that runs the suite:
//
//   * the workflow reader: both spellings of a job's environment, a hold only
//     in the job's own literal `if: false`, and an `environment:` it cannot
//     attribute reported by line rather than skipped;
//   * the tree against the expectation: a named environment must be live with
//     a custom policy, or pending and held — and the same job with its
//     `if: false` removed is red naming the job and the environment;
//   * the expectation against the tree: an environment nobody names says why,
//     and a pending one somebody still names;
//   * GitHub against the expectation, both directions, for environments,
//     rulesets, the default branch and the rules in force on it, each field on
//     its own — and a member the live read could not fill is not compared as
//     though it were empty.
//
// It reads NO committed setting: not `policy/settings-expected.json`, which no
// bot run reads and which stays outside TRUST-31's set for that reason, and
// not the workflows. This suite is the publish path's fifth gate, and what the
// gate executes is `tools/lib/settings.mjs`, inside the set. The committed
// expectation is held to this tree by `bot/tests/moderation-coverage.test.mjs`
// on every pull request, and to GitHub by the canary.

import {
  EXPECTATION_SCHEMA, POLICY_KINDS, branchRulesFromApi, compareSettings, compareTree, environmentFromApi,
  expectationProblems, policyKind, rulesetFromApi, workflowJobs,
} from "../lib/settings.mjs";
import { test, assert, assertEqual } from "./harness.mjs";

const SLUG = "fixture/registry";

const env = (kind, policies = [], rules = ["branch_policy"], bypass = true) => ({
  deployment_branch_policy: kind,
  branch_policies: policies.map(([name, type]) => ({ name, type })),
  protection_rules: rules,
  can_admins_bypass: bypass,
});

const EXPECTED = () => ({
  tree: "checkout",
  default_branch: "main",
  environments: {
    alerts: env("custom", [["main", "branch"]]),
    publish: env("custom", [["main", "branch"]]),
    operator: {
      ...env("custom", [["main", "branch"]]),
      named_by_no_workflow: "the operator workflow lands later, and the environment was pinned first on purpose",
    },
  },
  pending_environments: {
    "bot-state": { task: "B-T5.0", why: "the owner creates it at R5, admitting only main, with its key" },
  },
  rulesets: {
    "history is append-only": {
      target: "branch", enforcement: "active",
      include: ["refs/heads/main", "refs/heads/signed"], exclude: [], rules: ["deletion", "non_fast_forward"],
    },
  },
  rules_on_default_branch: ["deletion", "non_fast_forward"],
});

const DOC = () => ({ schema: EXPECTATION_SCHEMA, repositories: { [SLUG]: EXPECTED() } });

// A workflow in the shapes this repository writes: the bare spelling, the
// two-line spelling with a `url:`, a hold, a STEP-level `if: false` that is
// not a hold, a folded condition, and a comment at the jobs' indentation.
const WORKFLOW = [
  "name: fixture",
  "on:",
  "  push:",
  "jobs:",
  "  # a comment at the jobs' indentation ends nothing",
  "  publish:",
  "    runs-on: ubuntu-24.04",
  "    environment: publish   # the signing key",
  "    steps:",
  "      - run: echo",
  "  alert:",
  "    if: >-",
  "      always() &&",
  "      !cancelled()",
  "    environment:",
  "      name: alerts",
  "      url: ${{ steps.deploy.outputs.url }}",
  "    steps:",
  "      - if: false",
  "        run: echo",
  "  load:",
  "    needs: roots",
  "    if: false",
  "    environment: bot-state",
  "    steps:",
  "      - run: echo",
  "  plain:",
  "    runs-on: ubuntu-24.04",
  "    steps:",
  "      - run: echo",
  "",
].join("\n");

const FILE = ".github/workflows/fixture.yml";
const tree = (text = WORKFLOW) => workflowJobs(text, FILE);

/** Replace exactly one occurrence, or throw: a mutation that matched nothing proves nothing. */
function once(text, from, to) {
  const n = text.split(from).length - 1;
  if (n !== 1) throw new Error(`the fixture edit ${JSON.stringify(from)} matched ${n} times, not once`);
  const out = text.replace(from, to);
  if (out === text) throw new Error(`the fixture edit ${JSON.stringify(from)} changed nothing`);
  return out;
}

const codes = (findings) => findings.map((f) => f.code);
const said = (findings) => findings.map((f) => `${f.code} ${f.detail}`).join("\n");

/** What GitHub's API returns, in the fixture's terms, before normalisation. */
const api = {
  env: (name, dbp, rules = ["branch_policy"], bypass = true) => ({
    name, deployment_branch_policy: dbp, protection_rules: rules.map((type, i) => ({ id: i + 1, type })), can_admins_bypass: bypass,
  }),
  custom: { protected_branches: false, custom_branch_policies: true },
  protectedOnly: { protected_branches: true, custom_branch_policies: false },
};

/** The live read that matches EXPECTED(), normalised as the canary normalises it. */
function LIVE() {
  const main = [{ id: 1, name: "main", type: "branch" }];
  return {
    default_branch: "main",
    environments: {
      alerts: environmentFromApi(api.env("alerts", api.custom), main),
      operator: environmentFromApi(api.env("operator", api.custom), main),
      publish: environmentFromApi(api.env("publish", api.custom), main),
    },
    rulesets: [{
      name: "history is append-only",
      ...rulesetFromApi({
        target: "branch", enforcement: "active",
        conditions: { ref_name: { include: ["refs/heads/signed", "refs/heads/main"], exclude: [] } },
        rules: [{ type: "non_fast_forward" }, { type: "deletion" }],
      }),
    }],
    rules_on_default_branch: branchRulesFromApi([{ type: "deletion" }, { type: "non_fast_forward" }, { type: "deletion" }]),
  };
}

export async function run() {
  console.log("\nthe repository settings, against the expectation and the workflows (ops gap 22)");

  await test("the workflow reader finds both spellings of a job's environment, and a hold only in the job's own `if: false`", () => {
    const { jobs, problems } = tree();
    assertEqual(problems.join(" / "), "", "the fixture workflow is one this reader must read without a problem");
    const by = Object.fromEntries(jobs.map((j) => [j.job, j]));
    assertEqual(jobs.map((j) => j.job).join(","), "publish,alert,load,plain", "the jobs found, in order");
    assertEqual(by.publish.environment, "publish", "the bare spelling, with a trailing comment");
    assertEqual(by.alert.environment, "alerts", "the two-line spelling, with a `url:` under it");
    assertEqual(by.load.environment, "bot-state", "a held job's environment is still read");
    assertEqual(by.plain.environment, null, "a job with no environment names none");
    assertEqual(by.load.held, true, "`if: false` on the job is a hold");
    assertEqual(by.alert.held, false, "a STEP's `if: false` is not the job's, and a folded condition is never a hold");
    assertEqual(by.alert.condition, ">- always() && !cancelled()", "the folded condition is gathered whole for the message");
    assertEqual(by.publish.environmentLine, 8, "the line a finding points at is the environment's own");
  });

  await test("an `environment:` the reader cannot resolve or attribute is a problem by line, never a skip", () => {
    const cases = {
      "an expression": once(WORKFLOW, "environment: publish   # the signing key", "environment: ${{ inputs.target }}"),
      "a block with no name": once(WORKFLOW, "      name: alerts\n", "      label: alerts\n"),
      "a key under a step": once(WORKFLOW, "      - run: echo\n  alert:", "      - run: echo\n        environment: publish\n  alert:"),
      "a flow mapping": once(WORKFLOW, "environment: publish   # the signing key", "environment: { name: publish }"),
    };
    for (const [why, text] of Object.entries(cases)) {
      const { problems } = tree(text);
      assert(problems.length >= 1, `${why}: the reader reported nothing about an environment line it did not read`);
      assert(problems.every((p) => p.startsWith(`${FILE}:`)), `${why}: a problem does not name its file and line: ${problems[0]}`);
      const t = compareTree(SLUG, EXPECTED(), { jobs: [], problems });
      assert(codes(t.findings).includes("SETTINGS_TREE_UNREAD"), `${why}: an unread environment line did not turn the comparison red`);
    }
  });

  await test("every environment a job names is live with a custom policy, or the job is named red", () => {
    const clean = compareTree(SLUG, EXPECTED(), tree());
    assertEqual(said(clean.findings), "", "the fixture tree against the fixture expectation is clean");

    for (const [kind, policies] of [["all", []], ["protected", []], ["custom", []]]) {
      const x = EXPECTED();
      x.environments.publish = env(kind, policies);
      const t = compareTree(SLUG, x, tree());
      assertEqual(codes(t.findings).join(","), "SETTINGS_TREE_ENV_UNPINNED", `publish recorded as ${kind} with ${policies.length} polic(ies)`);
      assert(/job `publish`/.test(t.findings[0].detail) && /`publish`/.test(t.findings[0].detail), "the finding does not name the job and the environment");
    }
    const unknown = compareTree(SLUG, EXPECTED(), tree(once(WORKFLOW, "environment: publish   # the signing key", "environment: npm")));
    assert(codes(unknown.findings).includes("SETTINGS_TREE_ENV_UNKNOWN"), `an environment the expectation does not know was accepted: ${said(unknown.findings)}`);
    assert(/`npm`/.test(said(unknown.findings)), "the unknown environment is not named");
  });

  await test("a job held by `if: false` may name a pending environment, and without the hold it is red naming both", () => {
    const held = compareTree(SLUG, EXPECTED(), tree());
    assertEqual(said(held.findings), "", "a held job naming a pending environment is not a finding");
    assert(held.notes.some((n) => /`bot-state` pending creation \(B-T5\.0\)/.test(n) && /job `load`/.test(n)),
      "the run does not say which environment is pending and which job holds its name");

    const unheld = {
      "the hold deleted": once(WORKFLOW, "    if: false\n    environment: bot-state", "    environment: bot-state"),
      "an expression": once(WORKFLOW, "    if: false\n    environment: bot-state", "    if: ${{ false }}\n    environment: bot-state"),
      "a quoted string": once(WORKFLOW, "    if: false\n    environment: bot-state", "    if: 'false'\n    environment: bot-state"),
      "some other condition": once(WORKFLOW, "    if: false\n    environment: bot-state", "    if: github.ref == 'refs/heads/main'\n    environment: bot-state"),
    };
    for (const [why, text] of Object.entries(unheld)) {
      const t = compareTree(SLUG, EXPECTED(), tree(text));
      assertEqual(codes(t.findings).join(","), "SETTINGS_TREE_ENV_NOT_LIVE", `${why}: ${said(t.findings)}`);
      assert(/job `load`/.test(t.findings[0].detail) && /`bot-state`/.test(t.findings[0].detail) && /B-T5\.0/.test(t.findings[0].detail),
        `${why}: the finding does not name the job, the environment and the task: ${t.findings[0].detail}`);
    }
  });

  await test("an environment the expectation lists and no job names is red unless it says why, and a stale reason is red too", () => {
    const x = EXPECTED();
    delete x.environments.operator.named_by_no_workflow;
    const t = compareTree(SLUG, x, tree());
    assertEqual(codes(t.findings).join(","), "SETTINGS_ENV_UNNAMED", said(t.findings));
    assert(/`operator`/.test(t.findings[0].detail), "the unnamed environment is not named");

    const stale = compareTree(SLUG, EXPECTED(), tree(once(WORKFLOW, "  plain:\n    runs-on: ubuntu-24.04", "  plain:\n    runs-on: ubuntu-24.04\n    environment: operator")));
    assertEqual(codes(stale.findings).join(","), "SETTINGS_ENV_REASON_STALE", said(stale.findings));
  });

  await test("a pending environment no job names any more is red", () => {
    const t = compareTree(SLUG, EXPECTED(), tree(once(WORKFLOW, "    environment: bot-state\n", "")));
    assertEqual(codes(t.findings).join(","), "SETTINGS_PENDING_STALE", said(t.findings));
    assert(/`bot-state`/.test(t.findings[0].detail) && /B-T5\.0/.test(t.findings[0].detail), "the stale pending entry is not named with its task");
  });

  await test("an environment GitHub has and the expectation does not is red, and so is the reverse", () => {
    assertEqual(said(compareSettings(SLUG, EXPECTED(), LIVE())), "", "the live fixture matches the expectation it was built for");

    const extra = LIVE();
    extra.environments.npm = environmentFromApi(api.env("npm", null), null);
    const e = compareSettings(SLUG, EXPECTED(), extra);
    assertEqual(codes(e).join(","), "SETTINGS_ENV_UNEXPECTED", said(e));
    assert(/`npm`/.test(e[0].detail) && /EVERY ref/.test(e[0].detail), "the extra environment and its open policy are not named");

    const created = LIVE();
    created.environments["bot-state"] = environmentFromApi(api.env("bot-state", null), null);
    const c = compareSettings(SLUG, EXPECTED(), created);
    assertEqual(codes(c).join(","), "SETTINGS_ENV_UNEXPECTED", said(c));
    assert(/pending creation \(B-T5\.0\)/.test(c[0].detail), "a pending environment that now exists is not reported as the one it is");

    const missing = LIVE();
    delete missing.environments.alerts;
    const m = compareSettings(SLUG, EXPECTED(), missing);
    assertEqual(codes(m).join(","), "SETTINGS_ENV_MISSING", said(m));
    assert(/`alerts`/.test(m[0].detail), "the missing environment is not named");
  });

  await test("each environment field that drifts is red, naming the environment and the field", () => {
    const mutations = {
      deployment_branch_policy: (l) => { l.environments.publish = environmentFromApi(api.env("publish", null), null); },
      branch_policies: (l) => { l.environments.publish = environmentFromApi(api.env("publish", api.custom), [{ name: "*", type: "branch" }]); },
      "branch_policies (a tag added)": (l) => {
        l.environments.publish = environmentFromApi(api.env("publish", api.custom), [{ name: "main", type: "branch" }, { name: "v*", type: "tag" }]);
      },
      protection_rules: (l) => { l.environments.publish = environmentFromApi(api.env("publish", api.custom, ["branch_policy", "required_reviewers"]), [{ name: "main", type: "branch" }]); },
      can_admins_bypass: (l) => { l.environments.publish = environmentFromApi(api.env("publish", api.custom, ["branch_policy"], false), [{ name: "main", type: "branch" }]); },
    };
    for (const [field, mutate] of Object.entries(mutations)) {
      const live = LIVE();
      mutate(live);
      const f = compareSettings(SLUG, EXPECTED(), live);
      assert(f.length >= 1 && f.every((x) => x.code === "SETTINGS_ENV_DRIFT"), `${field}: ${said(f) || "nothing reported"}`);
      assert(f.some((x) => x.detail.includes("`publish`") && x.detail.includes(field.split(" ")[0])),
        `${field}: the finding does not name the environment and the field: ${said(f)}`);
    }
  });

  await test("rulesets: missing, unexpected, duplicated, and each field's drift are red by name", () => {
    const missing = LIVE();
    missing.rulesets = [];
    assertEqual(codes(compareSettings(SLUG, EXPECTED(), missing)).join(","), "SETTINGS_RULESET_MISSING", "a deleted ruleset");

    const extra = LIVE();
    extra.rulesets.push({ name: "release tags", ...rulesetFromApi({ target: "tag", enforcement: "active", rules: [{ type: "deletion" }] }) });
    const e = compareSettings(SLUG, EXPECTED(), extra);
    assertEqual(codes(e).join(","), "SETTINGS_RULESET_UNEXPECTED", said(e));
    assert(/`release tags`/.test(e[0].detail), "the unexpected ruleset is not named");

    const twice = LIVE();
    twice.rulesets.push({ ...twice.rulesets[0] });
    assert(codes(compareSettings(SLUG, EXPECTED(), twice)).includes("SETTINGS_RULESET_DUPLICATE"), "two rulesets under one name were accepted");

    const fields = {
      enforcement: (r) => { r.enforcement = "evaluate"; },
      include: (r) => { r.include = ["refs/heads/main"]; },
      exclude: (r) => { r.exclude = ["refs/heads/signed"]; },
      rules: (r) => { r.rules = ["deletion"]; },
      target: (r) => { r.target = "tag"; },
    };
    for (const [field, mutate] of Object.entries(fields)) {
      const live = LIVE();
      mutate(live.rulesets[0]);
      const f = compareSettings(SLUG, EXPECTED(), live);
      assertEqual(codes(f).join(","), "SETTINGS_RULESET_DRIFT", `${field}: ${said(f)}`);
      assert(f[0].detail.includes(`\`history is append-only\` ${field}`), `${field}: the finding does not name the ruleset and field`);
    }
  });

  await test("the default branch, and the rules GitHub says are in force on it, are compared", () => {
    const renamed = LIVE();
    renamed.default_branch = "trunk";
    assertEqual(codes(compareSettings(SLUG, EXPECTED(), renamed)).join(","), "SETTINGS_DEFAULT_BRANCH", "a renamed default branch");
    const weaker = LIVE();
    weaker.rules_on_default_branch = ["deletion"];
    assertEqual(codes(compareSettings(SLUG, EXPECTED(), weaker)).join(","), "SETTINGS_BRANCH_RULES_DRIFT", "force-pushes allowed on main again");
  });

  await test("a member the live read could not fill is not compared, rather than compared as empty", () => {
    // The canary reports every failed read as SETTINGS_NOT_ASKED by route. The
    // comparison's half of that contract: an absent member is silence here,
    // never "GitHub has no environments", which would be seven false reds and
    // would bury the one NOT ASKED that explains them.
    for (const member of ["default_branch", "environments", "rulesets", "rules_on_default_branch"]) {
      const live = LIVE();
      delete live[member];
      assertEqual(said(compareSettings(SLUG, EXPECTED(), live)), "", `${member} left unread was compared anyway`);
    }
    assertEqual(said(compareSettings(SLUG, EXPECTED(), {})), "", "a read that failed entirely was compared as an empty repository");
  });

  await test("GitHub's policy object is one of three words, and a shape nobody documented is never `custom`", () => {
    assertEqual(policyKind(null), "all", "null is every ref");
    assertEqual(policyKind(api.protectedOnly), "protected", "protected branches only");
    assertEqual(policyKind(api.custom), "custom", "a custom list");
    for (const odd of [{ protected_branches: true, custom_branch_policies: true }, {}, "custom", { custom_branch_policies: true }]) {
      const k = policyKind(odd);
      assert(!POLICY_KINDS.includes(k), `${JSON.stringify(odd)} was read as ${k}`);
    }
    const e = environmentFromApi(api.env("x", null), [{ name: "main", type: "branch" }]);
    assertEqual(e.branch_policies.length, 0, "policies were kept for an environment that admits every ref, which GitHub does not do");
  });

  await test("the expectation's own shape is refused by name", () => {
    assertEqual(expectationProblems(DOC()).join(" / "), "", "the fixture expectation is well formed");
    const cases = {
      "an unknown environment member": (d) => { d.repositories[SLUG].environments.publish.brnach_policies = []; },
      "a pending environment also listed live": (d) => { d.repositories[SLUG].pending_environments.publish = { task: "X-T1", why: "listed twice to see it refused" }; },
      "a pending environment with no task": (d) => { d.repositories[SLUG].pending_environments["bot-state"].task = "later"; },
      "policies under a policy that keeps none": (d) => { d.repositories[SLUG].environments.publish.deployment_branch_policy = "all"; },
      "a reason that is not one": (d) => { d.repositories[SLUG].environments.operator.named_by_no_workflow = "because"; },
      "two checkouts": (d) => { d.repositories["fixture/other"] = { ...EXPECTED() }; },
      "an unknown enforcement": (d) => { d.repositories[SLUG].rulesets["history is append-only"].enforcement = "on"; },
      "a wrong schema": (d) => { d.schema = "astra.registry.settings/1"; },
    };
    for (const [why, mutate] of Object.entries(cases)) {
      const d = DOC();
      mutate(d);
      assert(expectationProblems(d).length >= 1, `${why} was accepted`);
    }
  });
}
