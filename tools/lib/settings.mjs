// The repository settings this estate depends on, held to a committed
// expectation — the pure half. ops `dev/couplings.md` gap 22.
//
// ── WHY THERE IS A COMPARISON AT ALL ────────────────────────────────────────
//
// Which refs may reach an environment, whether a branch can be force-pushed or
// deleted, and which environments exist at all are facts that live in NO tree.
// Every one of them pairs with something that is in a tree — `environment:
// publish` in `sign.yml`, the runbook's "admits only `main`", a job held by
// `if: false` until the owner creates its environment — and until this file
// nothing compared the two halves. The drift was real and was found by hand:
// `alerts` existed with no branch policy while seven workflows declared it,
// AstraPlugins' `master` could be deleted, and three publish environments
// there admitted every ref. Each was harmless until the day the plan's next
// step put a secret behind it.
//
// So three things are compared, each in both directions:
//
//   * GitHub's live answer against `policy/settings-expected.json`, the
//     committed expectation — every environment with its deployment-branch
//     policy, its protection-rule types and its admin bypass; every ruleset
//     with its target, enforcement, ref conditions and rule types; the default
//     branch and the rules GitHub says are in force on it;
//   * the workflow TREE against the expectation — every environment a job
//     names is live with a custom branch policy, or pending creation and named
//     only by jobs a literal `if: false` holds. A job that names an environment
//     which does not exist makes GitHub CREATE it on the job's first run, with
//     no branch policy at all: `alerts`' shape again, from one deleted line;
//   * the expectation against itself — an environment nobody names says why,
//     a pending one names the task that creates it.
//
// ── WHAT IS NOT HERE ────────────────────────────────────────────────────────
//
// No network, no file system, no clock. `tools/coverage/settings.mjs` reads
// the world and hands this module plain values; `tools/selftest/settings.mjs`
// hands it fixtures. It lives under `tools/lib/` — inside TRUST-31's hashed
// set — because the selftest runs it, and the selftest is the publish path's
// fifth gate: code a gate executes belongs inside what the service's
// acknowledgement covers, rather than one more row in ops entry 116's residual.
// The expectation itself is read by no bot run and stays outside the set.

/** The expectation document's schema string. */
export const EXPECTATION_SCHEMA = "astra.registry.settings-expected/1";

/** GitHub's three answers to "which refs may deploy here", as one word each. */
export const POLICY_KINDS = ["all", "protected", "custom"];

const ENFORCEMENTS = ["active", "evaluate", "disabled"];
const TREES = ["checkout", "remote"];

/**
 * `deployment_branch_policy` as one word.
 *
 * `null` is GitHub's way of saying every ref may deploy, and it is the state
 * `alerts` was found in. An object that is neither of the two documented
 * shapes is reported as itself rather than guessed at: reading an unknown
 * shape as `custom` would be the one mistake this whole file exists to catch.
 */
export function policyKind(dbp) {
  if (dbp === null || dbp === undefined) return "all";
  if (typeof dbp === "object") {
    if (dbp.protected_branches === true && dbp.custom_branch_policies === false) return "protected";
    if (dbp.custom_branch_policies === true && dbp.protected_branches === false) return "custom";
  }
  return `unrecognised ${JSON.stringify(dbp)}`;
}

const sortedUnique = (xs) => [...new Set(xs)].sort();
const byTypeThenName = (a, b) => (a.type === b.type ? (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) : a.type < b.type ? -1 : 1);

/**
 * One environment out of `/environments` plus its `/deployment-branch-policies`,
 * in the expectation's shape.
 *
 * @param {object} env              one element of `/environments`' `environments`
 * @param {{name: string, type?: string}[]|null} policies  the branch policies, or null when the kind is not `custom`
 */
export function environmentFromApi(env, policies) {
  const kind = policyKind(env.deployment_branch_policy);
  return {
    deployment_branch_policy: kind,
    branch_policies: kind === "custom"
      ? (policies ?? []).map((p) => ({ name: p.name, type: p.type ?? "branch" })).sort(byTypeThenName)
      : [],
    protection_rules: sortedUnique((env.protection_rules ?? []).map((r) => r.type)),
    can_admins_bypass: env.can_admins_bypass,
  };
}

/** One ruleset's detail (`/rulesets/{id}`), in the expectation's shape. */
export function rulesetFromApi(detail) {
  return {
    target: detail.target,
    enforcement: detail.enforcement,
    include: sortedUnique(detail.conditions?.ref_name?.include ?? []),
    exclude: sortedUnique(detail.conditions?.ref_name?.exclude ?? []),
    rules: sortedUnique((detail.rules ?? []).map((r) => r.type)),
  };
}

/** `/rules/branches/{branch}`: the rule TYPES GitHub says are in force there. */
export function branchRulesFromApi(list) {
  return sortedUnique((list ?? []).map((r) => r.type));
}

// ── the workflow tree ───────────────────────────────────────────────────────

const noise = (l) => l.trim() === "" || l.trim().startsWith("#");
const indentOf = (l) => l.search(/\S/);

/** A value with its trailing comment removed; a `#` inside quotes is not one. */
function stripComment(raw) {
  let quote = null;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (quote) { if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === "#" && (i === 0 || /\s/.test(raw[i - 1]))) return raw.slice(0, i);
  }
  return raw;
}

/** A plain or singly-quoted scalar, or `null` for anything this reader will not guess at. */
function scalarName(raw) {
  const v = stripComment(raw).trim();
  const q = /^'([^']*)'$|^"([^"\\]*)"$/.exec(v);
  const text = q ? (q[1] ?? q[2]) : v;
  if (text === "" || /[{}[\]$,:]/.test(text) || /\s/.test(text)) return null;
  return text;
}

const ENV_KEY = /^\s*(?:-\s+)?environment\s*:/;

/**
 * Every job in one workflow file, with the environment it names and whether a
 * literal `if: false` holds it.
 *
 * Line-oriented, with no YAML parser, for the reason `bot/tests/workflows.test.mjs`
 * gives: this repository has no dependencies, and a gate that needs a lockfile
 * stops running on the day the lockfile is argued about. So it is strict
 * instead of clever, and **it never skips**: every non-comment line in the file
 * that starts an `environment:` key must be one this reader attributed to a
 * job, or it is returned in `problems` by line number. A reader that missed an
 * environment would otherwise report the tree as naming fewer environments
 * than it does — green, about a job it never saw.
 *
 * "Held" means the job's own `if:` is the unquoted literal `false`, inline.
 * `${{ false }}`, `'false'`, a folded block and a STEP's `if: false` are all
 * not held: a false red is repaired by writing the literal, and a false hold
 * is the environment GitHub creates with no policy.
 *
 * @returns {{jobs: {file: string, job: string, line: number, environment: string|null,
 *            environmentLine: number|null, held: boolean, condition: string|null}[], problems: string[]}}
 */
export function workflowJobs(text, file = "<workflow>") {
  const lines = String(text).split("\n");
  const problems = [];
  const jobs = [];
  const attributed = new Set();

  const at = lines.findIndex((l) => /^jobs:\s*(#.*)?$/.test(l));
  const starts = [];
  let end = lines.length;
  if (at >= 0) {
    let jobIndent = null;
    for (let i = at + 1; i < lines.length; i++) {
      const l = lines[i];
      if (noise(l)) continue;
      const ind = indentOf(l);
      if (ind === 0) { end = i; break; }
      if (jobIndent === null) jobIndent = ind;
      if (ind < jobIndent) {
        problems.push(`${file}:${i + 1} is indented less than the jobs above it and more than a top-level key`);
        continue;
      }
      if (ind === jobIndent) {
        const m = /^\s*([A-Za-z0-9_-]+):\s*(#.*)?$/.exec(l);
        if (m) starts.push([i, m[1]]);
        else problems.push(`${file}:${i + 1} sits where a job's name belongs and is not one`);
      }
    }
  }

  for (let k = 0; k < starts.length; k++) {
    const [start, job] = starts[k];
    const stop = k + 1 < starts.length ? starts[k + 1][0] : end;
    const body = [];
    for (let i = start + 1; i < stop; i++) body.push(i);
    const first = body.find((i) => !noise(lines[i]));
    const keyIndent = first === undefined ? null : indentOf(lines[first]);
    let environment = null;
    let environmentLine = null;
    let condition = null;
    let held = false;
    for (let b = 0; b < body.length; b++) {
      const i = body[b];
      const l = lines[i];
      if (noise(l) || indentOf(l) !== keyIndent) continue;
      const m = /^\s*([A-Za-z0-9_-]+)\s*:(.*)$/.exec(l);
      if (!m) continue;
      const [, key, rest] = m;
      if (key === "if") {
        condition = stripComment(rest).trim();
        held = condition === "false";
        // A folded or literal block is gathered for the message only; it is
        // never a hold, whatever it says.
        if (/^[>|][-+]?$/.test(condition)) {
          const parts = [];
          for (let c = b + 1; c < body.length; c++) {
            const cl = lines[body[c]];
            if (cl.trim() === "") continue;
            if (indentOf(cl) <= keyIndent) break;
            parts.push(cl.trim());
          }
          condition = `${condition} ${parts.join(" ")}`.trim();
        }
      } else if (key === "environment") {
        attributed.add(i);
        environmentLine = i + 1;
        const inline = stripComment(rest).trim();
        if (inline !== "") {
          environment = scalarName(inline);
          if (environment === null) {
            problems.push(`${file}:${i + 1} job \`${job}\` names its environment as ${JSON.stringify(inline)}, which this reader does not resolve — write the name as a plain scalar`);
          }
          continue;
        }
        // The two-line spelling: `environment:` then `name: <env>` one level in.
        let name = null;
        for (let c = b + 1; c < body.length; c++) {
          const cl = lines[body[c]];
          if (noise(cl)) continue;
          if (indentOf(cl) <= keyIndent) break;
          const nm = /^\s*name\s*:(.*)$/.exec(cl);
          if (nm) { name = scalarName(nm[1]); break; }
        }
        environment = name;
        if (name === null) {
          problems.push(`${file}:${i + 1} job \`${job}\` has an \`environment:\` block with no plain \`name:\` this reader can read`);
        }
      }
    }
    jobs.push({ file, job, line: start + 1, environment, environmentLine, held, condition });
  }

  lines.forEach((l, i) => {
    if (noise(l) || !ENV_KEY.test(l) || attributed.has(i)) return;
    problems.push(
      `${file}:${i + 1} starts an \`environment:\` key that is not a job's own, so this reader did not count it. ` +
      "If it is a job's environment, the job is shaped in a way the reader does not follow; if it is not, rename it",
    );
  });
  return { jobs, problems };
}

// ── the expectation's own shape ─────────────────────────────────────────────

const REPO_KEYS = new Set(["$comment", "tree", "default_branch", "environments", "pending_environments", "rulesets", "rules_on_default_branch"]);
const ENV_KEYS = new Set(["$comment", "because", "named_by_no_workflow", "deployment_branch_policy", "branch_policies", "protection_rules", "can_admins_bypass"]);
const PENDING_KEYS = new Set(["$comment", "task", "why"]);
const RULESET_KEYS = new Set(["$comment", "target", "enforcement", "include", "exclude", "rules"]);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStringList = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");

/**
 * Everything wrong with the expectation document itself, as sentences.
 *
 * Strict about keys: a misspelt `brnach_policies` would otherwise be a member
 * nothing compares, and an environment whose policy nobody compares reads
 * exactly like one whose policy matched.
 */
export function expectationProblems(doc) {
  const out = [];
  if (!isObject(doc)) return ["the expectation is not a JSON object"];
  if (doc.schema !== EXPECTATION_SCHEMA) out.push(`schema is ${JSON.stringify(doc.schema)}, not ${EXPECTATION_SCHEMA}`);
  for (const k of Object.keys(doc)) if (!["schema", "$comment", "repositories"].includes(k)) out.push(`unknown top-level member ${JSON.stringify(k)}`);
  if (!isObject(doc.repositories) || Object.keys(doc.repositories).length === 0) {
    out.push("`repositories` names no repository, so there is nothing to compare");
    return out;
  }
  const checkouts = Object.entries(doc.repositories).filter(([, r]) => r?.tree === "checkout").map(([k]) => k);
  if (checkouts.length !== 1) out.push(`exactly one repository is read from this checkout; ${checkouts.length} say \`tree: "checkout"\``);
  for (const [slug, repo] of Object.entries(doc.repositories)) {
    const at = `repositories[${JSON.stringify(slug)}]`;
    if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(slug)) out.push(`${at}: not an owner/name slug`);
    if (!isObject(repo)) { out.push(`${at}: not an object`); continue; }
    for (const k of Object.keys(repo)) if (!REPO_KEYS.has(k)) out.push(`${at}: unknown member ${JSON.stringify(k)}`);
    if (!TREES.includes(repo.tree)) out.push(`${at}.tree is ${JSON.stringify(repo.tree)}, not one of ${TREES.join(", ")}`);
    if (typeof repo.default_branch !== "string" || repo.default_branch === "") out.push(`${at}.default_branch is not a branch name`);
    if (!isStringList(repo.rules_on_default_branch)) out.push(`${at}.rules_on_default_branch is not a list of rule types`);
    if (!isObject(repo.environments)) out.push(`${at}.environments is not an object`);
    for (const [name, env] of Object.entries(isObject(repo.environments) ? repo.environments : {})) {
      const e = `${at}.environments[${JSON.stringify(name)}]`;
      if (!isObject(env)) { out.push(`${e}: not an object`); continue; }
      for (const k of Object.keys(env)) if (!ENV_KEYS.has(k)) out.push(`${e}: unknown member ${JSON.stringify(k)}`);
      if (!POLICY_KINDS.includes(env.deployment_branch_policy)) out.push(`${e}.deployment_branch_policy is not one of ${POLICY_KINDS.join(", ")}`);
      if (!Array.isArray(env.branch_policies) || !env.branch_policies.every((p) => isObject(p) && typeof p.name === "string" && ["branch", "tag"].includes(p.type) && Object.keys(p).length === 2)) {
        out.push(`${e}.branch_policies is not a list of {name, type: branch|tag}`);
      } else if (env.deployment_branch_policy !== "custom" && env.branch_policies.length) {
        out.push(`${e} lists branch policies under a \`${env.deployment_branch_policy}\` policy, where GitHub keeps none`);
      }
      if (!isStringList(env.protection_rules)) out.push(`${e}.protection_rules is not a list of rule types`);
      if (typeof env.can_admins_bypass !== "boolean") out.push(`${e}.can_admins_bypass is not a boolean`);
      if ("named_by_no_workflow" in env && (typeof env.named_by_no_workflow !== "string" || env.named_by_no_workflow.trim().length < 20)) {
        out.push(`${e}.named_by_no_workflow must be the reason, in a sentence`);
      }
    }
    const pending = repo.pending_environments ?? {};
    if (!isObject(pending)) out.push(`${at}.pending_environments is not an object`);
    for (const [name, p] of Object.entries(isObject(pending) ? pending : {})) {
      const e = `${at}.pending_environments[${JSON.stringify(name)}]`;
      if (!isObject(p)) { out.push(`${e}: not an object`); continue; }
      for (const k of Object.keys(p)) if (!PENDING_KEYS.has(k)) out.push(`${e}: unknown member ${JSON.stringify(k)}`);
      if (typeof p.task !== "string" || !/^[A-Z][A-Z0-9]*-[A-Z0-9.]+/.test(p.task)) out.push(`${e}.task does not name the task that creates it`);
      if (typeof p.why !== "string" || p.why.trim().length < 20) out.push(`${e}.why must say, in a sentence, why it does not exist yet`);
      if (isObject(repo.environments) && name in repo.environments) out.push(`${e} is also listed as live, so the expectation says two things about it`);
    }
    if (!isObject(repo.rulesets)) out.push(`${at}.rulesets is not an object keyed by ruleset name`);
    for (const [name, r] of Object.entries(isObject(repo.rulesets) ? repo.rulesets : {})) {
      const e = `${at}.rulesets[${JSON.stringify(name)}]`;
      if (!isObject(r)) { out.push(`${e}: not an object`); continue; }
      for (const k of Object.keys(r)) if (!RULESET_KEYS.has(k)) out.push(`${e}: unknown member ${JSON.stringify(k)}`);
      if (typeof r.target !== "string") out.push(`${e}.target is not a string`);
      if (!ENFORCEMENTS.includes(r.enforcement)) out.push(`${e}.enforcement is not one of ${ENFORCEMENTS.join(", ")}`);
      for (const k of ["include", "exclude", "rules"]) if (!isStringList(r[k])) out.push(`${e}.${k} is not a list of strings`);
    }
  }
  return out;
}

// ── the comparisons ─────────────────────────────────────────────────────────

const show = (v) => JSON.stringify(v);
const canon = (v) => JSON.stringify(Array.isArray(v) ? [...v].sort((a, b) => (show(a) < show(b) ? -1 : 1)) : v);
const ENV_FIELDS = ["deployment_branch_policy", "branch_policies", "protection_rules", "can_admins_bypass"];
const RULESET_FIELDS = ["target", "enforcement", "include", "exclude", "rules"];

/**
 * GitHub's live settings against the expectation, one repository, both
 * directions. Each finding is `{code, detail}` and names the environment or
 * ruleset and the field.
 *
 * @param {string} slug
 * @param {object} expected  one `repositories[slug]` of the expectation
 * @param {{default_branch?: string, environments?: object, rulesets?: {name: string}[],
 *          rules_on_default_branch?: string[]}} live  normalised; a member left out was NOT read
 */
export function compareSettings(slug, expected, live) {
  const out = [];
  const add = (code, detail) => out.push({ code, detail: `${slug}: ${detail}` });

  if ("default_branch" in live && live.default_branch !== expected.default_branch) {
    add("SETTINGS_DEFAULT_BRANCH", `the default branch is \`${live.default_branch}\` and the expectation says \`${expected.default_branch}\`. ` +
      "Every ruleset condition and branch policy here is spelled against a branch NAME, so a rename leaves them guarding a branch nobody uses");
  }

  if ("environments" in live) {
    const want = expected.environments ?? {};
    const pending = expected.pending_environments ?? {};
    for (const name of Object.keys(live.environments).sort()) {
      if (name in want) continue;
      if (name in pending) {
        add("SETTINGS_ENV_UNEXPECTED",
          `environment \`${name}\` exists, and the expectation still lists it as pending creation (${pending[name].task}). ` +
          `Somebody created it — the owner, or GitHub on a job's first run, which creates it with NO branch policy. ` +
          `It reads as ${describeEnv(live.environments[name])}; move it to \`environments\` with what it should be`);
      } else {
        add("SETTINGS_ENV_UNEXPECTED",
          `environment \`${name}\` exists (${describeEnv(live.environments[name])}) and the expectation does not list it. ` +
          "An environment is where a secret can be put; one nobody expected is one nobody is watching");
      }
    }
    for (const name of Object.keys(want).sort()) {
      const got = live.environments[name];
      if (!got) {
        add("SETTINGS_ENV_MISSING", `environment \`${name}\` is in the expectation and GitHub does not have it. ` +
          "The next job that names it re-creates it with no branch policy");
        continue;
      }
      for (const field of ENV_FIELDS) {
        if (canon(got[field]) !== canon(want[name][field])) {
          add("SETTINGS_ENV_DRIFT", `environment \`${name}\` ${field} is ${show(got[field])} and the expectation says ${show(want[name][field])}`);
        }
      }
    }
  }

  if ("rulesets" in live) {
    const want = expected.rulesets ?? {};
    const seen = new Map();
    for (const r of live.rulesets) seen.set(r.name, (seen.get(r.name) ?? 0) + 1);
    for (const [name, n] of [...seen].sort()) {
      if (n > 1) add("SETTINGS_RULESET_DUPLICATE", `${n} rulesets are named \`${name}\`, so the expectation cannot say which one it describes`);
    }
    for (const r of [...live.rulesets].sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (!(r.name in want)) {
        add("SETTINGS_RULESET_UNEXPECTED", `ruleset \`${r.name}\` (${r.enforcement}, ${r.target}, ${show(r.include)}, rules ${show(r.rules)}) is live and the expectation does not list it`);
      }
    }
    for (const name of Object.keys(want).sort()) {
      const got = live.rulesets.find((r) => r.name === name);
      if (!got) {
        add("SETTINGS_RULESET_MISSING", `ruleset \`${name}\` is in the expectation and GitHub does not have it: ${show(want[name].include)} ` +
          `lose ${show(want[name].rules)}`);
        continue;
      }
      for (const field of RULESET_FIELDS) {
        if (canon(got[field]) !== canon(want[name][field])) {
          add("SETTINGS_RULESET_DRIFT", `ruleset \`${name}\` ${field} is ${show(got[field])} and the expectation says ${show(want[name][field])}`);
        }
      }
    }
  }

  if ("rules_on_default_branch" in live && canon(live.rules_on_default_branch) !== canon(expected.rules_on_default_branch)) {
    add("SETTINGS_BRANCH_RULES_DRIFT",
      `the rules GitHub says are in force on \`${expected.default_branch}\` are ${show(live.rules_on_default_branch)} and the expectation says ` +
      `${show(expected.rules_on_default_branch)}. This is the effective answer, whatever the rulesets' own spelling says`);
  }
  return out;
}

function describeEnv(e) {
  const pol = e.deployment_branch_policy === "custom"
    ? `custom: ${e.branch_policies.map((p) => `${p.type} ${p.name}`).join(", ") || "no policy at all"}`
    : e.deployment_branch_policy === "all" ? "EVERY ref may deploy" : e.deployment_branch_policy;
  return pol;
}

/**
 * The workflow tree against the expectation, one repository.
 *
 * @param {string} slug
 * @param {object} expected   one `repositories[slug]` of the expectation
 * @param {{jobs: object[], problems: string[]}} tree  `workflowJobs` over every workflow file, concatenated
 * @returns {{findings: {code: string, detail: string}[], notes: string[]}}
 */
export function compareTree(slug, expected, tree) {
  const findings = [];
  const notes = [];
  const add = (code, detail) => findings.push({ code, detail: `${slug}: ${detail}` });
  const want = expected.environments ?? {};
  const pending = expected.pending_environments ?? {};

  for (const p of tree.problems) add("SETTINGS_TREE_UNREAD", p);

  const namedBy = new Map();
  for (const j of tree.jobs) {
    if (j.environment === null) continue;
    const who = `${j.file}:${j.environmentLine ?? j.line} (job \`${j.job}\`)`;
    if (!namedBy.has(j.environment)) namedBy.set(j.environment, []);
    namedBy.get(j.environment).push({ who, held: j.held, job: j });
    if (j.environment in want) {
      const e = want[j.environment];
      if (e.deployment_branch_policy !== "custom" || e.branch_policies.length === 0) {
        add("SETTINGS_TREE_ENV_UNPINNED",
          `${who} names environment \`${j.environment}\`, and the expectation records it as ${describeEnv(e)}. ` +
          "Every environment a workflow names must admit named refs only — a custom deployment-branch policy with at least one entry");
      }
    } else if (j.environment in pending) {
      if (!j.held) {
        add("SETTINGS_TREE_ENV_NOT_LIVE",
          `${who} names environment \`${j.environment}\`, which does not exist yet — the expectation lists it as pending creation ` +
          `(${pending[j.environment].task}) — and the job is not held by a literal \`if: false\`` +
          `${j.condition === null ? " (it has no job-level `if:` at all)" : ` (its \`if:\` is ${show(j.condition)})`}. ` +
          `On its first run GitHub creates \`${j.environment}\` with NO branch policy, so any ref could reach whatever is put in it. ` +
          `Restore \`if: false\`, or create the environment admitting only \`${expected.default_branch}\` first and move it to \`environments\``);
      }
    } else {
      add("SETTINGS_TREE_ENV_UNKNOWN",
        `${who} names environment \`${j.environment}\`, which the expectation neither lists as live nor as pending creation` +
        `${j.held ? " (the job is held by `if: false` today)" : ""}. List it: live, with its policy, or pending, with the task that creates it`);
    }
  }

  for (const name of Object.keys(want).sort()) {
    const by = namedBy.get(name) ?? [];
    const reason = want[name].named_by_no_workflow;
    if (by.length === 0 && !reason) {
      add("SETTINGS_ENV_UNNAMED",
        `environment \`${name}\` is live and no workflow job names it. An environment nobody uses is a place a secret can sit ` +
        "unwatched; delete it, or say why it exists in `named_by_no_workflow`");
    } else if (by.length > 0 && reason) {
      add("SETTINGS_ENV_REASON_STALE",
        `environment \`${name}\` says it is named by no workflow (${show(reason.slice(0, 80))}…), and ${by.map((b) => b.who).join(", ")} names it. Delete the reason`);
    } else if (by.length === 0) {
      notes.push(`${slug}: \`${name}\` is named by no workflow, declared: ${reason}`);
    }
  }
  for (const name of Object.keys(pending).sort()) {
    const by = namedBy.get(name) ?? [];
    if (by.length === 0) {
      add("SETTINGS_PENDING_STALE",
        `environment \`${name}\` is listed as pending creation (${pending[name].task}) and no workflow job names it any more. ` +
        "A pending entry that guards nothing is one that will shelter the next job to take the name");
    } else if (by.every((b) => b.held)) {
      notes.push(`${slug}: \`${name}\` pending creation (${pending[name].task}), named only by jobs held by \`if: false\`: ` +
        by.map((b) => b.who).join(", "));
    }
  }
  return { findings, notes };
}
