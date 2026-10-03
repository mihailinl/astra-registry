// ROLL-60's step 0, kept fresh: the rolling re-sign of the rehearsal canary's
// `signed`, with the throwaway keys in `tools/testkeys/` and the real signer.
// The command line is `tools/testkeys/rehearsal-resign.mjs`, and canary-4's
// scheduled workflow runs it (the template is
// `tools/testkeys/rehearsal-resign.yml`). Everything that decides anything is
// here, where `tools/selftest/rehearsal-resign.mjs` runs it against local bare
// remotes on a fake clock.
//
// ── why it exists ───────────────────────────────────────────────────────────
//
// ROLL-60's R2 half is the plugins service's publisher serving a rehearsal
// step 0 end to end. A fixture's step 0 is signed once, at its T0, and its
// list expires seven days later. That is production policy, and the
// publisher holds it: it refuses a list whose `expires_at` passes
// `min(issued_at, judged_at) + 8 days`, so neither a list dated ahead of its
// reader (canary-3) nor a longer one can stand in. A step 0 the service
// may meet on any day therefore has to be kept fresh the way production's
// is: re-signed at equal serials, with a new `issued_at` and `expires_at`,
// once the served copy is 20 hours old (SERVE-41; D4).
//
// ── what it runs, and why nothing is hand-assembled ─────────────────────────
//
// The re-sign is `tools/signer/run.mjs --step sign` and `--step commit`, the
// program `sign.yml` runs, against a throwaway registry:
//
// - its `main` is the canary's own, whose history holds step 0's
//   Source-Commit (the `-s ours` merge);
// - its `signed` is the canary's `signed`, fetched;
// - its `origin` is itself, as in the fixture generator, so the signer's own
//   fetch and push stay on this disk.
//
// The signer decides, by its own D4 rules, whether the copy is old enough
// (20 h on a schedule or a dispatch, 34 h on a push). It signs at the serial
// its gates compute, which for an unchanged Source-Commit is the head's. This
// file then holds the new commit to everything the plugins service will hold
// it to. Only after that does it push one fast-forward commit to the canary.
// It never forces, and it never writes anywhere but the re-sign canary's
// `signed`.
//
// ── the keys ────────────────────────────────────────────────────────────────
//
// `--test-key astra-index-2026a=TEST-ONLY-DO-NOT-TRUST-index-2026a`, read by
// the signer from this repository's `tools/testkeys/`, whose private halves are
// committed on purpose. The workflow fetches this repository at a pinned
// commit, so the key bytes are that commit's. A real index key in the
// environment is refused here before the signer is started (the signer
// refuses it too).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { cleanEnv, fixtureEnv } from "./git-env.mjs";
import { stableStringify } from "./canonical.mjs";
import { LS_TREE, parseLsTree, treeModeProblems } from "./tree-modes.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATION_TTL_DAYS, REVOCATIONS_SCHEMA, TRUST_SCHEMA,
  publicKeyFromBase64, signingDigest, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { DOCUMENTS, OUTGOING_ONLY, RUN_ENV } from "../testkeys/make-rehearsal-r2.mjs";
import {
  CANARIES, PRODUCTION_SLUG, Refusal, effectiveUrlProblem, gitAt, githubUrl, loadSeries, pagesBaseOf, repoSlug,
  sourceCheck, targetProblem,
} from "./rehearsal-push.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");

/** The step the re-sign keeps fresh. Only step 0: every later step's parent is the fixture's step 0. */
export const RESIGN_STEP = "rotation/00-baseline";
/** The plugins service's bound on a list: `expires_at` at most `min(issued_at, judged_at)` + this. */
export const SERVICE_LIST_BOUND_DAYS = 8;
/**
 * A served list older than this is a red run: Table 5-C's 36-hour operator
 * alarm on production's served list. Under SERVE-41's 20 hours and a schedule
 * whose worst measured gap is 13.34 h, a served list is at most 33.34 h old.
 */
export const STALE_AFTER_HOURS = 36;
/** How far ahead of this run's clock an `issued_at` may be: runner skew, never a date in the future. */
export const FUTURE_SKEW_MS = 5 * 60 * 1000;

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const rfc3339 = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

/** The roots the plugins service compiles: the committed public halves of TEST root-a and root-b. */
export function testRoots() {
  return ["a", "b"].map((x) => {
    const k = JSON.parse(fs.readFileSync(path.join(REPO, "tools", "testkeys", `TEST-ONLY-DO-NOT-TRUST-root-${x}.pub.json`), "utf8"));
    return { key_id: k.key_id, public_key: k.public_key, publicKey: publicKeyFromBase64(k.public_key) };
  });
}

// ── the target ──────────────────────────────────────────────────────────────

/** The re-sign canaries: CANARIES entries marked `resign`. */
export const resignCanaries = () => Object.keys(CANARIES).filter((slug) => CANARIES[slug].resign);

/** The slug a run is for, or a Refusal (exit 2) before anything touches the network. */
export function resolveTarget(spec) {
  const given = spec ?? resignCanaries()[0];
  const problem = targetProblem(given);
  if (problem) throw new Refusal("TARGET", problem, 2);
  const slug = repoSlug(given);
  if (!CANARIES[slug].resign) {
    throw new Refusal("TARGET", `${slug} is a rehearsal canary whose step 0 is not re-signed; the re-sign canary is ` +
      `${resignCanaries().join(" and ")}. A re-sign anywhere else would put a commit on a \`signed\` its own cut cannot follow`, 2);
  }
  return { slug, fixtures: CANARIES[slug].fixtures };
}

// ── the documents ───────────────────────────────────────────────────────────

const contentOf = (doc) => {
  const { issued_at, expires_at, ...rest } = doc?.signed ?? {};
  return stableStringify(rest);
};

/**
 * Everything the plugins service will hold a re-signed step 0 to, asked of
 * four documents' bytes. Returns the problems; none means it may be served.
 *
 * `step0` is the fixture's step 0, and `now` is this run's clock. `previous`
 * is the head the documents replace, if any. When `resignedAt` is given, the
 * documents must be exactly that run's.
 */
export function documentProblems({ bytes, step0, now, previous = null, resignedAt = null, roots = testRoots() }) {
  const problems = [];
  const docs = {};
  for (const rel of DOCUMENTS) {
    if (typeof bytes[rel] !== "string" && !Buffer.isBuffer(bytes[rel])) { problems.push(`${rel} is missing`); continue; }
    try { docs[rel] = JSON.parse(String(bytes[rel])); } catch (e) { problems.push(`${rel} is not JSON (${e.message})`); }
  }
  if (problems.length) return problems;
  const [index, list, trust, root] = DOCUMENTS.map((rel) => docs[rel]);

  // trust.json and root.json are byte copies of main's at the Source-Commit (DEC-1; TRUST-3), so step 0's.
  for (const rel of ["registry/v1/trust.json", "registry/v1/root.json"]) {
    if (!Buffer.from(bytes[rel]).equals(Buffer.from(step0.docs[rel]))) problems.push(`${rel} is not step 0's bytes`);
  }
  // The roots the service compiles, current {root-a, root-b}, next {} (SERVE-16).
  const served = (root.roots ?? []).map((r) => `${r.key_id}=${r.public_key}`).sort().join(" ");
  if (served !== roots.map((r) => `${r.key_id}=${r.public_key}`).sort().join(" ")) problems.push("root.json's roots are not tools/testkeys' root-a and root-b");

  // Signatures, every one of them, the way SERVE-15 asks: trust.json under the
  // compiled roots, the catalogue and the list under trust.json's index keys.
  const each = (doc, domain, keys, rel) => {
    const v = verifyEnvelope(doc, domain, keys);
    if (!v.ok) { problems.push(`${rel} does not verify: ${v.reason}`); return; }
    const digest = signingDigest(domain, doc.signed);
    for (const s of doc.signatures ?? []) {
      const k = keys.find((x) => x.key_id === s.key_id);
      if (!k || !crypto.verify(null, digest, k.publicKey, Buffer.from(String(s.sig), "base64"))) {
        problems.push(`${rel}'s signature by ${s.key_id} does not verify under ${k ? "that key" : "any key of that id"}`);
      }
    }
  };
  each(trust, TRUST_SCHEMA, roots, "registry/v1/trust.json");
  const indexKeys = (trust.signed?.index_keys ?? []).map((k) => ({ key_id: k.key_id, publicKey: publicKeyFromBase64(k.public_key) }));
  each(index, INDEX_SCHEMA, indexKeys, "registry/v1/index.json");
  each(list, REVOCATIONS_SCHEMA, indexKeys, "registry/v1/revocations.json");

  const base = {
    "registry/v1/index.json": JSON.parse(String(step0.docs["registry/v1/index.json"])),
    "registry/v1/revocations.json": JSON.parse(String(step0.docs["registry/v1/revocations.json"])),
  };
  const ttl = { "registry/v1/index.json": CATALOG_TTL_DAYS, "registry/v1/revocations.json": REVOCATION_TTL_DAYS };
  for (const rel of ["registry/v1/index.json", "registry/v1/revocations.json"]) {
    const doc = docs[rel];
    const s = doc.signed ?? {};
    // Equal serials and equal content: a re-sign moves the dates and the signatures, nothing else.
    if (s.serial !== base[rel].signed.serial) problems.push(`${rel} is at serial ${s.serial}, and step 0's is ${base[rel].signed.serial}: a re-sign keeps the serial`);
    if (contentOf(doc) !== contentOf(base[rel])) problems.push(`${rel}'s signed content, dates aside, is not step 0's`);
    const issued = Date.parse(s.issued_at);
    const expires = Date.parse(s.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires)) { problems.push(`${rel} has no readable issued_at or expires_at`); continue; }
    if (expires - issued !== ttl[rel] * DAY_MS) problems.push(`${rel} is valid ${(expires - issued) / DAY_MS} days, not the signer's ${ttl[rel]}`);
    if (issued > now + FUTURE_SKEW_MS) problems.push(`${rel} is issued ${s.issued_at}, after this run's clock ${rfc3339(now)}`);
    if (expires <= now) problems.push(`${rel} expired at ${s.expires_at}`);
    if (resignedAt !== null && s.issued_at !== resignedAt) problems.push(`${rel} is issued ${s.issued_at}, not at this re-sign's ${resignedAt}`);
    if (previous) {
      const before = JSON.parse(String(previous[rel])).signed?.issued_at;
      if (!(issued > Date.parse(before))) problems.push(`${rel} is issued ${s.issued_at}, not later than the copy it replaces (${before}; SERVE-88)`);
    }
  }
  // The publisher's own bound on a list.
  const ls = list.signed ?? {};
  const from = Math.min(Date.parse(ls.issued_at), now);
  if (Date.parse(ls.expires_at) > from + SERVICE_LIST_BOUND_DAYS * DAY_MS) {
    problems.push(`registry/v1/revocations.json expires ${ls.expires_at}, past min(issued_at, now) + ${SERVICE_LIST_BOUND_DAYS} days, which the plugins service refuses`);
  }
  return problems;
}

/** A list's age, in hours, at `now`. */
export const listAgeHours = (bytes, now) =>
  (now - Date.parse(JSON.parse(String(bytes["registry/v1/revocations.json"])).signed.issued_at)) / HOUR_MS;

// ── git ─────────────────────────────────────────────────────────────────────

/**
 * A blob's bytes exactly, or null. Not `gitAt`, which trims what git prints:
 * a document that lost its last newline is a document the service never saw.
 */
export function blobBytes(dir, gitConfig, ref, rel) {
  const r = spawnSync("git", [...gitConfig.flatMap((c) => ["-c", c]), "-C", dir, "cat-file", "blob", `${ref}:${rel}`], {
    env: fixtureEnv(dir), stdio: ["ignore", "pipe", "pipe"],
  });
  return r.status === 0 ? Buffer.from(r.stdout) : null;
}

/**
 * Null when `head` is step 0 or a line of re-signs of it; otherwise why not.
 * Each commit after step 0 has one parent, changes only the four documents,
 * and carries step 0's trust.json and root.json.
 */
export function lineageProblem(git, step0, head) {
  if (head === step0.sha) return null;
  if (!git(["merge-base", "--is-ancestor", step0.sha, head], { allowFail: true }).ok) {
    return `\`signed\` is at ${head}, which does not descend from step 0 (${step0.sha}). Something other than the rehearsal pushed there`;
  }
  const line = git(["rev-list", "--parents", `${step0.sha}..${head}`]).out.split("\n").filter(Boolean);
  for (const entry of line) {
    const [sha, ...parents] = entry.split(" ");
    if (parents.length !== 1) return `${sha} on \`signed\` has ${parents.length} parents; a re-sign has one`;
    const changed = git(["diff", "--name-only", parents[0], sha]).out.split("\n").filter(Boolean);
    const stray = changed.filter((f) => !DOCUMENTS.includes(f));
    if (stray.length) return `${sha} on \`signed\` changes ${stray.join(", ")}, which no re-sign writes`;
    // The tree as the registry's tree rule lists it (tools/lib/tree-modes.mjs),
    // directories included. `ls-tree -r` alone lists leaves, so a commit that
    // carried the four documents and an empty directory beside them, or a
    // document as a link, read here as "D2's four documents".
    const rows = parseLsTree(git([...LS_TREE, sha]).out);
    const files = rows.filter((r) => r.mode !== "040000").map((r) => r.path).sort();
    if (files.join(" ") !== [...DOCUMENTS].sort().join(" ")) return `${sha} on \`signed\` holds ${files.join(", ")}, not D2's four documents`;
    const odd = treeModeProblems(rows, sha.slice(0, 12));
    if (odd.length) return `${sha} on \`signed\` holds ${odd.map((p) => `${p.path}: ${p.message}`).join("; ")}`;
    for (const rel of ["registry/v1/trust.json", "registry/v1/root.json"]) {
      if (git(["rev-parse", `${sha}:${rel}`]).out !== git(["rev-parse", `${step0.sha}:${rel}`]).out) {
        return `${sha} on \`signed\` carries a ${rel} that is not step 0's`;
      }
    }
  }
  return null;
}

// ── the signer ──────────────────────────────────────────────────────────────

/** The environment the signer runs in: no repository variables, no real key, no workflow outputs. */
function signerEnv(extra = {}) {
  const env = cleanEnv();
  for (const k of Object.keys(env)) {
    if (k.startsWith("ASTRA_INDEX_SIGNING_KEY") || k === "GITHUB_OUTPUT" || k === "GITHUB_STEP_SUMMARY") delete env[k];
  }
  return { ...env, ...extra };
}

function signer(args, env) {
  const r = spawnSync(process.execPath, [path.join("tools", "signer", "run.mjs"), ...args], {
    cwd: REPO, encoding: "utf8", env, stdio: ["ignore", "pipe", "pipe"],
  });
  return { status: r.status, out: r.stdout ?? "", err: r.stderr ?? "" };
}

// ── the command line ────────────────────────────────────────────────────────

export const USAGE = `usage: node tools/testkeys/rehearsal-resign.mjs [--repo owner/name] [--event schedule|workflow_dispatch|push] [--dry-run] [--evidence FILE]
       node tools/testkeys/rehearsal-resign.mjs --status [--repo owner/name]
       node tools/testkeys/rehearsal-resign.mjs --wait-pages [--repo owner/name] [--pages-timeout SECONDS] [--evidence FILE]
       node tools/testkeys/rehearsal-resign.mjs --audit-workflow FILE [--registry-sha SHA]
     --repo is a re-sign canary: ${resignCanaries().join(", ")}. With none, it is the first of them.`;

export function parseArgs(argv) {
  const a = { repo: null, event: null, dryRun: false, status: false, waitPages: false, audit: null, registrySha: null,
    evidence: null, pagesTimeout: 600 };
  const value = (i, flag) => {
    const v = argv[i];
    if (v === undefined || v.startsWith("--")) throw new Refusal("USAGE", `${flag} needs a value\n${USAGE}`, 2);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    if (f === "--repo") a.repo = value(++i, f);
    else if (f === "--event") a.event = value(++i, f);
    else if (f === "--dry-run") a.dryRun = true;
    else if (f === "--status") a.status = true;
    else if (f === "--wait-pages") a.waitPages = true;
    else if (f === "--audit-workflow") a.audit = value(++i, f);
    else if (f === "--registry-sha") a.registrySha = value(++i, f);
    else if (f === "--evidence") a.evidence = value(++i, f);
    else if (f === "--pages-timeout") a.pagesTimeout = Number(value(++i, f));
    else throw new Refusal("USAGE", `unknown argument ${JSON.stringify(f)}\n${USAGE}`, 2);
  }
  if ([a.status, a.waitPages, a.audit !== null].filter(Boolean).length > 1) {
    throw new Refusal("USAGE", `name at most one of --status, --wait-pages, --audit-workflow\n${USAGE}`, 2);
  }
  if (!(a.pagesTimeout >= 0)) throw new Refusal("USAGE", "--pages-timeout takes seconds", 2);
  return a;
}

/**
 * The whole run. Returns the exit code: 0 done (a re-sign pushed, or none
 * due), 1 a check did not hold, 2 refused before anything was asked.
 *
 * @param {string[]} argv
 * @param {{fetchImpl?: Function, gitConfig?: string[], log?: (l: string) => void, clock?: () => number,
 *          sleep?: (ms: number) => Promise<void>, pagesBase?: string, env?: NodeJS.ProcessEnv}} deps
 */
export async function main(argv, deps = {}) {
  const log = deps.log ?? ((l) => console.log(l));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rehearsal-resign-"));
  try {
    return await run(argv, { ...deps, log, tmp });
  } catch (e) {
    if (e instanceof Refusal) {
      log(`${e.exit === 2 ? "REFUSED" : "FAIL "} ${e.message}`);
      return e.exit;
    }
    throw e;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

const output = (env, pairs) => {
  const file = env.GITHUB_OUTPUT;
  if (file) fs.appendFileSync(file, `${Object.entries(pairs).map(([k, v]) => `${k}=${v}`).join("\n")}\n`);
};

function appendEvidence(file, record, log) {
  if (!file) return;
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify(record)}\n`);
  log(`ok    evidence appended to ${file}`);
}

const describeDocs = (bytes) => Object.fromEntries(DOCUMENTS.map((rel) => {
  const doc = JSON.parse(String(bytes[rel]));
  return [rel, {
    sha256: sha256(Buffer.from(bytes[rel])), serial: doc.signed?.serial ?? null,
    issued_at: doc.signed?.issued_at ?? null, expires_at: doc.signed?.expires_at ?? null,
    signed_by: (doc.signatures ?? []).map((s) => s.key_id),
  }];
}));

async function run(argv, { fetchImpl, gitConfig = [], log, clock = Date.now, sleep, pagesBase, env = process.env, tmp }) {
  const a = parseArgs(argv);
  if (a.audit !== null) return auditCommand(a, log);

  // 1. The target, before anything reads the network.
  const { slug, fixtures } = resolveTarget(a.repo);
  const realKey = Object.keys(env).filter((k) => k.startsWith("ASTRA_INDEX_SIGNING_KEY"));
  if (realKey.length) {
    throw new Refusal("REAL_KEY", `${realKey.join(", ")} is set in this environment. The rehearsal re-sign signs with ` +
      "tools/testkeys only, and a job that holds a real index key is not a job this may run in", 2);
  }
  const url = githubUrl(slug);
  pagesBase ??= pagesBaseOf(slug);
  const step0 = loadSeries("rotation", { fixtures })[0];
  if (step0.id !== RESIGN_STEP) throw new Refusal("FIXTURE", `${fixtures}'s first rotation step is ${step0.id}, not ${RESIGN_STEP}`);

  // 2. The canary, fetched into a throwaway registry.
  const work = path.join(tmp, "registry");
  fs.mkdirSync(work);
  const git = gitAt(work, gitConfig);
  git(["init", "-q", "-b", "rehearsal-work"]);
  git(["config", "user.email", "rehearsal@users.noreply.invalid"]);
  git(["config", "user.name", "rehearsal re-sign"]);
  git(["config", "commit.gpgsign", "false"]);
  git(["remote", "add", "canary", url]);
  for (const [which, args] of [["fetch", ["remote", "get-url", "canary"]], ["push", ["remote", "get-url", "--push", "canary"]]]) {
    const p = effectiveUrlProblem(git(args).out, url, which);
    if (p) throw new Refusal("TARGET", p, 2);
  }
  const fetched = git(["fetch", "--quiet", "--no-tags", "canary", "+refs/heads/signed:refs/heads/signed", "+refs/heads/main:refs/rehearsal/canary-main"], { allowFail: true });
  if (!fetched.ok) throw new Refusal("FETCH", `${slug} has no \`signed\` and \`main\` to re-sign from: ${fetched.err}. Push step 0 with rehearsal-push first`);
  const head = git(["rev-parse", "refs/heads/signed"]).out;
  const lineage = lineageProblem(git, step0, head);
  if (lineage) throw new Refusal("HEAD_FOREIGN", lineage);
  const headBytes = Object.fromEntries(DOCUMENTS.map((rel) => [rel, blobBytes(work, gitConfig, head, rel)]));
  const resigns = Number(git(["rev-list", "--count", `${step0.sha}..${head}`]).out);
  const nowMs = clock();
  const ageBefore = listAgeHours(headBytes, nowMs);

  if (a.status || a.waitPages) {
    log(`${slug}, fixtures ${fixtures}, step 0 ${step0.sha}`);
    log(`\`signed\`: ${head}${head === step0.sha ? " (step 0 itself)" : `, step 0 re-signed ${resigns} time(s)`}`);
    const list = JSON.parse(String(headBytes["registry/v1/revocations.json"])).signed;
    log(`list: serial ${list.serial}, issued ${list.issued_at} (${ageBefore.toFixed(2)} h ago), expires ${list.expires_at}; ` +
      `the signer re-signs it at 20 h on a schedule run`);
    const problems = documentProblems({ bytes: headBytes, step0, now: nowMs });
    if (problems.length) log(`FAIL  the head would be refused: ${problems.join("; ")}`);
    if (a.status) {
      if (fetchImpl) {
        const p = await pagesServes(fetchImpl, pagesBase, headBytes);
        log(`Pages: ${p.match ? "serving the head, byte for byte" : `not serving the head (${p.summary})`}`);
      }
      return problems.length ? 1 : 0;
    }
    return await waitPagesCommand({ a, slug, head, headBytes, step0, problems, fetchImpl, pagesBase, clock, sleep, log, env, ageBefore, resigns });
  }

  // 3. TRUST-3, as the service asks it, before anything is signed.
  const src = sourceCheck(git, step0, "refs/rehearsal/canary-main");
  if (!src.ok) throw new Refusal("TRUST3", `TRUST-3: ${src.why}. Merge the cut's sources into ${slug}'s main first (rehearsal-push --export-source)`);
  log(`ok    TRUST-3: ${src.why}`);
  log(`ok    \`signed\` is ${head}: ${head === step0.sha ? "step 0 itself" : `step 0 re-signed ${resigns} time(s)`}; its list was issued ${ageBefore.toFixed(2)} h ago`);

  // 4. The signer, on the throwaway registry: main at step 0's Source-Commit, origin itself.
  git(["update-ref", "refs/heads/main", step0.sourceCommit]);
  git(["checkout", "-q", "--detach", step0.sourceCommit]);
  git(["remote", "add", "origin", work]);
  const now = rfc3339(nowMs);
  const tree = path.join(tmp, "signed-tree");
  const record = path.join(tmp, "record.json");
  const signArgs = ["--step", "sign", "--root", work, "--source-commit", step0.sourceCommit, "--now", now,
    ...OUTGOING_ONLY.flatMap((k) => ["--test-key", k]), "--out", tree, "--record", record,
    ...(a.event ? ["--event", a.event] : [])];
  const signed = signer(signArgs, signerEnv());
  if (!fs.existsSync(record)) throw new Refusal("SIGNER", `the signer wrote no record (exit ${signed.status}): ${signed.err.trim().slice(-600)}`);
  const rec = JSON.parse(fs.readFileSync(record, "utf8"));
  if (signed.status !== 0 || rec.refusals?.length) {
    throw new Refusal("SIGNER", `the signer refused (exit ${signed.status}): ${(rec.refusals ?? []).join(" | ") || signed.err.trim().slice(-600)}`);
  }
  const decisions = { index: rec.documents?.index?.decision, revocations: rec.documents?.revocations?.decision };
  const base = { schema: "astra.registry.rehearsal-resign/1", at: rfc3339(clock()), now, repo: slug, fixtures,
    step0: step0.sha, event: a.event, run: env.GITHUB_RUN_ID ? { id: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT ?? null,
      repository: env.GITHUB_REPOSITORY ?? null } : null, parent: head, decisions, serials: rec.serials,
    list_age_hours_before: Number(ageBefore.toFixed(4)) };

  if (!rec.commit) {
    log(`ok    nothing to re-sign: catalogue ${decisions.index}, list ${decisions.revocations} ` +
      `(the signer re-signs an unchanged document at 20 h on a schedule or dispatch run, 34 h on a push)`);
    output(env, { pushed: "false", signed_sha: head });
    appendEvidence(a.evidence, { ...base, action: "fresh", signed_sha: head }, log);
    return 0;
  }
  if (decisions.index !== "resign" || decisions.revocations !== "resign") {
    throw new Refusal("DECISION", `the signer decided catalogue ${decisions.index} and list ${decisions.revocations}; a re-sign of ` +
      "step 0 re-signs both at an unchanged Source-Commit, and anything else is not this tool's to push");
  }
  const committed = signer(["--step", "commit", "--root", work, "--record", record, "--tree", tree],
    signerEnv({ ...RUN_ENV, GIT_AUTHOR_DATE: now, GIT_COMMITTER_DATE: now }));
  if (committed.status !== 0) throw new Refusal("SIGNER", `the signer's commit step exited ${committed.status}: ${committed.err.trim().slice(-600)}`);
  const sha = git(["rev-parse", "refs/heads/signed"]).out;

  // 5. The new commit, held to what the service will hold it to.
  const parent = git(["rev-parse", `${sha}^`]).out;
  if (parent !== head) throw new Refusal("RESIGN", `the re-sign ${sha}'s parent is ${parent}, not the canary's head ${head}`);
  const lineageAfter = lineageProblem(git, step0, sha);
  if (lineageAfter) throw new Refusal("RESIGN", lineageAfter);
  const bytes = Object.fromEntries(DOCUMENTS.map((rel) => [rel, blobBytes(work, gitConfig, sha, rel)]));
  const problems = documentProblems({ bytes, step0, now: nowMs, previous: headBytes, resignedAt: now });
  if (problems.length) throw new Refusal("RESIGN", `the re-sign ${sha} would be refused, so nothing is pushed: ${problems.join("; ")}`);
  const message = git(["log", "-1", "--format=%B", sha]).out;
  if (!message.includes(`Source-Commit: ${step0.sourceCommit}`)) throw new Refusal("RESIGN", `the re-sign ${sha} does not name step 0's Source-Commit`);
  log(`ok    re-signed at ${now}: ${sha}, one commit on ${head.slice(0, 12)}; catalogue ${rec.serials.index} and list ${rec.serials.revocations} at their serials, ` +
    `list expires ${JSON.parse(String(bytes["registry/v1/revocations.json"])).signed.expires_at}`);

  // 6. The push: one fast-forward, never forced, read back.
  let action = "would-resign";
  if (a.dryRun) log(`dry   would push ${sha} to ${slug} \`signed\` (fast-forward from ${head}); pushed nothing`);
  else {
    git(["push", "--quiet", "canary", `${sha}:refs/heads/signed`]);
    const after = git(["ls-remote", "canary", "refs/heads/signed"]).out.split(/\s+/)[0] || null;
    if (after !== sha) throw new Refusal("PUSH", `pushed, and \`signed\` reads back as ${after}, not ${sha}`);
    log(`ok    pushed: ${slug} \`signed\` is ${sha}`);
    action = "resigned";
  }
  output(env, { pushed: String(action === "resigned"), signed_sha: action === "resigned" ? sha : head });
  appendEvidence(a.evidence, { ...base, action, signed_sha: sha, documents: describeDocs(bytes), commit_message: message }, log);
  return 0;
}

// ── Pages ───────────────────────────────────────────────────────────────────

/** Whether Pages serves `bytes`, document by document. A query string defeats the CDN's cache. */
export async function pagesServes(fetchImpl, base, bytes) {
  const served = {};
  for (const rel of DOCUMENTS) {
    try {
      const r = await fetchImpl(`${base}${rel}?resign=${Date.now()}`);
      const body = r.status === 200 ? Buffer.from(await r.arrayBuffer()) : null;
      served[rel] = { status: r.status, bytes: body, match: body !== null && body.equals(Buffer.from(bytes[rel])) };
    } catch (e) {
      served[rel] = { status: null, bytes: null, match: false, error: String(e?.message ?? e) };
    }
  }
  const match = DOCUMENTS.every((rel) => served[rel].match);
  const summary = DOCUMENTS.map((rel) => `${path.basename(rel)} ${served[rel].status ?? served[rel].error}${served[rel].match ? "" : " (differs)"}`).join(", ");
  return { served, match, summary };
}

async function waitPagesCommand({ a, slug, head, headBytes, step0, problems, fetchImpl, pagesBase, clock, sleep, log, env, ageBefore, resigns }) {
  if (problems.length) throw new Refusal("HEAD", `${slug}'s head ${head} would be refused: ${problems.join("; ")}`);
  if (!fetchImpl) throw new Refusal("USAGE", "--wait-pages needs the network", 2);
  sleep ??= (ms) => new Promise((r) => setTimeout(r, ms));
  const start = clock();
  let p;
  for (;;) {
    p = await pagesServes(fetchImpl, pagesBase, headBytes);
    if (p.match || clock() - start >= a.pagesTimeout * 1000) break;
    await sleep(10_000);
  }
  if (!p.match) throw new Refusal("PAGES", `after ${Math.round((clock() - start) / 1000)} s Pages does not serve ${head}: ${p.summary}`);
  // The served bytes, judged again as served: the dates are fresh and every signature verifies.
  const nowMs = clock();
  const servedBytes = Object.fromEntries(DOCUMENTS.map((rel) => [rel, p.served[rel].bytes]));
  const servedProblems = documentProblems({ bytes: servedBytes, step0, now: nowMs });
  const age = listAgeHours(servedBytes, nowMs);
  if (age > STALE_AFTER_HOURS) servedProblems.push(`the served list is ${age.toFixed(2)} h old, past ${STALE_AFTER_HOURS} h: the schedule is not keeping it fresh`);
  if (servedProblems.length) throw new Refusal("SERVED", `Pages serves ${head}, and it would be refused: ${servedProblems.join("; ")}`);
  log(`ok    Pages serves ${head}'s four documents byte for byte (after ${Math.round((nowMs - start) / 1000)} s); every signature ` +
    `verifies under tools/testkeys' roots, and the list is ${age.toFixed(2)} h old`);
  appendEvidence(a.evidence, {
    schema: "astra.registry.rehearsal-resign/1", at: rfc3339(nowMs), repo: slug, action: "pages", signed_sha: head,
    step0: step0.sha, resigns, run: env.GITHUB_RUN_ID ? { id: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT ?? null } : null,
    pages: { base: pagesBase, waited_ms: nowMs - start, status: Object.fromEntries(DOCUMENTS.map((rel) => [rel, p.served[rel].status])) },
    served: describeDocs(servedBytes), list_age_hours: Number(age.toFixed(4)), list_age_hours_at_head_read: Number(ageBefore.toFixed(4)),
  }, log);
  return 0;
}

// ── the workflow ────────────────────────────────────────────────────────────

/** The placeholder the template carries where the deployed workflow pins this repository's commit. */
export const PIN_PLACEHOLDER = "@REGISTRY_SHA@";
export const TEMPLATE = path.join(REPO, "tools", "testkeys", "rehearsal-resign.yml");

/**
 * Why a workflow text could reach something other than the re-sign canary's
 * `signed`, or hold something it must not. Line rules over a template this
 * repository writes, because the repository has no YAML parser and the
 * template is short enough to be read by them whole.
 */
export function workflowProblems(text, { slug = resignCanaries()[0] } = {}) {
  const problems = [];
  const lines = text.split("\n");
  const top = (key) => lines.findIndex((l) => l === `${key}:`);
  const blockOf = (key) => {
    const at = top(key);
    if (at === -1) return null;
    const out = [];
    for (let i = at + 1; i < lines.length && (lines[i] === "" || /^\s/.test(lines[i]) || lines[i].startsWith("#")); i++) {
      if (lines[i].trim() && !lines[i].trim().startsWith("#")) out.push(lines[i]);
    }
    return out;
  };
  // The triggers: the schedule and a hand dispatch, as production's re-sign. Nothing a stranger's push or PR starts.
  const on = blockOf("on");
  const triggers = (on ?? []).filter((l) => /^ {2}[a-z_]+:/.test(l)).map((l) => l.trim().replace(/:.*$/, ""));
  if (triggers.join(" ") !== "schedule workflow_dispatch") problems.push(`the workflow starts on ${triggers.join(", ") || "nothing"}, not exactly schedule and workflow_dispatch`);
  // The token: write to this repository's contents and ask for a Pages build, and nothing else.
  const perms = blockOf("permissions");
  const granted = (perms ?? []).map((l) => l.trim()).sort();
  if (granted.join(" | ") !== "contents: write | pages: write") problems.push(`the token is granted ${granted.join(", ") || "the default"}, not exactly contents: write and pages: write`);
  if (lines.filter((l) => /^\s+permissions:/.test(l)).length) problems.push("a job widens its own permissions");
  if (/write-all|read-all/.test(text)) problems.push("the workflow names write-all or read-all");
  // No credential but this repository's own token.
  if (/\bsecrets\./.test(text)) problems.push("the workflow reads a secret; the re-sign holds none");
  // `sign.yml` as a name of its own: `rehearsal-resign.yml` ends in the same letters.
  if (/ASTRA_INDEX_SIGNING_KEY|(?<![\w-])sign\.yml|environment:/.test(text)) problems.push("the workflow names a real signing key, sign.yml or an environment");
  // It runs only in the re-sign canary, so a copy anywhere else does nothing.
  if (!lines.some((l) => l.trim() === `if: github.repository == '${slug}'`)) problems.push(`no job guard \`if: github.repository == '${slug}'\``);
  // The registry, fetched read-only from its public URL at one pinned commit.
  const pinLine = lines.find((l) => /^\s+REGISTRY_SHA: /.test(l));
  const pin = pinLine ? pinLine.trim().replace(/^REGISTRY_SHA: "?([^"]*)"?$/, "$1") : null;
  if (!pin || !(pin === PIN_PLACEHOLDER || /^[0-9a-f]{40}$/.test(pin))) problems.push(`REGISTRY_SHA is ${pin ?? "absent"}, not a 40-hex commit`);
  if (!text.includes(`git -C registry fetch -q --depth 1 https://github.com/${PRODUCTION_SLUG}.git "$REGISTRY_SHA"`)) {
    problems.push("the registry is not fetched from its public URL at $REGISTRY_SHA");
  }
  // Every action pinned by commit.
  for (const l of lines.filter((x) => /^\s+(- )?uses:/.test(x))) {
    if (!/@[0-9a-f]{40}(\s|$)/.test(l)) problems.push(`\`${l.trim()}\` is not pinned to a commit`);
  }
  // The push credential is scoped to this repository's URL, and the tool is told this repository.
  if (!text.includes('git config --global "http.https://github.com/${GITHUB_REPOSITORY}.git.extraheader"')) {
    problems.push("the push credential is not scoped to this repository's URL");
  }
  // Every run of the tool but the audit is aimed at this repository, and none at another.
  const invocations = lines.filter((l) => l.includes("rehearsal-resign.mjs") && !l.trim().startsWith("#") && !l.includes("--audit-workflow"));
  if (invocations.length === 0) problems.push("the workflow never runs the re-sign");
  for (const l of invocations) {
    const repos = [...l.matchAll(/--repo\s+(\S+)/g)].map((m) => m[1]);
    if (repos.length !== 1 || repos[0] !== '"$GITHUB_REPOSITORY"') problems.push(`\`${l.trim().slice(0, 120)}\` is not told this repository, and only it`);
  }
  return problems;
}

/** The deployed text against the template: equal, with the placeholder pinned to `registrySha`. */
export function deployedProblems(deployed, template, registrySha) {
  if (!/^[0-9a-f]{40}$/.test(registrySha ?? "")) return [`the registry commit ${registrySha} is not a 40-hex sha`];
  const want = template.split(PIN_PLACEHOLDER).join(registrySha);
  if (deployed === want) return [];
  const a = deployed.split("\n");
  const b = want.split("\n");
  const at = a.findIndex((l, i) => l !== b[i]);
  return [`the deployed workflow is not the registry's template at ${registrySha.slice(0, 12)} pinned to it: first difference at line ` +
    `${at + 1}: ${JSON.stringify(a[at] ?? "<end>")} where the template has ${JSON.stringify(b[at] ?? "<end>")}`];
}

function auditCommand(a, log) {
  const text = fs.readFileSync(a.audit, "utf8");
  const template = fs.readFileSync(TEMPLATE, "utf8");
  const sha = a.registrySha ?? gitAt(REPO)(["rev-parse", "HEAD"]).out;
  const problems = [...workflowProblems(text), ...deployedProblems(text, template, sha)];
  if (problems.length) {
    for (const p of problems) log(`FAIL  ${p}`);
    return 1;
  }
  log(`ok    ${a.audit} is the registry's template at ${sha}, pinned to it: it starts on the schedule and a dispatch only, ` +
    "its token may write this repository's contents and ask for a Pages build and nothing else, it reads no secret, and it runs " +
    `only in ${resignCanaries().join(", ")}`);
  return 0;
}
