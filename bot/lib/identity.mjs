// Which repository published these bytes, and is it the one the listing is
// about.
//
// Registry plan B-T3.2 (identity from the certificate) and the comparison half
// of B-T3.3a (TRUST-23 against MIG-20's baseline). Everything here is pure:
// certificate fields in, a decision out, no network and no filesystem, so a
// test can stand at any point in a rename, a transfer or a re-creation without
// arranging one.
//
// ── the anchor is a number, and the name is a label beside it ──────────────
//
// A repository NAME is a string its owner can give away. The catalogue already
// carries the proof: `astra-chess` and `knice-chess` were released from
// `KNICE-TECH/astra-chess`, the organisation renamed itself to `MINICE-AI`, and
// the freed login is registrable by anybody who wants it. The certificate's
// `.12` froze the old name at signing; `.15` and `.17` did not move.
//
// So the comparison is: **ids decide, names are reported**. Two ids agreeing
// with a different name is a RENAME, which a person rules on (ID-41; TRUST-23)
// — it is not an error and it is not a silent pass. Two ids differing under
// the same name is a repository that was deleted and re-created, or one that
// never was the one the listing means.
//
// **`.12` equalling `source.repo` is not, by itself, agreement.** For the two
// chess listings it is true only because the registry's record is stale in the
// same direction as the certificate: two stale strings agreeing is not a match,
// and nothing here may be written as though it were. That is why every
// comparison below takes the ids as well, and why `sameName` alone never
// produces `ok`.
//
// ── what this module cannot do yet, and refuses to pretend about ───────────
//
// B-T3.3a's full decision needs four things. **Three of them are not on
// `main`** — the binding-line grammar (B-T2.4, R2), the service verdict `ask`
// returns (B-T3.1), and B-T4.2's `identity_reset` writer. The fourth,
// `bot/lib/listing-state.mjs` (M-T5.1), **landed in this commit's merge**, and
// the count here is edited rather than left at four because a header saying a
// module does not exist is exactly the class of claim that outlives its truth
// in this estate — nothing executes a comment.
//
// `bindingDecision`'s refusal still names all four and still fires, and that
// is correct rather than an oversight: it checks the inputs a CALLER obtained,
// not which files exist, so a caller that has not read `listingState` still
// cannot decide a binding. Landing the piece a refusal names is not a licence
// to loosen the refusal — *a refusal can be holding a defect out of reach, and
// removing it ships the defect* — and three of the four are genuinely still
// missing. `bot/tests/identity.test.mjs:291` asserts that wording, so it is
// load-bearing and not editable in passing.
//
// What IS here is every rule those four do not gate: the TRUST-23
// comparison, MIG-28's hold for an id with no baseline, and the rule that a
// baseline ends at the newest voiding record. `bindingDecision` refuses by
// name for the rest, in the shape `bot/baseline.mjs` uses for the same
// problem, so the gap is a refusal somebody can read rather than a hole shaped
// like one.

import { SUPPORTED_KEYS } from "../../tools/lib/platform.mjs";
import { parseSemver } from "../../tools/lib/semver.mjs";

import { repoFromUri } from "./certificate.mjs";

const BASE10_RE = /^[0-9]+$/;

/**
 * The vocabulary this module answers in.
 *
 * These are CONTRACT codes (ID-25, ID-41, TRUST-23, MIG-28), not the
 * author-facing policy codes in `bot/lib/policy/constants.mjs`. They are kept
 * apart on purpose: every key of `POLICY_CODES` must be explained in
 * `docs/POLICY.md`, and the author-facing text for the bound world is written
 * once, by reg.61a (B-T3.3b), rather than four times by whoever lands first.
 * `bot/lib/policy/decision.mjs` maps these onto the policy vocabulary.
 */
export const IDENTITY_CODES = Object.freeze({
  /** The ids and the name all agree with the baseline. */
  OK: "ok",
  /** Same name, both ids changed: the login was freed and taken (ID-41 row 1). */
  B_REPOSITORY_RECYCLED: "B_REPOSITORY_RECYCLED",
  /** A rename, a transfer, or a re-creation: a person rules on it. */
  R_IDENTITY_CHANGED: "R_IDENTITY_CHANGED",
  /** A read that did not happen. Never absence, never a difference. */
  W_GITHUB_RATE_LIMITED: "W_GITHUB_RATE_LIMITED",
});

/**
 * The identity the certificate states, as the registry records it.
 *
 * `.12` supplies the NAME (BOT-21: `source.repo` and each `release.repo`),
 * `.15` and `.17` the two ids, `.13` the attested commit, `.21` the run
 * MIG-31 asks about. Nothing here is read from a service answer, a submission
 * form or a predicate.
 *
 * @param {Record<string, string|null>} fields `certificate.mjs`'s ten
 * @returns {{ok: boolean, repo: string|null, repository_id: string|null,
 *   repository_owner_id: string|null, commit: string|null, run: string|null,
 *   run_id: string|null, missing: string[]}}
 */
export function identityFromCertificate(fields = {}) {
  const repo = repoFromUri(fields.source_repository_uri ?? null);
  const id = typeof fields.repository_id === "string" && BASE10_RE.test(fields.repository_id)
    ? fields.repository_id : null;
  const ownerId = typeof fields.repository_owner_id === "string" && BASE10_RE.test(fields.repository_owner_id)
    ? fields.repository_owner_id : null;
  const run = typeof fields.run === "string" ? fields.run : null;
  const missing = [];
  if (!repo) missing.push("source_repository_uri (.12)");
  if (!id) missing.push("repository_id (.15)");
  if (!ownerId) missing.push("repository_owner_id (.17)");
  return {
    ok: missing.length === 0,
    repo,
    repository_id: id,
    repository_owner_id: ownerId,
    commit: typeof fields.sha === "string" ? fields.sha : null,
    run,
    // `.21` is `https://github.com/<owner>/<name>/actions/runs/<id>[/attempts/n]`.
    run_id: run ? (/\/actions\/runs\/(\d+)/.exec(run)?.[1] ?? null) : null,
    missing,
  };
}

/**
 * BOT-21, applied: the listing's repository name comes from `.12`.
 *
 * `deriveListing` writes the repository the SUBMITTER named, because on the
 * legacy path that is the only name there is and the ownership check is what
 * stands behind it. From R3 the certificate is the source of the string, and
 * `publish` overwrites the placeholder: `source.repo` and every
 * `release.repo` become `.12`'s owner/name.
 *
 * The two are equal on today's path — `verifyAttestation` refuses a
 * certificate naming another repository — and that is exactly why this has to
 * be written down rather than left implicit. A later path (a service answer, a
 * lease, an artifact) that supplies the name instead would pass every test in
 * the suite while quietly moving where the registry's belief comes from.
 *
 * @param {{plugin: object, version: object}} derived
 * @param {{repo: string}} identity
 * @returns {{ok: boolean, derived: object|null, reason?: string}}
 */
export function applyIdentity(derived, identity) {
  if (!identity?.repo) {
    return { ok: false, derived: null, reason: "the certificate states no source repository (.12)" };
  }
  if (!derived?.plugin || !derived?.version) {
    return { ok: false, derived: null, reason: "there is no derived listing to apply an identity to" };
  }
  const plugin = { ...derived.plugin, source: { ...(derived.plugin.source ?? {}), kind: "github", repo: identity.repo } };
  const version = { ...derived.version, release: { ...(derived.version.release ?? {}), repo: identity.repo } };
  return { ok: true, derived: { ...derived, plugin, version } };
}

/**
 * BOT-21: the plugin id and version come from the ATTESTED asset name.
 *
 * `<id>-<version>-<key>.astraplugin`. Not from a service answer, not from a
 * form, and not from the manifest alone — the asset name is the string the
 * attestation's subject digest is bound to, and `bot/ingest.mjs` already
 * refuses a bundle whose manifest and filename disagree.
 */
export function idAndVersionFromAssetName(name) {
  const miss = { ok: false, id: null, version: null, platformKey: null };
  if (typeof name !== "string" || !name.endsWith(".astraplugin")) return miss;
  const stem = name.slice(0, -".astraplugin".length);
  // The platform key is matched against the set this registry supports rather
  // than against a pattern, because `<id>-<version>-<key>` cannot be split by
  // hyphen alone: a semver prerelease carries hyphens too, and
  // `astra-chess-0.1.17-linux-x64` has five of them. One ambiguity remains —
  // an id that itself ends in something semver accepts — and it is resolved
  // by taking the EARLIEST split that parses, which matches how the name is
  // built. `bot/ingest.mjs` composes the expected name from the manifest and
  // refuses a disagreement, so nothing downstream rests on this parse alone.
  const platformKey = SUPPORTED_KEYS.find((k) => stem.endsWith(`-${k}`));
  if (!platformKey) return miss;
  const rest = stem.slice(0, -(platformKey.length + 1));
  for (let i = rest.indexOf("-"); i >= 0; i = rest.indexOf("-", i + 1)) {
    const id = rest.slice(0, i);
    const version = rest.slice(i + 1);
    if (/^[a-z0-9][a-z0-9-]*$/.test(id) && parseSemver(version)) return { ok: true, id, version, platformKey };
  }
  return miss;
}

/**
 * The certificate's `.15`/`.17` against the repository the assets were
 * downloaded from (B-T1.3's `fetchRepositoryIds`).
 *
 * Three outcomes, and the difference between them is the whole point:
 *
 *   * `ok` — the ids agree. The names may still differ, and `renamed` says so.
 *   * `alert` — `.15` is not the id of the repository the bytes came from.
 *     Nothing is written, no result is posted, and an operator is paged: the
 *     attestation and the download disagree about where the artifact came
 *     from, which no author action fixes and no listing should absorb.
 *   * `wait` — the id could not be read. `transient` is never a difference.
 *
 * @param {{identity: object, downloadRepoIds: {status: string, id?: string|null,
 *   owner_id?: string|null, full_name?: string|null, reason?: string}}} opts
 */
export function checkDownloadRepository({ identity, downloadRepoIds }) {
  if (!identity?.ok) {
    return { outcome: "alert", code: "E_ATTESTATION_INVALID", reason: `the certificate is missing ${identity?.missing?.join(", ") || "identity fields"}` };
  }
  if (!downloadRepoIds || downloadRepoIds.status === "transient") {
    return {
      outcome: "wait",
      code: IDENTITY_CODES.W_GITHUB_RATE_LIMITED,
      reason: `GitHub did not answer for the download repository (${downloadRepoIds?.reason ?? "no answer"}); a read that did not happen is not a difference`,
    };
  }
  if (downloadRepoIds.status === "not_found") {
    return {
      outcome: "alert",
      code: "E_ATTESTATION_REPO_MISMATCH",
      reason: "GitHub has no repository at the name the assets were downloaded from",
    };
  }
  if (downloadRepoIds.id !== identity.repository_id) {
    return {
      outcome: "alert",
      code: "E_ATTESTATION_REPO_MISMATCH",
      reason:
        `the certificate says the bytes were built in repository ${identity.repository_id} and the assets ` +
        `were downloaded from repository ${downloadRepoIds.id} (${downloadRepoIds.full_name}). Nothing is ` +
        "written and no result is posted: two different repositories cannot both have produced one artifact.",
    };
  }
  const renamed = typeof downloadRepoIds.full_name === "string" &&
    downloadRepoIds.full_name.toLowerCase() !== String(identity.repo).toLowerCase();
  return {
    outcome: "ok",
    renamed,
    reason: renamed
      ? `the ids agree; the certificate froze the name as ${identity.repo} and GitHub calls it ${downloadRepoIds.full_name} today`
      : "the ids and the name agree",
  };
}

/**
 * The floor MIG-31 imposes when the account that ran the build is not the
 * account that owns the repository.
 *
 * Fourteen days. It is not in `docs/POLICY.md` and must not be quoted there
 * by this task: `docs/POLICY.md` is reg.61a's (B-T3.3b), which publishes the
 * bound world's numbers in one edit, and a second file publishing a third
 * number is how a document and its code start disagreeing.
 */
export const ACTOR_MISMATCH_FLOOR_DAYS = 14;

/**
 * MIG-31: the run's triggering actor against the repository's owner id.
 *
 * `.21` names the run, B-T1.3's `workflowRun` reads its `triggering_actor.id`,
 * and `.17` says whose repository it is. A difference is not a refusal — an
 * organisation member releasing an organisation's plugin is the ordinary case
 * — but it is the shape a stolen credential takes too, so the release waits
 * out a floor before it can publish.
 *
 * **A failed read waits.** It does not pass and it does not impose the floor:
 * "GitHub did not answer" is not "somebody else pressed the button", and a
 * decision record that says the second when the first happened cannot be
 * un-written.
 *
 * @param {{identity: object, actor: {status: string, triggering_actor_id?: string|null, reason?: string}}} opts
 */
export function compareActor({ identity, actor }) {
  if (!actor || actor.status === "transient") {
    return {
      outcome: "wait",
      code: IDENTITY_CODES.W_GITHUB_RATE_LIMITED,
      reason: `the run's triggering actor could not be read (${actor?.reason ?? "no answer"}); this run decides nothing and asks again`,
    };
  }
  if (actor.status === "not_found") {
    return {
      outcome: "wait",
      code: IDENTITY_CODES.W_GITHUB_RATE_LIMITED,
      reason: "GitHub has no such run. The certificate names it, so this is a disagreement to re-read rather than a fact about the author",
    };
  }
  if (!actor.triggering_actor_id) {
    return { outcome: "wait", code: IDENTITY_CODES.W_GITHUB_RATE_LIMITED, reason: "the run carries no triggering actor id" };
  }
  if (actor.triggering_actor_id === identity?.repository_owner_id) {
    return { outcome: "ok", floor_days: 0, reason: "the account that ran the build owns the repository" };
  }
  return {
    outcome: "floor",
    floor_days: ACTOR_MISMATCH_FLOOR_DAYS,
    reason:
      `the build was started by account ${actor.triggering_actor_id} and the repository's owner is ` +
      `${identity?.repository_owner_id}. That is ordinary inside an organisation and it is also what a ` +
      `stolen credential looks like, so this release waits ${ACTOR_MISMATCH_FLOOR_DAYS} days (MIG-31).`,
  };
}

/**
 * BOT-15 / INV-37: the `publish` job composes from facts it re-reads, and a
 * facts file that disagrees with the verification writes nothing.
 *
 * The job graph (B-T3.1, BOT-55) hands `publish` a fixed-schema facts list
 * that `verify` produced. `publish` holds no attestation and cannot re-verify,
 * so the one thing it can do is refuse a list that does not match what this
 * run actually claimed — and refuse loudly, because a facts file naming
 * another repository's ids is not a bug, it is the shape an attack takes.
 *
 * @param {{claimed: {plugin_id: string, version: string, repository_id: string,
 *   repository_owner_id: string, repo: string}[], factsFile: object}} opts
 */
export function compareFactsFile({ claimed, factsFile }) {
  const problems = [];
  const facts = Array.isArray(factsFile?.facts) ? factsFile.facts : null;
  if (!facts) return { ok: false, problems: ["the facts file carries no `facts` list"] };

  const byKey = new Map(claimed.map((c) => [`${c.plugin_id}@${c.version}`, c]));
  for (const fact of facts) {
    const key = `${fact?.plugin_id}@${fact?.version}`;
    const mine = byKey.get(key);
    if (!mine) {
      problems.push(
        `${key} is in the facts file and is not work this run claimed. A `+
        "publishing job writes for the submissions it pulled and for nothing else (INV-36).",
      );
      continue;
    }
    for (const member of ["repository_id", "repository_owner_id", "repo"]) {
      if (fact[member] !== mine[member]) {
        problems.push(
          `${key}: the facts file says ${member} ${JSON.stringify(fact[member])} and this run verified ` +
          `${JSON.stringify(mine[member])}`,
        );
      }
    }
  }
  return { ok: problems.length === 0, problems };
}

/**
 * INV-36: a path, or an artifact, that names a plugin this run did not claim.
 *
 * The canary this exists for is "a planted `listing-*` is refused": the
 * `verify` job's output travels between jobs, and an entry planted into it
 * would make `publish` write a listing nothing verified. The NAMES of those
 * entries belong to B-T3.1's job graph — **which IS on `main`** since `e6520be`
 * (`plugins-ingest.yml`, twelve jobs); this sentence said "is not on `main`"
 * until 2026-09-22 and was falsified by the commit that landed the graph. The
 * predicate stays here rather than in the YAML for the reason below: it lands
 * once rather than being invented again inside a step. The predicate
 * is here, with its caller, so the rule lands once rather than being invented
 * again inside a YAML step.
 *
 * @param {{entries: string[], claimedIds: string[]}} opts
 */
export function refuseUnclaimedEntries({ entries, claimedIds }) {
  const claimed = new Set(claimedIds);
  const refused = [];
  for (const entry of entries) {
    const id = /^listing-(.+)$/.exec(entry)?.[1] ?? entry;
    if (!claimed.has(id)) refused.push(entry);
  }
  return { ok: refused.length === 0, refused };
}

// ── TRUST-23, against MIG-20's baseline (the B-T3.3a half that is buildable) ─

/**
 * A baseline ends at the newest voiding record (B-T4.2's reset).
 *
 * Without this rule a reset leaves the OLD certificate ids as the baseline
 * through the listing's later publication records, TRUST-23 compares against
 * them again, and the id is refused `B_REPOSITORY_RECYCLED` a second time —
 * which is precisely what the reset exists to lift. Every reader of a baseline
 * goes through here: TRUST-23's, MIG-28's, MIG-20's tree check and detector
 * A1.
 *
 * @param {{records: object[], pluginId: string}} opts decision records for one
 *   id, in any order: `migration` baselines and `identity_reset` voidings.
 * @returns {{baseline: object|null, voidedAt: string|null}}
 */
export function effectiveBaseline({ records, pluginId }) {
  const mine = (records ?? []).filter((r) => r?.plugin_id === pluginId);
  const resets = mine
    .filter((r) => r?.trigger === "identity_reset" || r?.state === "identity_reset")
    .map((r) => r.decided_at)
    .filter(Boolean)
    .sort();
  const voidedAt = resets.at(-1) ?? null;
  const baselines = mine
    .filter((r) => r?.trigger === "migration" && r?.state === "published" && r?.repository_id)
    .filter((r) => !voidedAt || String(r.decided_at) > voidedAt)
    .sort((a, b) => String(a.decided_at).localeCompare(String(b.decided_at)));
  return { baseline: baselines.at(-1) ?? null, voidedAt };
}

/**
 * TRUST-23, for a listing with no identity record: this release's certificate
 * against the migration baseline.
 *
 * The four outcomes TRUST-23's Check asks for a fixture of, and the one the
 * plan adds (MIG-28):
 *
 * | baseline vs certificate | outcome |
 * |---|---|
 * | both ids equal, name equal | `ok` |
 * | both ids equal, name different | `R_IDENTITY_CHANGED` — a rename |
 * | owner id different, repo id equal | `R_IDENTITY_CHANGED` — a transfer |
 * | one id different | `R_IDENTITY_CHANGED` — a re-creation |
 * | BOTH ids different, name the same | `B_REPOSITORY_RECYCLED` |
 * | no baseline at all | `R_IDENTITY_CHANGED` (MIG-28, BOT-40) |
 *
 * The recycled row is the one that is terminal, and it is the one the name
 * agreeing is *evidence for* rather than against: a login that was freed and
 * registered by somebody else gives exactly this shape — the same string,
 * two different repositories behind it. Comparing by name is how a registry
 * hands a listing to whoever registered the abandoned login, which is why
 * the canary for this table is "watched by comparing by name".
 *
 * The hold names BOTH id pairs, because the person ruling on it cannot
 * otherwise tell a transfer from a re-creation.
 *
 * @param {{identity: object, baseline: {repository_id: string,
 *   repository_owner_id: string, repo: string}|null}} opts
 */
export function compareWithBaseline({ identity, baseline }) {
  if (!identity?.ok) {
    return {
      code: IDENTITY_CODES.R_IDENTITY_CHANGED,
      terminal: false,
      reason: `the certificate is missing ${identity?.missing?.join(", ") || "identity fields"}`,
    };
  }
  if (!baseline) {
    return {
      code: IDENTITY_CODES.R_IDENTITY_CHANGED,
      terminal: false,
      reason:
        `${identity.repo} publishes repository ${identity.repository_id} (owner ${identity.repository_owner_id}) ` +
        "and this id has no migration baseline to compare against, so nothing here can say whether the " +
        "repository is the one the listing has always meant (MIG-28).",
    };
  }
  const sameRepoId = baseline.repository_id === identity.repository_id;
  const sameOwnerId = baseline.repository_owner_id === identity.repository_owner_id;
  const sameName = String(baseline.repo).toLowerCase() === String(identity.repo).toLowerCase();

  if (sameRepoId && sameOwnerId) {
    if (sameName) return { code: IDENTITY_CODES.OK, terminal: false, reason: "the ids and the name agree with the baseline" };
    return {
      code: IDENTITY_CODES.R_IDENTITY_CHANGED,
      terminal: false,
      reason:
        `both ids are unchanged (${identity.repository_id}/${identity.repository_owner_id}) and the name moved ` +
        `from ${baseline.repo} to ${identity.repo}: a rename. Every installed copy carries a pin to the old name.`,
    };
  }

  if (!sameRepoId && !sameOwnerId && sameName) {
    return {
      code: IDENTITY_CODES.B_REPOSITORY_RECYCLED,
      terminal: true,
      reason:
        `${identity.repo} was baselined as repository ${baseline.repository_id} (owner ` +
        `${baseline.repository_owner_id}) and this release attests repository ${identity.repository_id} ` +
        `(owner ${identity.repository_owner_id}) under the same name. A login that was given up and ` +
        "registered by somebody else looks exactly like this, and the name is the part an attacker gets " +
        "for free.",
    };
  }

  return {
    code: IDENTITY_CODES.R_IDENTITY_CHANGED,
    terminal: false,
    reason:
      `the baseline is repository ${baseline.repository_id} / owner ${baseline.repository_owner_id} ` +
      `(${baseline.repo}) and this release attests repository ${identity.repository_id} / owner ` +
      `${identity.repository_owner_id} (${identity.repo})` +
      (sameRepoId ? " — the repository id is unchanged, so this is a transfer" : "") +
      (sameOwnerId ? " — the owner id is unchanged, so this is a re-creation under the same account" : ""),
  };
}

/**
 * The rest of B-T3.3a, refused by name.
 *
 * Shaped like `bot/baseline.mjs`'s `resolveCertificateReader` and for the same
 * reason: the thing that must not happen is a second implementation growing
 * here to fill a gap, because a second answer to "is this listing bound" is a
 * second identity system. Each refusal names the module, the task, and the one
 * thing it wants.
 *
 * @param {{listingState?: object, bindingLine?: object, verdict?: object,
 *   marker?: object}} available what the caller managed to obtain
 */
export function bindingDecision(available = {}) {
  const missing = [];
  if (!available.listingState) {
    missing.push(
      "`bot/lib/listing-state.mjs` (M-T5.1), which is the only module allowed to say whether a listing is " +
      "`grandfathered`, `frozen` or bound (MIG-1, BOT-72). `B_UNBOUND`'s scope and MIG-1's revoked-binding " +
      "`frozen` are both decided by it",
    );
  }
  if (!available.bindingLine) {
    missing.push(
      "the binding-line reader (B-T2.4, from R2): `astra-binding: <token>` at the ATTESTED commit (ID-22), " +
      "whose grammar decides `B_BINDING_MALFORMED` and whose token decides ID-41's rows",
    );
  }
  if (!available.verdict) {
    missing.push(
      "the service verdict `ask` returns (B-T3.1), which carries eligibility, the minted-for id and " +
      "`shadow` — and in shadow nothing mapped may be committed or posted at all (BOT-92, ID-71)",
    );
  }
  if (!available.marker) {
    missing.push(
      "`log/rollout/R3-exit.json` and `log/cutover.json` (B-T3.6; M-T5.x), the registry-owned markers " +
      "`B_UNBOUND` is keyed on — it applies on one side of them and not the other (ID-25, seam 22)",
    );
  }
  if (missing.length) {
    return {
      ok: false,
      code: null,
      reason:
        "this run cannot decide a binding, and says so rather than deciding one: " + missing.join("; ") +
        ". The identity comparison (TRUST-23, MIG-28) is decided above and is not affected.",
    };
  }
  return { ok: true, code: null, reason: "every input a binding decision needs is present" };
}
