// The dead-man receiver's checks: every one this estate posts to, what posts
// to it, how long its silence may last, and which of them are created
// disarmed.
//
// Why this list is in the repository at all, rather than only in the receiver.
// The receiver is a product the owner creates (registry plan RC-R1-0, §2.12's
// R1 row), and the act he performs is "one check per scheduled job, with the
// bounds below, plus one `ASTRA_DEADMAN_URL_<CHECK>` secret each". That act
// needs a list. A list that exists only in a plan document is a list nobody can
// diff against the jobs that post, and the failure it permits is the quiet one:
// a job posts to a check nobody created, the POST 404s, the step goes red for a
// reason that reads like a typo, and — worse in the other direction — a check
// is created and no job ever posts to it, so it pages once and is switched off.
// `bot/heartbeat.mjs` refuses a name that is not here, and this file is what
// the owner's receiver is built from.
//
// **It is not the credential.** Nothing here is a URL. Each check's whole ping
// URL lives in its own secret in environment `alerts`, and this file only says
// what that secret is called. That split is attack M-5's rule and the reason
// there is no base URL anywhere in this repository: a base plus a name is a
// project-level ping key, and whoever held it could silence the two checks the
// plugins service pages through — including the one that fires when the Almaty
// box, and with it the service's own on-box Telegram path, is gone.
//
// **Unknown intervals are null, deliberately.** Several of these checks belong
// to tasks that have not landed, and their schedules are theirs to fix. An
// invented number here would become the bound the receiver was built with and
// would outlive its truth in the one place nobody re-reads. A null interval
// means the bound cannot be computed yet, `boundMinutes` says so, and the task
// named in `source` is the one that fills it in.

// §0.7's time grammar, spelled HERE and not imported from tools/lib/time.mjs,
// which is where every other reader in this repository takes it (contract
// 0.34.0). Every alert job's sparse checkout carries this file and not that one
// — the alert action's own step names the five files it needs, and nine
// workflows copy that list — so an import would fail each of them at the first
// alert. The copy is not trusted to stay a copy: tools/selftest/times.mjs holds
// this pattern to `TIME_PATTERN` byte for byte and drives `isArmedAt` with
// second 60, hour 24 and `2026-02-30`. Until 0.34.0 this admitted all three.
const ARMED_AT_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;

/** `armed_at`: a §0.7 time — the grammar, and a day its month has. */
export function isArmedAt(value) {
  if (typeof value !== "string" || !ARMED_AT_RE.test(value)) return false;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z") === value;
}

/** The `<CHECK>` grammar: what may appear in a check name and in a secret's suffix. */
export const CHECK_NAME_PATTERN = "^[a-z][a-z0-9-]{1,30}[a-z0-9]$";
const CHECK_NAME_RE = new RegExp(CHECK_NAME_PATTERN);

/** BOT-85's floor: no bound is shorter than this, whatever the interval. */
export const MIN_BOUND_MINUTES = 90;

/**
 * Who posts. `registry` is a job in this repository. The other three are
 * checks the owner creates here, with the rest, and that this repository must
 * never hold a URL for: `test-repository` is BOT-88's separate repository,
 * whose secret is stored there; `probe-host` is ROLL-15's prober, which runs
 * on the owner's chosen machine with its own credentials in 0600 files
 * (RC-R1-7); `plugins-service` is minice-be's host. One receiver, four
 * parties, and no credential of one resolving a check of another.
 */
export const PARTIES = ["registry", "test-repository", "probe-host", "plugins-service"];

// ── which registry checks are created ARMED ──────────────────────────────────
//
// **Decided 2026-09-22 by the coordinator session (astra-plugins-ops,
// `dev/couplings.md` entry 25):** a registry check is created armed only if a
// poster for it runs on a live trigger in this repository today; otherwise it
// is created disarmed and arms at its first heartbeat.
//
// Why. Armed with no running poster, a check can only page falsely, and it
// starts doing so on the day the owner creates the receiver (R1) — the first
// thing a new alarm channel would say is an absence that is not an outage,
// which is how a person learns the channel is noise. A check created disarmed
// that arms at its first post loses nothing while its poster does not run.
// The residual risk is a poster that runs but fails before its first
// successful post and so never arms its check; that is why a check whose
// poster already runs stays armed.
//
// Until 2026-09-22 every registry row said `created_disarmed: false` and a test
// asserted it with the message "has a poster in this repository", which was
// false for five of the thirteen. The rule is COMPUTED now, not listed:
// `bot/tests/workflows.test.mjs` finds every job that calls
// `.github/actions/alert` with `check:` or `ack-check:`, asks whether its
// workflow has a live `schedule:` — the one trigger that counts as live here,
// for the reason that test gives — and fails by name in both directions. So a
// poster that goes live — R3's open commit un-commenting
// `plugins-moderation.yml`'s schedule is the first — is red until its row here
// is armed, in the same commit.
//
// Arming after creation is recorded in `armed_at`, as it is for the two service
// checks below. Nothing in this repository arms a check: it is a receiver
// setting (or the receiver's own first-post behaviour, whichever product the
// owner chooses, Q-O2), and this field is the record that it happened.

export const CHECKS = [
  {
    name: "detectors",
    party: "registry",
    source: "B-T3.8 (BOT-43), .github/workflows/detectors.yml",
    interval_seconds: 3600,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "moderation-run",
    party: "registry",
    // 600 s is a contract MUST since A6, recorded in the token file and in
    // ROLL-7's file; a cron edit waits for a contract MINOR (SCOPE-1). So this
    // interval is pinned rather than guessed, and 3 × 600 s is under the floor,
    // which is why the bound comes out at 90 minutes and not at 30.
    //
    // Disarmed: its poster is the `settled` job, and the workflow's schedule
    // is commented out until R3 opens (§2.5), so today it runs only on a
    // dispatch. R3's open commit arms this row with the schedule.
    source: "M-T3.4 (BOT-83), .github/workflows/plugins-moderation.yml",
    interval_seconds: 600,
    created_disarmed: true,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "signer",
    party: "registry",
    // ROLL-62's row in RC-R1-0's own table reads "the signer, RC-R1-2", and
    // this is it. One check for the whole workflow and not one per job:
    // `publish` and `pages` sit behind one `alert` job, as `served-set`'s two
    // comparisons do below, and two checks would page twice for one silence.
    //
    // The interval is the signer's cron, `23 * * * *`, and it is the CADENCE
    // rather than the publication rate on purpose. D4 re-signs an unchanged
    // document only once `signed`'s copy is 20 hours old, so about one run in
    // twenty commits anything — but every completed run posts a heartbeat,
    // because what this check watches for is the signer not RUNNING. A signer
    // that stopped looks exactly like an hour in which nothing changed, and
    // the withdrawal list it is not refreshing expires in seven days, at
    // which point every armed client blocks installs.
    source: "RC-R1-2 (ROLL-62), .github/workflows/sign.yml",
    interval_seconds: 3600,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "served-set",
    party: "registry",
    // SERVE-85 and SERVE-39 are two jobs of one workflow behind one `alert`
    // job (RC-R1-5: "Same `alert` job"), so they are one heartbeat and one
    // check. Two checks here would page twice for one silence and would need a
    // second poster that does not exist.
    source: "RC-R1-4, RC-R1-5 (SERVE-85, SERVE-39), .github/workflows/served-set.yml",
    interval_seconds: 900,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "coverage-canary",
    party: "registry",
    source: "M-T1.5 (MOD-39), .github/workflows/moderation-coverage.yml",
    interval_seconds: 900,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "probe",
    party: "probe-host",
    // ROLL-15's probe runs on the owner's chosen host at 96 runs a day
    // (RC-R1-7, §2.12's probe-host decision), which is one run every 15
    // minutes. The host is still the owner's to choose; the cadence is the
    // one ROLL-21 counts against. Its ping URL lives on that host in a 0600
    // file beside its own Telegram credential, never in `alerts`: the prober
    // pages through a bot of its own precisely so that a lost catalogue host
    // cannot take the alarm with it, and a registry job holding its ping URL
    // would put both back in one place.
    source: "RC-R1-7 (ROLL-15)",
    interval_seconds: 900,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "keepalive",
    party: "registry",
    // ROLL-62's monthly keepalive, which is what keeps every other schedule in
    // this repository from lapsing. 30 days.
    source: "RC-R1-9(b) (ROLL-62)",
    interval_seconds: 2592000,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "alarm-drill",
    party: "registry",
    // Not in RC-R1-0's own table, and it belongs there: §2.0 says "every
    // scheduled check posts a BOT-85 heartbeat from such a job", and the weekly
    // alarm is a scheduled check. Without it the one workflow whose whole
    // purpose is to prove the channel still works is the one workflow whose
    // silence nothing notices — GitHub disables a schedule on an idle
    // repository, and a drill that stopped running looks exactly like a week
    // with no alarm in it.
    source: "RC-R1-0 (BOT-86), .github/workflows/alarm-drill.yml",
    interval_seconds: 604800,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "alarm-ack",
    party: "registry",
    // BOT-86's escalation, and the one check here that is not a heartbeat.
    // It is measured PER ALARM: `alarm-drill.yml` sends `start` in the step
    // that posts the weekly alarm, the acknowledgement link in that message
    // sends `success`, and the receiver alerts KNICE 48 hours after a start
    // with no success. A single "ping within 7 days + 48 hours" check measured
    // from the last success would escalate up to about 95 hours after the
    // alarm that was missed, when the previous week's was acknowledged late.
    //
    // It therefore has no silence bound: silence between alarms is normal, and
    // `alarm-drill`'s own heartbeat above is what notices a drill that stopped.
    source: "RC-R1-0 (BOT-86), .github/workflows/alarm-drill.yml",
    interval_seconds: null,
    escalation_hours: 48,
    created_disarmed: false,
    armed_at: null,
    signals: ["start", "success"],
  },
  {
    name: "canary-tag",
    party: "test-repository",
    // B-T1.6 names this check by name and puts its poster in the test
    // repository, so its secret is stored there, under the same name, and
    // never in `alerts`. It is here because the owner creates the check.
    source: "B-T1.6 (BOT-88), the test repository's canary-tag.yml",
    interval_seconds: 604800,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "release-canary",
    party: "registry",
    // Disarmed: `release-canary.yml` does not exist yet, so nothing posts here.
    source: "B-T1.6 (BOT-88), .github/workflows/release-canary.yml",
    interval_seconds: 604800,
    created_disarmed: true,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "conformance",
    party: "registry",
    // BOT-90. B-T3.11 fixes the schedule at R3; until it does, the bound
    // cannot be computed and saying so is the honest state. Disarmed: no
    // workflow posts here yet.
    source: "B-T3.11 (BOT-90)",
    interval_seconds: null,
    created_disarmed: true,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "poll-and-sweep",
    party: "registry",
    // BOT-87, at R5. Same: B-T5.0 and B-T5.1 fix the poll interval and the
    // daily sweep, and the receiver's bound is recalibrated at R3 anyway.
    // Disarmed: no workflow posts here yet.
    source: "B-T5.0, B-T5.1 (BOT-87)",
    interval_seconds: null,
    created_disarmed: true,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "deadline-watch",
    party: "registry",
    // Disarmed: no workflow posts here yet.
    source: "M-T5.4 (ROLL-63)",
    interval_seconds: 86400,
    created_disarmed: true,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: "baseline-names",
    party: "registry",
    // **Not in RC-R1-0's table, and it is owed one.** `baseline.yml` has a
    // daily `names` job: for every baseline `repository_id` it asks GitHub
    // what that repository is called today and compares the answer with
    // `source.repo`. It is MIG-20's last sentence — "the bot MUST alarm when a
    // baseline repository's current name differs, never re-baselining from a
    // name" — and it is the registry's only defence against threat row 18, the
    // name recycler: clients key on names, so a freed `owner/name` that
    // somebody else registers is an update channel into every installation of
    // that plugin.
    //
    // §2.0 says every scheduled check posts a BOT-85 heartbeat from such a
    // job, and this is a scheduled check. The alternative the alert action
    // offers — `no-heartbeat-because:` — needs a true sentence, and the two
    // true ones it is for do not apply: nobody else watches this job (the
    // service's BOT-47 watches BOT-51's ingest schedule and nothing else), and
    // it is not unscheduled. Writing one anyway would be writing down a reason
    // that is not the reason.
    //
    // What silence here would hide is specific and quiet. The job going RED is
    // visible: it fails the run. The job not RUNNING is not — GitHub disables
    // schedules on a repository with no activity, a concurrency group can
    // swallow a run, and a daily job that stopped looks exactly like a day
    // with no rename in it. That is the same argument `alarm-drill` above is
    // here for, and it is the argument BOT-85 is.
    //
    // **Created ARMED, by the rule above `CHECKS`.** This row used to say it
    // was armed against the merits, pending ONE decision about every registry
    // check whose poster lands after R1, because `baseline.yml` was expected
    // at R3. That decision was taken on 2026-09-22 (the block above `CHECKS`),
    // and by then `baseline.yml` had been on `main` since `b248a34`
    // (2026-09-19) with a live daily cron, so its `names` job is a poster that
    // runs today and this check is armed on the merits.
    source: "B-T3.7b (MIG-20's rename watch), .github/workflows/baseline.yml, the `names` job",
    interval_seconds: 86400,
    created_disarmed: false,
    armed_at: null,
    signals: ["success"],
  },
  // ── the two the plugins service posts to ───────────────────────────────────
  //
  // Created here, with the rest, because the receiver is this plan's to create
  // (ext.4) — and created DISARMED, because their poster is not. The relay's
  // delivery heartbeat is built at minice-be's W2, which is inside R2, and
  // §1.3 row 8.1 asks for it before R1's gate walk. A check armed from its
  // first minute would page every ninety minutes for a heartbeat nobody sends,
  // through the whole of R1 — the step whose exit arms every shipped client's
  // 7-day block — and the repair reached for on the third night is the one
  // repair that must never be reached for: switching the estate's only path to
  // a person off. Creating them disarmed is what stops anyone needing it
  // (attack B-1; TRUST-45: "an always-firing alarm is ignored").
  //
  // `armed_at` is filled in, in this file, by the first post each one receives,
  // and RC-R1-12's exit note says whether it was armed when R1 exited or still
  // waiting. Nothing arms them automatically: arming is a receiver setting the
  // owner changes, and this record is what says he did.
  //
  // **The names are minice-be's to supply** (§1.3 row 8.1), which is why they
  // are `null` here and why nothing may be invented in their place: a check
  // created under a guessed name is a check the service never posts to and the
  // receiver pages about for ever.
  {
    name: null,
    name_pending: "MBE-PENDING: the relay's delivery-heartbeat check name (§1.3 row 8.1)",
    party: "plugins-service",
    source: "minice-be's astra-alarm-watch, on each pass (SERVE-104)",
    interval_seconds: null,
    created_disarmed: true,
    armed_at: null,
    signals: ["success"],
  },
  {
    name: null,
    name_pending: "MBE-PENDING: the SERVE-104 evaluator's check name (§1.3 row 8.1)",
    party: "plugins-service",
    source: "minice-be's evaluator, every 15 minutes (SERVE-104)",
    interval_seconds: 900,
    created_disarmed: true,
    armed_at: null,
    signals: ["success"],
  },
];

/** How many of these the plugins service posts to. The reach assertion's floor. */
export const SERVICE_CHECK_COUNT = CHECKS.filter((c) => c.party === "plugins-service").length;

/**
 * BOT-85's silence bound: the longer of 3 × the interval and 90 minutes,
 * recalibrated at R3 to at least twice the p99 gap between completed runs over
 * 7 days (OPEN-OPS-13).
 *
 * @returns {number|null} minutes, or null when the interval is not fixed yet
 */
export function boundMinutes(check) {
  if (check.interval_seconds === null || check.interval_seconds === undefined) return null;
  return Math.max(MIN_BOUND_MINUTES, (check.interval_seconds / 60) * 3);
}

/** @returns {object|undefined} the check with this name */
export function findCheck(name) {
  return CHECKS.find((c) => c.name === name);
}

/**
 * The secret in `alerts` that carries this check's WHOLE ping URL for this
 * signal. A name, never a URL, and never a base plus a name: `_START` is a
 * second secret rather than a path appended to the first, because the receiver
 * product is still the owner's to choose (Q-O2) and appending a suffix would
 * pin this repository to one product's ping protocol before anybody picked one.
 */
export function secretName(name, signal = "success") {
  const stem = `ASTRA_DEADMAN_URL_${name.toUpperCase().replaceAll("-", "_")}`;
  return signal === "success" ? stem : `${stem}_${signal.toUpperCase()}`;
}

/**
 * Every secret the owner's act has to place in environment `alerts`, in the
 * order a person would create them. The two service checks contribute none:
 * this repository posts to neither, so it holds no value that addresses them,
 * which is the half of attack M-5's rule that this side owns.
 */
export function alertsEnvironmentSecrets() {
  const out = ["ASTRA_ALERT_TELEGRAM_TOKEN", "ASTRA_ALERT_CHAT_ID", "ASTRA_ALERT_COPY_CHAT_ID"];
  for (const check of CHECKS) {
    if (check.party !== "registry") continue;
    for (const signal of check.signals) out.push(secretName(check.name, signal));
  }
  return out;
}

/** Problems with the table itself, as a list of sentences. Empty means sound. */
export function tableProblems(checks = CHECKS) {
  const problems = [];
  const seen = new Set();
  for (const check of checks) {
    const where = check.name ?? check.name_pending ?? "(an entry with neither a name nor a pending note)";
    if (check.name === null) {
      if (!check.name_pending) problems.push(`${where}: no name and no note saying whose it is`);
      if (check.party === "registry") problems.push(`${where}: a registry check with no name cannot be posted to`);
    } else {
      if (!CHECK_NAME_RE.test(check.name)) problems.push(`${check.name}: not a check name (${CHECK_NAME_PATTERN})`);
      if (seen.has(check.name)) problems.push(`${check.name}: listed twice, so one of the two is never created`);
      seen.add(check.name);
    }
    if (!PARTIES.includes(check.party)) problems.push(`${where}: party ${JSON.stringify(check.party)} is not one of ${PARTIES.join(", ")}`);
    if (!Array.isArray(check.signals) || check.signals.length === 0) {
      problems.push(`${where}: no signals, so nothing would ever post to it`);
    }
    for (const signal of check.signals ?? []) {
      if (signal !== "success" && signal !== "start") problems.push(`${where}: signal ${JSON.stringify(signal)} is not one this estate sends`);
    }
    if (!check.source) problems.push(`${where}: no source, so nobody can tell whether a poster exists`);
    // The arming record. A check created disarmed that shows `armed: true`
    // with no date is the state RC-R1-12's exit note cannot report, and
    // "switch it off" is the repair the night it fires. Arming is recorded or
    // it did not happen.
    if (check.armed_at !== null && !isArmedAt(check.armed_at)) {
      problems.push(`${where}: armed_at is not an RFC 3339 UTC time in whole seconds`);
    }
    if (check.armed_at !== null && !check.created_disarmed) {
      problems.push(`${where}: armed_at is recorded for a check that was never disarmed`);
    }
  }
  return problems;
}
