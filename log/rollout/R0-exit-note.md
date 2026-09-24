# R0's exit walk: the GitHub settings

This is the note beside [`R0-settings.json`](R0-settings.json), R0's marker. It
records R0's exit walk:
- ROLL-1 is walked "as a user would";
- ROLL-8's five watches (below);
- ROLL-2's commit review.

Name-free, like the marker: SHAs, run ids, counts and dates, never a login.

**Walked 2026-09-24, 03:59Z to 04:25Z,** by an astra-plugins-ops lane from a
fresh clone, against astra-registry `8503ce1`. Plan: ops
`dev/server-registry-plan-registry.md` §2.2, RC-R0-4. Contract: §9, ROLL-4 to
ROLL-7.

**The verdict: R0's exit is recorded with one watch outstanding.**
- Watch 3 has not been walked. There has been no release-desk push since the
  ruleset landed.
- The read with a token that cannot write is NOT ASKED. The read is recorded
  and the one-step way to take it is below.
- Nothing else R0 needs is missing.

## The exit needs

| need | state | evidence |
|---|---|---|
| ROLL-4: `publish` admits only `main` | **holds** | Read with no credential: custom policy, one policy `main` (branch), `can_admins_bypass: false` |
| ROLL-5: one ruleset on `main` and `signed`, refusing force pushes and deletion, requiring no pull request and no check | **holds** | Ruleset 23694850, `history is append-only`, active. It targets `refs/heads/main` and `refs/heads/signed` with rules `deletion` and `non_fast_forward`. **0 bypass actors** (credentialed read), `current_user_can_bypass: never` |
| ROLL-6: `plugins-service` admits only `main` and holds no secret | **holds** | Custom policy `main`; 0 secrets (credentialed read) |
| RC-R0-3a: `operator` admits only `main` and holds no secret | **holds** | The same |
| RC-R0-3(c): SERVE-90's ruleset half | **refused by GitHub** | On a user-owned repository GitHub Actions cannot be a bypass actor (HTTP 422, measured 2026-09-23). `served-set.yml`'s provenance check carries SERVE-90 (RC-R1-5) |
| RC-R0-3(e): ID-39 | **answered** | Written acceptance, 2026-09-13, confirmed 2026-09-24. It is in the marker's `id39` |
| RC-R0-3(f): every environment admits only `main` | **holds, 5 of 5** | `alerts`, `github-pages`, `operator`, `plugins-service`, `publish`. `bot-state` is pending until R5 |
| ROLL-7: the name-free file | **this commit** | `R0-settings.json`. Its environment rows are `policy/settings-expected.json`'s. `bot/tests/moderation-coverage.test.mjs` now compares the committed file both ways |
| ROLL-8: five watches | **4 of 5** | Below |
| ROLL-9: one correcting commit | **holds** | `3a47d90`. The grep of ROLL-9's three phrases matches only the suite's own search strings (`tools/selftest/repo-rules.mjs`); `revoke.yml` is gone |
| ROLL-10: the `KNICE-TECH` containment registered as Checked | **holds** | ops `dev/couplings.md`, row *A freed organisation login is not first-party*, watched failing 2026-09-18. It was registered by ops `2ad96b9`, which names `3a47d90` |
| SERVE-9: no catalogue-host or gcore credential | **holds** | 18 secret names in all: 16 in `alerts`, 2 in `publish`, 0 at repository level. None is a host or gcore credential |

## ROLL-8's five watches

Watches 1 and 5 name `build-index`'s `sign` and `deploy` jobs. The plan's D1
has since moved both into `sign.yml`. **What is recorded for them is the
measured equivalent, and it is named as the equivalent.**

1. **A scheduled sign and Pages deploy (the equivalent, in `sign.yml`).**
   - `Signer` run 35916493222, event `schedule`, 2026-09-23T20:31:11Z.
   - Its `publish` job re-signed both documents and pushed `signed` `5b46b89`.
   - Its `pages` job ran `actions/deploy-pages@v4` to success, as
     `github-pages` deployment 6623792662.
2. **An ingest publish push.**
   - `Ingest` run 35504547656's `publish` job pushed `de2e91e` to `main` at
     2026-09-20T10:17:13Z, catalogue serial 52, through the ruleset.
   - The latest such push: run 35847840167, `6a558d5`, 2026-09-23T10:17:24Z.
3. **A release-desk push-only rerun: NOT WALKED.**
   - The last desk commit under `releases/` is `c93e505` (0.2.5, 2026-09-11),
     before the ruleset (2026-09-19T07:51Z). Since then every human change has
     reached `main` as a pull-request merge.
   - The partial evidence is not the watch:
     - the ruleset's rules are only `deletion` and `non_fast_forward`;
     - the fast-forward pushes it admitted since are the bot's (watch 2) and
       the signer's to `signed`.
   - The watch is walked at the next desk release, and recorded as an
     amendment beside this note.
4. **A job in `publish` on a throwaway branch, referencing no secret, refused.**
   - Branch `lane-ck/r0-watch-4`, commit `79f091d`, pushed 04:10:49Z. It
     carried one workflow whose job declares `environment: publish` and runs
     `echo`.
   - Run 35954546183, job 107489964459: **0 steps, no runner**. The annotation
     read *"Branch "lane-ck/r0-watch-4" is not allowed to deploy to publish due
     to environment protection rules."*
   - Deployment 6630004005 ended `failure`.
   - The branch was deleted at 04:11:13Z; `git ls-remote` then found 0 refs.
   - The same refusal was seen for `alerts` on 2026-09-23 (run 35801502108).
5. **A pull-request run with checks and no signing (the equivalent).**
   - `Registry index` run 35955470751, event `pull_request`, head `20f7223`:
     `check` success.
   - The workflow has had no signing job since D1. `sign.yml` has no
     `pull_request` trigger, and 0 of its 243 runs came from one (173 push,
     21 schedule, 49 workflow_run).
   - `tools/selftest/repo-rules.mjs`'s *"no job that can reach the publish
     environment runs on a pull request"* holds the rule in the suite.

## The recurring live read (OPEN-OPS-1) and its throwaway key

**The read, 2026-09-24.**
- **With no credential**, as an outsider: the repository, `/environments`,
  each environment's deployment-branch policies, `/rulesets`, the ruleset,
  `/rules/branches/main` and `/branches/main`.
  - All answered 200.
  - `/collaborators`, `/keys`, environment secrets and `/actions/permissions`
    answered **401**.
- **The rest, with a session that can write**:
  - collaborators: 1, admin;
  - deploy keys: 0;
  - secret names;
  - Actions permissions: enabled, all actions, default workflow permission
    `read`;
  - bypass actors: 0.

**The read with a token that cannot write: NOT ASKED.**
- **Why:** no credential that cannot write exists on this side, and none may
  be minted by an agent.
- **The one step for the owner:**
  - Create a fine-grained token: *Settings → Developer settings → Fine-grained
    tokens*.
    - Resource owner: this repository's owner.
    - Only this repository.
    - Repository permissions *Administration*, *Environments*, *Secrets* and
      *Actions*, each **read-only**. *Metadata* is read-only by default.
    - One day's expiry.
  - Run in his own shell:

    ```sh
    GH_TOKEN=<token> sh -c 'gh api -X POST repos/mihailinl/astra-registry/keys -f title=write-probe -f key=not-a-key; node ~/Documents/GitHub/astra-plugins-ops/tools/read-settings.mjs'
    ```

- **How the probe line proves the token cannot write, without writing.**
  - A token that can add a deploy key reaches validation and gets **422**
    ("key is invalid"). Measured 2026-09-24 with the write-capable session: 422,
    and 0 keys afterwards.
  - A token that cannot gets **403**. That half is not measured; it is what
    GitHub documents.
  - Bypass actors stay with a write-capable session: GitHub shows them only to
    a caller that can edit the ruleset.

**The throwaway deploy key (RC-R0-4's canary: the read notices a new entry and
records its flag).**

| | UTC | evidence |
|---|---|---|
| before | 04:11:21Z | 0 deploy keys |
| private half destroyed | 04:11:21Z | `shred -u`, **before** the public half was uploaded, so no usable key existed during the window |
| added, read-only | 04:11:21Z | id 164269936, `SHA256:0bTGvca6fSS5rBboRN1SR+CNcZEgxpCsJWdppbimnUY`, `read_only: true` |
| the read reports it | between 04:11:22Z and 04:11:36Z | ops `tools/read-settings.mjs`, "Deploy keys": `count: 1`, `**read-only**` |
| deleted | 04:11:36Z | `DELETE /keys/164269936` |
| the next read | after 04:11:36Z | `count: 0 (empty)`; `GET /keys/164269936` returned 404 |

## ROLL-2: commit review of R0's commits

ROLL-2's check is "commit review at exit". Each commit spans one repository,
by construction of git. The review question is whether each cross-repository
step landed in order and names what came before it.

| task | commit | repository | names its predecessor | finding |
|---|---|---|---|---|
| RC-R0-1 | `3a47d90` | registry | first, none needed | one commit (ROLL-9) |
| RC-R0-5 | `2ad96b9` | ops | names `3a47d90` | as planned |
| RC-R0-2 | `5ccffe5` | ops | before the settings | as planned |
| B-T0.1, B-T0.4a | `a1c76a3` | registry | names `126189c` and `f67a646` (the defect's instances) | as planned |
| B-T0.4a's measurement | `493a7dd` | registry | names run 35485336476 | as planned |
| B-T0.4a's record | ops PR #75 (`1aa115c`, merged 2026-09-20T10:04:36Z), in the owner's morning runbook; then `notes/state.md`, where the plan puts it, by ops PR #87 (`73f8bb4`, merged 2026-09-21T01:46:42Z) | ops | the measurement run 35487527105 | the answer was on ops `main` 15.7 h before B-T0.4b; **the record in the file the plan names came 23 s after** |
| B-T0.4b, B-T0.2 | `285d5e0` (registry PR #118, merged 2026-09-21T01:46:19Z) | registry | names **run** 35487527105, not an ops SHA | **partial**: it relied on an answer already on ops `main` (#75), but names no ops SHA, and it landed 23 s before the record in the file the plan names |
| B-T0.3 | `c3f78bb`, `3468544`, `cbb2d53` | registry | `c3f78bb` names ops `3d63ea7`; `3468544` names `c3f78bb`; `cbb2d53` names `3468544` | as planned |
| B-T0.3's record | `920a715` | ops | names `3468544` and `c3f78bb` | as planned |
| B-T0.5, B-T0.6 | `1c06025` | registry | registry-only | as planned |
| AP-1 | `e3923e0` | AstraPlugins | names Astra `02d5bcff`, cut from Astra's main, not the plan's `4111841`, and says why | as planned |

The one partial is small. Nothing was relied on before it was measured: the
answer, `answered=true`, was on ops `main` from 2026-09-20T10:04:36Z. But the
rule "each commit names the previous SHA" was met by naming a run, and the
plan's record location trailed the registry commit by 23 seconds.

## What R0's exit hands on

- **Watch 3**, walked at the next release-desk push.
- **The read with a token that cannot write**, taken by the owner in one step.
- **The monthly read**, from this file, and **each exit walk's read**. An
  amendment is a new dated file under `log/rollout/`, because `log/**` is
  append-only (MOD-34). The file already pins `alerts`; `bot-state` joins at
  R5.
- **The private half of ROLL-7**, in ops `notes/state.md`: the repository and
  owner ids, which are also in the marker, and every account with write
  access, by name.
