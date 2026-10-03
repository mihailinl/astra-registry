#!/usr/bin/env node
// ROLL-60's step 0 on the re-sign canary, kept fresh with the throwaway keys.
//
//   node tools/testkeys/rehearsal-resign.mjs                 # re-sign step 0 if the signer says it is due, and push
//   node tools/testkeys/rehearsal-resign.mjs --dry-run       # everything but the push
//   node tools/testkeys/rehearsal-resign.mjs --status        # the head, its list's age, and whether Pages serves it
//   node tools/testkeys/rehearsal-resign.mjs --wait-pages    # wait until Pages serves the head, then judge the served bytes
//   node tools/testkeys/rehearsal-resign.mjs --audit-workflow .github/workflows/rehearsal-resign.yml
//
// With no `--repo` it is `mihailinl/astra-registry-canary-4`, the one re-sign
// canary, serving `fixtures/rehearsal-r2d/`'s step 0. canary-4's scheduled
// workflow runs it hourly from this repository fetched at a pinned commit
// (the template is `rehearsal-resign.yml` beside this file). Every decision is
// in `tools/lib/rehearsal-resign.mjs`, which `tools/selftest/rehearsal-resign.mjs`
// drives against local bare remotes. This file only wires the network for
// Pages and argv. The runbook is astra-plugins-ops
// `runbooks/roll-60-rehearsal.md`.

import { main } from "../lib/rehearsal-resign.mjs";

process.exit(await main(process.argv.slice(2), { fetchImpl: globalThis.fetch }));
