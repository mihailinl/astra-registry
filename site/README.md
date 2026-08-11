# The website

Static HTML, generated from the **signed catalogue**, in the job that publishes
it. About 1,440 lines of Node ESM across six files, plus a 320-line test, no framework, and — like
everything else in this repository — **no dependencies**.

```
node site/build.mjs \
  --index       dist/registry/v1/index.json \
  --revocations dist/registry/v1/revocations.json \
  --registry-dir dist/registry/v1 \
  --out         dist/site
```

```
site/
  build.mjs             the generator, and the argument for its shape
  selftest.mjs          `node site/selftest.mjs`
  lib/html.mjs          escaping, the page shell, a small Markdown subset
  templates/plugin.mjs  /p/<id>/ — and the note on the missing deep link
  templates/advisory.mjs  /advisory/<ASTRA-YYYY-NNNN>/ and the four actions
  templates/pages.mjs   everything else
  assets/               one stylesheet, one search script
```

## The property it exists for

**A plugin page exists if and only if the signed catalogue has an entry for
it** — by construction, not by discipline.

There is one input. `--index` is the *deploy candidate itself*, after signing;
`--registry-dir` copies those same bytes into the published tree, so
`/registry/v1/index.json` on the site and the file the generator read are one
file. There is no second source a page could be generated from and no second job
for it to go stale in.

`site/selftest.mjs` asserts it in both directions against a synthetic catalogue —
an entry that is present gets exactly one page, an entry that is removed loses
its page on the next build, and the set of `p/*/` directories equals the set of
ids. `.github/workflows/build-index.yml` asserts it again against what was
actually written, after the real build.

## Pages

| Path | What it is |
|---|---|
| `/` | Every entry, with the honest privilege sentence above the fold. |
| `/p/<id>/` | One per entry: releases, artifacts with full SHA-256, permissions with the author's own reason, the provenance panel, the permanent "does not prove" block, and a `astra-plugin verify` one-liner. |
| `/search/` | Client-side, over `../registry/v1/index.json` fetched at page load. No generated search index — a second document describing the first is a document that can disagree with it. |
| `/publisher/<owner>/` | The GitHub account a plugin is released from. There are no registry accounts, so there is nothing else a publisher could be. |
| `/publish/` | `init-ci`, a tag, a listing issue. Every command on it was read out of `astra-plugin-cli/src/main.rs`. |
| `/policy/` | `POLICY.md` and `docs/POLICY.md`, rendered. |
| `/security/` | `SECURITY.md`, rendered, under the embargoed-report block generated from `bot/security-contact.json`. |
| `/transparency/` | The moderation log, the four actions, and what the log deliberately does not contain. |
| `/advisory/<ASTRA-YYYY-NNNN>/` | One per advisory **in the signed withdrawal list**. An advisory file that has not been deployed gets no page. |

## There is no `astra://` install link, and there will not be one

The scheme is already in use, and not by the plugin system: it is the
remote-daemon pairing connection string, built in three places in the Astra tree
as `astra://<host>:<port>` —

    astra-rs/astra-ui/src/pages/Oobe/OobePage.tsx:5123
    astra-rs/astra-ui/src/pages/Settings/SettingsPage.tsx:740
    astra-rs/astra-tui/src/main.rs:1751

Registering it as an OS protocol handler so a web page could hand the app an
install request would do two things at once: create a grammar collision
(`astra://install/dice-roller` and `astra://192.168.1.4:9000` arrive at one
parser, and one of them loses), and make a handler family that includes "connect
this client to that daemon" reachable from any web page in any browser with a
click. That is a remote attack surface bolted onto a pairing mechanism, bought in
exchange for saving a user one paste of a plugin id into a search box the app
already has.

So every plugin page says "open Astra, search this id". `site/selftest.mjs`
fails the build if an `href="astra:` or `src="astra:` ever appears in generated
output. The long version of the argument is at the top of
`site/templates/plugin.mjs`, which is where a future contributor will look for
the missing feature.

## Hosting

GitHub Pages, deployed by `.github/workflows/build-index.yml` when — and only
when — the catalogue was signed, which is only ever on `main`. `/registry/v1/**`
is inside the published tree, so the site and the catalogue are same-origin and
`/search/` needs no CORS.

None of that changes what a daemon fetches. Astra's `DEFAULT_REGISTRY_URL`
(`astra-daemon/src/plugins/registry_client.rs`) is a `raw.githubusercontent.com`
URL on the default branch, `plugins.registry_url` overrides it, and the
verification path contains no hostname check at all — a catalogue is believed
because a root key signed the trust document naming the key that signed it. The
copy served here is a mirror that is byte-identical because it was never a copy.

`.github/workflows/revoke.yml` rebuilds and redeploys the site too, **after** it
pushes the withdrawal list, so a slow or queued Pages deployment can never delay
the one thing in this repository that is measured in minutes.
