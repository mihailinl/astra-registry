# Moderation entries

One JSON file per action taken against a **listed** plugin. Read by
`bot/lib/moderation.mjs`, published as `/transparency/moderation-log.json` and
rendered at `/transparency/`.

A refusal is not in here. A submission that never got listed is a public issue
with the failing check named; mixing the two would make the count meaningless.

## The file

Named `<date>-<plugin>-<action>.json` — the generator refuses a file whose name
does not match its contents, so a directory listing reads as a log.

```json
{
  "date": "2026-08-11",
  "action": "revoke",
  "plugin": "example-plugin",
  "versions": ["0.3.0", "0.3.1"],
  "reason": "Shipped a build that read the Astra config directory and posted it to a third-party host.",
  "advisory": "ASTRA-2026-0001",
  "appeal": "https://github.com/mihailinl/astra-registry/issues/42"
}
```

| Field | Rule |
|---|---|
| `date` | `YYYY-MM-DD`, the day the action took effect. |
| `action` | `yank`, `delist`, `deprecate` or `revoke`. |
| `plugin` | The listed plugin id. |
| `versions` | Optional. Semver strings, for an action that covers some versions and not others. |
| `reason` | 10–300 characters, shown verbatim. Bidi overrides and zero-width joiners are refused, exactly as in an advisory. |
| `advisory` | **Required** for `deprecate` and `revoke`, **refused** for `yank` and `delist`. `ASTRA-YYYY-NNNN`. |
| `appeal` | Optional https URL of the appeal thread. |

## The four actions, and what each costs a user who already installed

Escalating. Each one is a mechanism that already exists; none of them is new
behaviour invented for the log.

| Action | Expressed as | Signed? | A copy already installed |
|---|---|---|---|
| **yank** | `"yanked": true` on `plugins/<id>/versions/<semver>.json` | no | Untouched. The version leaves the catalogue (`tools/build-index.mjs` `listedReleases`). |
| **delist** | `"unlisted": true` on `plugins/<id>/plugin.json` | no | Untouched. The plugin leaves the catalogue and stops being offered updates. |
| **deprecate** | an advisory with `"action": "warn"` | yes | Badged, and the user is told. Nothing is blocked and nothing is stopped. |
| **revoke** | an advisory with `"action": "block_install"` or `"disable"` | yes | `block_install`: new installs and updates refused, a running copy left alone. `disable`: also stopped, and it will not start again. |

The last two are the ones with teeth, and they are the ones the maintainer
cannot fake here: `buildModerationLog` is given the **signed**
`revocations.json` being deployed and refuses to emit an entry whose advisory is
not in it, or whose advisory carries a different action. A transparency log that
could claim an unsigned revocation could be used to scare people off a
competitor.

## Writing one

1. Do the thing first — edit `plugins/**` for a yank or a delist, write
   `tools/revocations/ASTRA-YYYY-NNNN.json` for a deprecation or a revocation.
2. Add the file here.
3. `node bot/moderation.mjs --check` and, when an advisory is involved,
   `node bot/moderation.mjs --revocations registry/v1/revocations.json`.
4. Commit both together. A revocation deployed without its log entry is a
   withdrawal nobody can read the reason for; a log entry without its advisory
   fails the build.

## Timing

A revocation is signed and on the CDN by `.github/workflows/revoke.yml`, which
exists separately from the catalogue build precisely so it does not queue behind
it. Everything else here rides the ordinary index build.

The triage clock — how long from a report arriving to one of these four actions —
is in `docs/POLICY.md`.
