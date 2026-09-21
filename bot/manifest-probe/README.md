# `astra-manifest-probe`

The registry's `plugin.toml` parser, which is not a parser: it is
`astra-plugin-manifest`, the crate the **daemon** parses `plugin.toml` with,
linked and asked one question at a time.

```
$ echo '{"plugin_toml":"[plugin]\nid=\"x\"\n…"}' | astra-manifest-probe
{"schema":"astra.manifest-probe.result/1","ok":true,"findings":[],"manifest":{…}}
```

One JSON object in on stdin, one out on stdout. No network, no filesystem, no
arguments. The bot lifts `plugin.toml` and `MANIFEST.json` out of a
`.astraplugin` **in memory** and pipes them here, so a hostile bundle never
reaches a disk on the way.

Exit `0` when the manifest is acceptable, `1` when it is not, `2` when the probe
itself failed — because "the plugin is bad" and "our tooling is bad" must not
render as the same comment to a stranger.

## Why a subprocess rather than a port

`bot/README.md` has the argument in full. Short version: the *crate* is the
requirement, not the language. This binary satisfies it completely, and the rest
of the bot stays in the language that already holds exactly one implementation
of the listing rules, RFC 8785 canonicalisation and the ZIP reader — all of which
would have had to be forked to move it.

## Why the crate is not vendored here

Astra owns `astra-plugin-manifest`. AstraPlugins vendors it under a byte-equality
check. A third copy in this repository would be a third place to drift, and the
whole point of the crate (see its `lib.rs`: `ui_panels` shipped in three examples
and declared nothing at all) is that there is one definition.

So `Cargo.toml` has a path dependency into `_deps/AstraPlugins/`, which is
git-ignored and produced one of two ways:

```bash
./link-deps.sh                                    # sibling checkout, or $ASTRA_PLUGINS_DIR
ASTRA_PLUGINS_REF=<sha> ./link-deps.sh --clone    # CI
cargo build --release
```

`--clone` refuses to run without `ASTRA_PLUGINS_REF`. The rules a stranger's
listing is judged by should come from a commit somebody chose, not from whatever
`HEAD` happens to be.

That commit is `astra-plugins.pin`, beside this file: `KEY=VALUE` lines a shell
can `source` and a workflow can append to `$GITHUB_ENV` unchanged. It is the
only place the SHA is written. Every reader — `ingest.yml`'s `selftest` job,
`build-index.yml`'s `check` job, `bot-tests.yml`, and
`tools/coverage/reserved-id-mirror.mjs` for the URL — reads it from there, and
`bot/tests/workflows.test.mjs` fails a workflow that writes the pin as a
literal instead.

## Error codes

The crate answers `Result<PluginManifest>`: valid or not, with a sentence for a
human. The bot needs to say *which* rule was broken, in a code
`docs/BOT-CHECKS.md` documents. `classify()` in `src/main.rs` maps the crate's
error text onto those codes, and every arm is covered by a test that feeds in a
manifest which really produces it — so rewording a message upstream turns this
crate's test run red rather than silently degrading every diagnosis to
`E_MANIFEST_INVALID`.

```bash
cargo test    # 15 tests, including the `ui_panels` drift and the id-as-path-component rules
```

## Why it also reads the JS half, and the proto

Four of those tests assert nothing about a manifest. They are here because this
is the only part of the bot that has both halves in one process: the crate the
daemon judges by, and — through `_deps/AstraPlugins`, at the commit
`astra-plugins.pin` names — `proto/plugin.proto`. The JS half has neither, so
`bot/lib/rpcscan.mjs` carried three hand-maintained copies of things it could
not check:

| | held against |
|---|---|
| `RPC_RULES`'s permission ids | `astra_plugin_manifest::PERMISSION_NAMES` |
| `HOST_RPCS`'s method names | `service PluginHostService` in `proto/plugin.proto` |
| `HOST_RPCS` vs `ALWAYS_ALLOWED` + `RPC_RULES` | each other — every method governed exactly once |
| the header's `ten` / `four` / `six` | the three literals they count |

Only the first existed. The second is the one that cost something: the scan
searches a bundle only for names that are in `HOST_RPCS`, so an eleventh host
RPC was never searched for by anybody, and nothing anywhere went red on the day
the proto grew one. The third is subtler and is why fixing the array alone is
not the fix — `isDeclared` returns `true` for an rpc it has no rule for, so a
name added to `HOST_RPCS` and nowhere else is in the list and still exempt from
the check.
