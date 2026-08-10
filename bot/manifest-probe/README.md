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

## Error codes

The crate answers `Result<PluginManifest>`: valid or not, with a sentence for a
human. The bot needs to say *which* rule was broken, in a code
`docs/BOT-CHECKS.md` documents. `classify()` in `src/main.rs` maps the crate's
error text onto those codes, and every arm is covered by a test that feeds in a
manifest which really produces it — so rewording a message upstream turns this
crate's test run red rather than silently degrading every diagnosis to
`E_MANIFEST_INVALID`.

```bash
cargo test    # 11 tests, including the `ui_panels` drift and the id-as-path-component rules
```
