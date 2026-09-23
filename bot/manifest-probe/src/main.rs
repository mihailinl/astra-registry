//! `astra-manifest-probe` — the daemon's manifest parse, as a subprocess.
//!
//! One JSON object in on stdin, one JSON object out on stdout. It never touches
//! the network, never reads a path it was not handed, and never writes a file.
//! The bot pipes it two strings it has already lifted out of a `.astraplugin`
//! **in memory** — `plugin.toml` and `MANIFEST.json` — and gets back either a
//! description of the plugin or a list of coded findings.
//!
//! # Why this exists at all
//!
//! Because `plugin.toml` has exactly one definition, and it is
//! [`astra_plugin_manifest::PluginManifest`] — the type the daemon deserializes
//! on the install path. A registry that judged manifests with its own parser
//! would be judging a different language than the one users run: that is how
//! `ui_panels` shipped in three examples and declared nothing at all
//! (see the crate's `capabilities.rs`). So the registry does not have a parser.
//! It has this, and this has the crate.
//!
//! # Why the findings are coded here and not upstream
//!
//! The crate answers `Result<PluginManifest>`: valid or not, with a sentence for
//! a human. The bot has to say *which* rule a stranger broke, in a code that
//! `docs/BOT-CHECKS.md` documents and that never changes wording, so the issue
//! comment is actionable and the failure class is greppable. So this file maps
//! the crate's error text onto codes — and [`tests`] asserts every mapping
//! against a manifest that really produces it. Reword an upstream message and
//! the mapping does not silently degrade to `E_MANIFEST_INVALID`: the test
//! turns red.
//!
//! # What it deliberately does not decide
//!
//! Anything that needs more than the manifest text: digests, attestations,
//! ownership, typosquatting, the archive's shape. Those live in the JS half,
//! which owns the bytes. This process is pure and total — same input, same
//! output, no ambient authority.

use std::io::Read;

use astra_plugin_manifest::{
    CAPABILITY_NAMES, PERMISSION_NAMES, PluginManifest, is_reserved_device_name, platform_key_for,
};
use serde::{Deserialize, Serialize};

/// What the bot sends. Unknown members are refused: a request this build does
/// not understand must not be answered as though it had been understood.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// The exact bytes of `plugin.toml` as they sit in the bundle.
    plugin_toml: String,
    /// The exact bytes of `MANIFEST.json`, when the caller has them.
    #[serde(default)]
    manifest_json: Option<String>,
    /// "Would this install on Astra X?" — asked, never assumed. This binary is
    /// not an Astra (the crate's `astra-host` feature is off here), so there is
    /// no host version to read; the bot supplies the floor it wants tested.
    #[serde(default)]
    host_astra_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct Finding {
    level: &'static str,
    code: &'static str,
    message: String,
}

impl Finding {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self { level: "error", code, message: message.into() }
    }
    fn warn(code: &'static str, message: impl Into<String>) -> Self {
        Self { level: "warn", code, message: message.into() }
    }
}

/// Everything the bot derives a listing from. Every field here comes out of the
/// bundle, which is covered by the attestation — nothing is taken from a form.
#[derive(Debug, Serialize)]
struct ManifestFacts {
    id: String,
    name: String,
    version: String,
    description: String,
    author: String,
    license: String,
    homepage: String,
    min_astra_version: String,
    call_timeout_secs: Option<u64>,
    capabilities: Vec<String>,
    entry_command: String,
    entry_args: Vec<String>,
    entry_cwd: String,
    entry_runtimes: Vec<String>,
    platform_os: Vec<String>,
    platform_arch: Vec<String>,
    /// The registry artifact key `[platform]` implies, when it implies exactly
    /// one. `null` means "the manifest does not pin a single host" — which is
    /// normal for a `noarch` plugin and is decided from `MANIFEST.platform`, not
    /// from here.
    platform_key: Option<String>,
    dependencies: std::collections::BTreeMap<String, String>,
    ui_contribution_ids: Vec<String>,
    has_config_schema: bool,
}

#[derive(Debug, Serialize)]
struct Response {
    schema: &'static str,
    ok: bool,
    findings: Vec<Finding>,
    manifest: Option<ManifestFacts>,
    /// The vocabulary this build accepts, echoed so the JS half never has to
    /// carry a second copy of the capability list to render a hint with.
    known_capabilities: &'static [&'static str],
}

const RESULT_SCHEMA: &str = "astra.manifest-probe.result/1";

fn main() {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        emit(Response {
            schema: RESULT_SCHEMA,
            ok: false,
            findings: vec![Finding::error("E_PROBE_INPUT", format!("cannot read stdin: {e}"))],
            manifest: None,
            known_capabilities: CAPABILITY_NAMES,
        });
        std::process::exit(2);
    }

    let request: Request = match serde_json::from_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            emit(Response {
                schema: RESULT_SCHEMA,
                ok: false,
                findings: vec![Finding::error(
                    "E_PROBE_INPUT",
                    format!("the request is not a valid probe request: {e}"),
                )],
                manifest: None,
                known_capabilities: CAPABILITY_NAMES,
            });
            std::process::exit(2);
        }
    };

    let response = probe(&request);
    let ok = response.ok;
    emit(response);
    // 0 = the manifest is acceptable, 1 = it is not, 2 = the probe itself
    // failed. The bot distinguishes all three: "the plugin is bad" and "our
    // tooling is bad" must never render as the same comment to a stranger.
    std::process::exit(if ok { 0 } else { 1 });
}

fn emit(response: Response) {
    println!("{}", serde_json::to_string(&response).expect("Response is serializable"));
}

fn probe(request: &Request) -> Response {
    let mut findings = Vec::new();

    // ── the parse, by the daemon's own code ─────────────────────────────────
    //
    // `from_str` is `toml::from_str` + `validate()`, and it is the constructor
    // the install path uses. Calling the two halves separately would be a
    // second opinion; there is only one opinion here.
    let manifest = match PluginManifest::from_str(&request.plugin_toml) {
        Ok(m) => m,
        Err(e) => {
            findings.push(classify(&e));
            return Response {
                schema: RESULT_SCHEMA,
                ok: false,
                findings,
                manifest: None,
                known_capabilities: CAPABILITY_NAMES,
            };
        }
    };

    // ── the rules the crate exposes as predicates ───────────────────────────
    //
    // `validate()` already refused a reserved device name, so reaching this
    // with one would mean the crate changed under us. Asserted rather than
    // assumed: this is the id that becomes `<plugins_dir>/<id>/` and is passed
    // to `remove_dir_all`, and a check that silently stopped running is the
    // failure mode the whole trust chain is built to avoid.
    if is_reserved_device_name(&manifest.plugin.id) {
        findings.push(Finding::error(
            "E_ID_RESERVED_DEVICE",
            format!(
                "plugin.id '{}' is a reserved Windows device name. It would name the console \
                 device instead of a directory on every Windows install.",
                manifest.plugin.id
            ),
        ));
    }

    // ── MANIFEST.json must describe the same plugin as plugin.toml ──────────
    //
    // §5.3-D: the daemon asserts these agree at install. A bundle where they do
    // not is a bundle whose listing describes one plugin and whose extracted
    // directory is another, and the registry is the last place that can say so
    // before a user's machine does.
    if let Some(json) = &request.manifest_json {
        match serde_json::from_str::<serde_json::Value>(json) {
            Ok(v) => {
                let bundle_id = v.get("plugin_id").and_then(|x| x.as_str());
                let bundle_version = v.get("version").and_then(|x| x.as_str());
                if let Some(bid) = bundle_id
                    && bid != manifest.plugin.id
                {
                    findings.push(Finding::error(
                        "E_TOML_MANIFEST_DISAGREE",
                        format!(
                            "MANIFEST.json says plugin_id {bid:?} and plugin.toml says {:?}. \
                             The daemon installs under the manifest's id and starts what \
                             plugin.toml describes; when they differ, one of the two is a lie.",
                            manifest.plugin.id
                        ),
                    ));
                }
                if let Some(bv) = bundle_version
                    && bv != manifest.plugin.version
                {
                    findings.push(Finding::error(
                        "E_TOML_MANIFEST_DISAGREE",
                        format!(
                            "MANIFEST.json says version {bv:?} and plugin.toml says {:?}.",
                            manifest.plugin.version
                        ),
                    ));
                }
                // The entry command the daemon executes comes from MANIFEST.json
                // on the install path. A plugin.toml that names a different one
                // is not a rejection — plugin.toml's copy is what `astra-plugin
                // dev` runs — but it means the reviewed thing and the executed
                // thing are not the same file.
                if let Some(cmd) =
                    v.get("entry").and_then(|e| e.get("command")).and_then(|c| c.as_str())
                    && cmd != manifest.entry.command
                {
                    findings.push(Finding::warn(
                        "W_ENTRY_COMMAND_DISAGREE",
                        format!(
                            "MANIFEST.json runs {cmd:?}; plugin.toml declares {:?}. The daemon \
                             executes the manifest's.",
                            manifest.entry.command
                        ),
                    ));
                }
            }
            Err(e) => findings.push(Finding::error(
                "E_MANIFEST_INVALID",
                format!("MANIFEST.json is not valid JSON: {e}"),
            )),
        }
    }

    // ── "would it install on the Astra we publish for?" ─────────────────────
    if let Some(host) = &request.host_astra_version
        && let Err(e) = manifest.check_min_astra_version(host)
    {
        findings.push(Finding::error("E_MIN_ASTRA_TOO_NEW", e.to_string()));
    }

    // A single-host manifest gets its registry key derived here, by the same
    // function the daemon looks the download up with. Silence when `[platform]`
    // names more than one host or none: that is `noarch`, and the archive's
    // `MANIFEST.platform` decides it, not this.
    let platform_key = match (manifest.platform.os.as_slice(), manifest.platform.arch.as_slice()) {
        ([os], [arch]) => match platform_key_for(os, arch) {
            Ok(key) => Some(key.to_string()),
            Err(e) => {
                findings.push(Finding::error(
                    "E_PLATFORM_UNSUPPORTED",
                    format!(
                        "{e} A bundle published for a host Astra ships no daemon for has nothing \
                         to run on."
                    ),
                ));
                None
            }
        },
        _ => None,
    };

    let facts = ManifestFacts {
        id: manifest.plugin.id.clone(),
        name: manifest.plugin.name.clone(),
        version: manifest.plugin.version.clone(),
        description: manifest.plugin.description.clone(),
        author: manifest.plugin.author.clone(),
        license: manifest.plugin.license.clone(),
        homepage: manifest.plugin.homepage.clone(),
        min_astra_version: manifest.plugin.min_astra_version.clone(),
        call_timeout_secs: manifest.plugin.call_timeout_secs,
        capabilities: manifest.capabilities.as_list().into_iter().map(String::from).collect(),
        entry_command: manifest.entry.command.clone(),
        entry_args: manifest.entry.args.clone(),
        entry_cwd: manifest.entry.cwd.clone(),
        entry_runtimes: manifest.entry.runtimes.clone(),
        platform_os: manifest.platform.os.clone(),
        platform_arch: manifest.platform.arch.clone(),
        platform_key,
        dependencies: manifest.dependencies.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ui_contribution_ids: manifest
            .ui
            .as_ref()
            .map(|u| u.contributions.iter().map(|c| c.id.clone()).collect())
            .unwrap_or_default(),
        has_config_schema: manifest.config.is_some(),
    };

    Response {
        schema: RESULT_SCHEMA,
        ok: !findings.iter().any(|f| f.level == "error"),
        findings,
        manifest: Some(facts),
        known_capabilities: CAPABILITY_NAMES,
    }
}

/// The crate's prose, mapped onto a code the docs describe and a stranger can
/// grep for.
///
/// The whole error chain is searched, not just the outermost message: `from_str`
/// wraps a `toml` error in "Failed to parse plugin.toml", so the sentence that
/// names the actual problem is one or two levels down.
///
/// Every arm is covered by a test that feeds in a manifest which really produces
/// it. That is the only thing keeping this from rotting into
/// `E_MANIFEST_INVALID` for everything the day someone rewords a message
/// upstream.
fn classify(err: &anyhow::Error) -> Finding {
    let text = err.chain().map(|c| c.to_string()).collect::<Vec<_>>().join(": ");
    let lower = text.to_ascii_lowercase();

    if lower.contains("reserved windows device name") {
        return Finding::error(
            "E_ID_RESERVED_DEVICE",
            format!(
                "{text}\nPick another id. `con`, `prn`, `aux`, `nul`, `com1`-`com9` and \
                 `lpt1`-`lpt9` name devices on Windows, not directories."
            ),
        );
    }
    if lower.contains("must not end with a dot or space") {
        return Finding::error(
            "E_ID_CHARSET",
            format!("{text}\nWindows strips a trailing dot or space, so the id and the directory it creates would not be the same string."),
        );
    }
    if lower.contains("plugin.id must be lowercase") {
        return Finding::error(
            "E_ID_CHARSET",
            format!("{text}\nThe id becomes a directory name on every user's disk: lowercase letters, digits and hyphens only."),
        );
    }
    if lower.contains("min_astra_version") {
        return Finding::error(
            "E_MIN_ASTRA_INVALID",
            format!("{text}\nWrite a plain semver version, e.g. `min_astra_version = \"0.9.0\"`. A value that does not parse is a requirement that requires nothing."),
        );
    }
    if lower.contains("entry.command is required") {
        return Finding::error(
            "E_ENTRY_COMMAND_MISSING",
            format!("{text}\nAdd an `[entry]` section with the program the daemon should run."),
        );
    }
    if lower.contains("is required") {
        return Finding::error(
            "E_MANIFEST_FIELD_MISSING",
            format!("{text}\nEvery listing needs `plugin.id`, `plugin.name` and `plugin.version`."),
        );
    }
    // An unknown `[capabilities]` key. `deny_unknown_fields` is what makes this
    // an error instead of a silent "no capabilities enabled", and the crate's
    // `explain_unknown_capability` already puts the correct name in the text.
    if lower.contains("unknown field") && lower.contains("capabilit") {
        return Finding::error(
            "E_CAPABILITY_UNKNOWN",
            format!(
                "{text}\nThe vocabulary is: {}.",
                CAPABILITY_NAMES.join(", ")
            ),
        );
    }
    if lower.contains("unknown field") {
        return Finding::error("E_CAPABILITY_UNKNOWN", text);
    }
    Finding::error("E_MANIFEST_INVALID", text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(toml: &str) -> Request {
        Request {
            plugin_toml: toml.to_string(),
            manifest_json: None,
            host_astra_version: None,
        }
    }

    fn codes(r: &Response) -> Vec<&'static str> {
        r.findings.iter().map(|f| f.code).collect()
    }

    const GOOD: &str = r#"
[plugin]
id = "dice-roller"
name = "Dice Roller"
version = "0.2.0"
description = "Rolls dice"
license = "MIT"
min_astra_version = "0.9.0"

[entry]
command = "./bin/dice_roller"

[capabilities]
tools = true
triggers = true

[platform]
os = ["linux"]
arch = ["x86_64"]
"#;

    #[test]
    fn a_conforming_manifest_yields_facts_and_no_findings() {
        let r = probe(&req(GOOD));
        assert!(r.ok, "{:?}", r.findings);
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        let m = r.manifest.expect("facts");
        assert_eq!(m.id, "dice-roller");
        assert_eq!(m.version, "0.2.0");
        assert_eq!(m.capabilities, vec!["tools", "triggers"]);
        assert_eq!(m.platform_key.as_deref(), Some("linux-x64"));
        assert_eq!(m.entry_command, "./bin/dice_roller");
        assert_eq!(m.license, "MIT");
    }

    /// The whole reason this binary is Rust. `ui_panels` is the name the CLI's
    /// fork invented; three shipped examples declared it and the daemon read no
    /// capabilities from any of them. A registry that used its own parser would
    /// list those plugins as capable of nothing and say nothing about it.
    #[test]
    fn the_capability_that_drifted_is_a_hard_error_here() {
        let toml = GOOD.replace("tools = true", "ui_panels = true");
        let r = probe(&req(&toml));
        assert!(!r.ok);
        assert_eq!(codes(&r), vec!["E_CAPABILITY_UNKNOWN"]);
        assert!(
            r.findings[0].message.contains("ui_contributions"),
            "the correct name must be in the message: {}",
            r.findings[0].message
        );
    }

    /// Each of these asserts one arm of `classify` against a manifest that
    /// really produces it. Reword a message in the crate and the arm stops
    /// matching — which shows up here, not as a stranger receiving
    /// `E_MANIFEST_INVALID` for a problem the bot could have named.
    #[test]
    fn every_classified_message_is_produced_by_a_real_manifest() {
        for (id, expected) in [
            ("con", "E_ID_RESERVED_DEVICE"),
            ("com1", "E_ID_RESERVED_DEVICE"),
            ("Dice-Roller", "E_ID_CHARSET"),
            ("../evil", "E_ID_CHARSET"),
            ("dice.", "E_ID_CHARSET"),
        ] {
            let toml = GOOD.replace(r#"id = "dice-roller""#, &format!(r#"id = "{id}""#));
            let r = probe(&req(&toml));
            assert_eq!(codes(&r), vec![expected], "id {id:?} -> {:?}", r.findings);
        }

        let toml = GOOD.replace(r#"min_astra_version = "0.9.0""#, r#"min_astra_version = "nightly""#);
        assert_eq!(codes(&probe(&req(&toml))), vec!["E_MIN_ASTRA_INVALID"]);

        let toml = GOOD.replace(r#"command = "./bin/dice_roller""#, r#"command = """#);
        assert_eq!(codes(&probe(&req(&toml))), vec!["E_ENTRY_COMMAND_MISSING"]);

        let toml = GOOD.replace(r#"name = "Dice Roller""#, r#"name = """#);
        assert_eq!(codes(&probe(&req(&toml))), vec!["E_MANIFEST_FIELD_MISSING"]);
    }

    #[test]
    fn a_manifest_json_naming_another_plugin_is_refused() {
        let mut r = req(GOOD);
        r.manifest_json = Some(
            r#"{"plugin_id":"not-dice-roller","version":"0.2.0","entry":{"command":"./bin/dice_roller"}}"#
                .to_string(),
        );
        let out = probe(&r);
        assert!(!out.ok);
        assert_eq!(codes(&out), vec!["E_TOML_MANIFEST_DISAGREE"]);
    }

    #[test]
    fn a_manifest_json_at_another_version_is_refused() {
        let mut r = req(GOOD);
        r.manifest_json = Some(r#"{"plugin_id":"dice-roller","version":"9.9.9"}"#.to_string());
        assert_eq!(codes(&probe(&r)), vec!["E_TOML_MANIFEST_DISAGREE"]);
    }

    /// Not a rejection: `astra-plugin dev` runs plugin.toml's command and the
    /// daemon runs the manifest's, so the two legitimately differ during
    /// development. It is still worth saying that the reviewed program and the
    /// executed program are different files.
    #[test]
    fn a_different_entry_command_in_the_bundle_manifest_warns_only() {
        let mut r = req(GOOD);
        r.manifest_json =
            Some(r#"{"plugin_id":"dice-roller","version":"0.2.0","entry":{"command":"./bin/other"}}"#.to_string());
        let out = probe(&r);
        assert!(out.ok, "{:?}", out.findings);
        assert_eq!(codes(&out), vec!["W_ENTRY_COMMAND_DISAGREE"]);
    }

    /// The floor is asked for, never assumed: this build is not an Astra, so
    /// "which Astra?" is the caller's question to answer.
    #[test]
    fn the_astra_floor_is_only_compared_when_the_caller_names_one() {
        let toml = GOOD.replace(r#"min_astra_version = "0.9.0""#, r#"min_astra_version = "99.0.0""#);
        let out = probe(&req(&toml));
        assert!(out.ok, "no host named, nothing to compare: {:?}", out.findings);

        let mut r = req(&toml);
        r.host_astra_version = Some("0.9.0".to_string());
        let out = probe(&r);
        assert!(!out.ok);
        assert_eq!(codes(&out), vec!["E_MIN_ASTRA_TOO_NEW"]);
        assert!(out.findings[0].message.contains("99.0.0"));
    }

    /// A macOS or arm64 bundle has no host: Astra's release workflow builds no
    /// daemon for either, so listing it would publish a file nobody can run.
    #[test]
    fn a_platform_with_no_astra_daemon_is_refused() {
        let toml = GOOD.replace(r#"os = ["linux"]"#, r#"os = ["macos"]"#);
        let out = probe(&req(&toml));
        assert!(!out.ok);
        assert_eq!(codes(&out), vec!["E_PLATFORM_UNSUPPORTED"]);
    }

    /// `noarch` is the interpreted-language case and it is not an error: the
    /// key comes from the archive's `MANIFEST.platform`, and a manifest with no
    /// `[platform]` section pins no host by design.
    #[test]
    fn a_manifest_with_no_platform_section_pins_no_key_and_is_fine() {
        let toml = GOOD
            .replace(r#"os = ["linux"]"#, "")
            .replace(r#"arch = ["x86_64"]"#, "")
            .replace(r#"command = "./bin/dice_roller""#, r#"command = "node""#);
        let out = probe(&req(&toml));
        assert!(out.ok, "{:?}", out.findings);
        assert_eq!(out.manifest.expect("facts").platform_key, None);
    }

    /// The sections the CLI's fork silently dropped. If any of them stops
    /// reaching the bot, the registry starts publishing listings that describe
    /// less than the plugin is.
    #[test]
    fn the_whole_manifest_reaches_the_bot() {
        let toml = r#"
[plugin]
id = "kitchen-sink"
name = "Kitchen Sink"
version = "1.2.3"
author = "Astra Team"
license = "Apache-2.0"
homepage = "https://example.invalid/"
call_timeout_secs = 180

[entry]
command = "{venv}/python"
args = ["-m", "sink"]
runtimes = ["python"]

[dependencies]
astra-plugin-sdk = ">=0.6,<0.7"

[config]
schema = "{}"

[ui]
[[ui.contributions]]
id = "sink-panel"
"#;
        let m = probe(&req(toml)).manifest.expect("facts");
        assert_eq!(m.call_timeout_secs, Some(180));
        assert_eq!(m.entry_args, vec!["-m", "sink"]);
        assert_eq!(m.entry_runtimes, vec!["python"]);
        assert_eq!(m.dependencies.get("astra-plugin-sdk").map(String::as_str), Some(">=0.6,<0.7"));
        assert_eq!(m.ui_contribution_ids, vec!["sink-panel"]);
        assert!(m.has_config_schema);
        assert_eq!(m.license, "Apache-2.0");
    }

    /// Every permission id the JS half puts in front of an author must be one
    /// the daemon actually has.
    ///
    /// `bot/lib/rpcscan.mjs` tells a submitter which declaration would make an
    /// undeclared host call legitimate. It is JavaScript, so it cannot import
    /// [`astra_plugin_manifest::PERMISSION_NAMES`], and it drifted exactly the
    /// way an uncheckable copy does: it carried `get_daemon_info`, an id in no
    /// vocabulary anywhere. An author following that hint would have declared a
    /// key the daemon files as unrecognised and §4.3's consent sheet renders as
    /// "not recognised by this version" — a scary box on a store page, bought
    /// for a call that needs no permission at all.
    ///
    /// This test is in Rust because Rust is where the vocabulary lives. It reads
    /// the JS as text for the same reason the daemon's consistency canaries do:
    /// the alternative is a fourth copy of the list.
    #[test]
    fn every_permission_the_js_half_names_is_a_real_one() {
        let js = include_str!("../../lib/rpcscan.mjs");
        let rules = js
            .split("export const RPC_RULES")
            .nth(1)
            .expect("RPC_RULES must still be exported from rpcscan.mjs");
        let body = rules.split("};").next().expect("RPC_RULES literal");

        let mut seen = 0;
        for chunk in body.split("permission: \"").skip(1) {
            let id = chunk.split('"').next().expect("a closing quote");
            assert!(
                PERMISSION_NAMES.contains(&id),
                "bot/lib/rpcscan.mjs offers `[permissions] {id}`, which is not one of the \
                 {} ids the daemon knows ({}). An author told to declare it would get a \
                 permission the daemon treats as inert.",
                PERMISSION_NAMES.len(),
                PERMISSION_NAMES.join(", "),
            );
            seen += 1;
        }
        // A vacuity guard: a rename that emptied the table would otherwise pass.
        assert!(
            seen >= 6,
            "only {seen} permission id(s) found in RPC_RULES — the parse above has \
             stopped matching the file's shape, so this test is checking nothing"
        );
    }

    // ── `HOST_RPCS`, and the proto it is a copy of ──────────────────────────
    //
    // The test above pins `RPC_RULES`'s permission **ids** to the daemon's
    // vocabulary. Nothing pinned the **method names** beside them, and the
    // asymmetry was invisible precisely because the neighbouring literal was
    // held: `HOST_RPCS` appeared exactly twice in the whole registry — its
    // declaration at `bot/lib/rpcscan.mjs:49` and its one loop at `:297` — and
    // was compared with nothing at all.
    //
    // What that costs is not an error. It is silence. `scanHostRpcs` only ever
    // searches a bundle for names that are IN that array, so an eleventh host
    // RPC is never searched for: the author who copies a snippet, calls it and
    // ships a manifest that never declared the permission gets a clean scan, a
    // green listing, and a plugin that fails at run time on a user's machine
    // with a permission error nobody can debug from the store page — which is
    // the exact failure the scan exists to prevent. Nothing goes red, in this
    // repository or anywhere else, on the day the proto grows a method.
    //
    // These tests are here, in Rust, for the same reason the permission test
    // is: this is the one part of the bot that already has a checkout of
    // AstraPlugins at the commit `astra-plugins.pin` names, so `plugin.proto`
    // can be read rather than re-described. `bot-tests.yml` and `ingest.yml`
    // already run `cargo test` on this crate, so the check has a workflow
    // without one being added.

    /// `bot/lib/rpcscan.mjs`, read as text — the alternative is a fourth copy
    /// of the list, which is the thing being prevented.
    const RPCSCAN_MJS: &str = include_str!("../../lib/rpcscan.mjs");

    /// `proto/plugin.proto` out of the pinned AstraPlugins checkout.
    ///
    /// A missing file is a FAILURE and never a skip. A test that quietly
    /// passed because it could not find the thing it compares would be worse
    /// than no test: it would close this gap on paper.
    fn pinned_proto() -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("_deps/AstraPlugins/proto/plugin.proto");
        std::fs::read_to_string(&p).unwrap_or_else(|e| {
            panic!(
                "cannot read {}: {e}. That path is the AstraPlugins checkout \
                 `bot/manifest-probe/astra-plugins.pin` names — the same one this \
                 crate's path dependency links. Run `bot/manifest-probe/link-deps.sh`. \
                 This test does not skip when the proto is absent, because a host \
                 RPC list compared against nothing is what it exists to refuse.",
                p.display()
            )
        })
    }

    /// The `rpc` method names inside one `service` block of a `.proto`.
    ///
    /// Scoped to the named service on purpose: `SubscribeEvents` is declared by
    /// `CoreService` and `ChatService` as well, so a whole-file search for a
    /// method name would answer "yes" for a name `PluginHostService` does not
    /// serve — wrong in the permissive direction, which is the direction that
    /// does not go red.
    ///
    /// Line comments are removed before the braces are counted, so a `{` in
    /// prose cannot move the end of the block.
    fn proto_service_rpcs(proto: &str, service: &str) -> Vec<String> {
        let uncommented: String = proto
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");

        let needle = format!("service {service} {{");
        let start = uncommented
            .find(&needle)
            .unwrap_or_else(|| panic!("`{needle}` is not in proto/plugin.proto"))
            + needle.len();
        let rest = &uncommented[start..];

        let mut depth = 1usize;
        let mut end = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }

        rest[..end]
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("rpc "))
            .map(|r| {
                r.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect::<String>()
            })
            .filter(|n| !n.is_empty())
            .collect()
    }

    /// The double-quoted strings of a JS array literal that begins at `opener`.
    fn js_string_list(js: &str, opener: &str) -> Vec<String> {
        let body = js
            .split(opener)
            .nth(1)
            .unwrap_or_else(|| panic!("`{opener}` is not in bot/lib/rpcscan.mjs"))
            .split(']')
            .next()
            .expect("a closing bracket");
        body.split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    }

    /// The keys of the `RPC_RULES` object literal.
    fn rpc_rules_keys(js: &str) -> Vec<String> {
        let body = js
            .split("export const RPC_RULES = {")
            .nth(1)
            .expect("RPC_RULES must still be exported from rpcscan.mjs")
            .split("\n};")
            .next()
            .expect("the RPC_RULES literal");
        body.lines()
            .filter_map(|l| l.trim().split_once(": {"))
            .map(|(k, _)| k.to_string())
            .filter(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric()))
            .collect()
    }

    fn set(v: &[String]) -> std::collections::BTreeSet<String> {
        v.iter().cloned().collect()
    }

    /// `HOST_RPCS` is `PluginHostService`, or the scan has a blind spot.
    #[test]
    fn the_host_rpc_list_is_the_protos_and_not_a_copy_of_it() {
        let proto = pinned_proto();
        let in_proto = proto_service_rpcs(&proto, "PluginHostService");
        let in_js = js_string_list(RPCSCAN_MJS, "export const HOST_RPCS = [");

        // Vacuity guards, both directions. A parse that stopped matching either
        // file's shape would otherwise compare two empty sets and pass.
        assert!(
            in_proto.len() >= 8,
            "only {} rpc(s) parsed out of PluginHostService — the proto parse has \
             stopped matching the file, so this test is checking nothing",
            in_proto.len()
        );
        assert!(
            in_js.len() >= 8,
            "only {} name(s) parsed out of HOST_RPCS — the JS parse has stopped \
             matching rpcscan.mjs, so this test is checking nothing",
            in_js.len()
        );

        let p = set(&in_proto);
        let j = set(&in_js);
        assert_eq!(p.len(), in_proto.len(), "PluginHostService declares a duplicate rpc name");
        assert_eq!(j.len(), in_js.len(), "HOST_RPCS lists a name twice");

        let unsearched: Vec<_> = p.difference(&j).cloned().collect();
        assert!(
            unsearched.is_empty(),
            "PluginHostService in proto/plugin.proto declares {unsearched:?}, which \
             bot/lib/rpcscan.mjs's HOST_RPCS does not list. `scanHostRpcs` only \
             searches a bundle for the names in that array, so this method is \
             never searched for at all: a plugin that calls it without declaring \
             the permission gets a clean scan, a green listing, and a permission \
             error at run time on the user's machine. Add it to HOST_RPCS, AND to \
             either RPC_RULES or ALWAYS_ALLOWED beside it — the next test says why \
             the array alone is not enough."
        );

        let stale: Vec<_> = j.difference(&p).cloned().collect();
        assert!(
            stale.is_empty(),
            "bot/lib/rpcscan.mjs's HOST_RPCS lists {stale:?}, which PluginHostService \
             in proto/plugin.proto does not declare. The scan would refuse a listing, \
             or tell an author to buy a permission, over a string that names no call \
             the daemon serves."
        );
    }

    /// Adding the name is half the edit, and the other half fails silently.
    ///
    /// `isDeclared` at `bot/lib/rpcscan.mjs:270` opens `const rule =
    /// RPC_RULES[rpc]; if (!rule) return true;` — an rpc in `HOST_RPCS` with no
    /// rule and no `ALWAYS_ALLOWED` entry is treated as *already declared* by
    /// every manifest, so the loop at `:297` skips it for every bundle for ever.
    /// It does not throw and it does not warn. So the eleventh host RPC can be
    /// added to `HOST_RPCS` — passing the test above — and still be searched for
    /// in no plugin ever submitted.
    ///
    /// The disjointness half is the same failure mirrored: `ALWAYS_ALLOWED` is
    /// consulted first, so a rule written for a name that is also always-allowed
    /// is dead while reading exactly like a live gate.
    #[test]
    fn every_host_rpc_is_either_always_allowed_or_carries_a_rule() {
        let host = js_string_list(RPCSCAN_MJS, "export const HOST_RPCS = [");
        let free = js_string_list(RPCSCAN_MJS, "const ALWAYS_ALLOWED = new Set([");
        let ruled = rpc_rules_keys(RPCSCAN_MJS);

        assert!(host.len() >= 8, "HOST_RPCS parse is checking nothing");
        assert!(free.len() >= 3, "ALWAYS_ALLOWED parse is checking nothing");
        assert!(ruled.len() >= 5, "RPC_RULES key parse is checking nothing");

        let (h, f, r) = (set(&host), set(&free), set(&ruled));

        let ungoverned: Vec<_> = h.difference(&f).filter(|n| !r.contains(*n)).cloned().collect();
        assert!(
            ungoverned.is_empty(),
            "bot/lib/rpcscan.mjs lists {ungoverned:?} in HOST_RPCS with neither an \
             ALWAYS_ALLOWED entry nor an RPC_RULES row. `isDeclared` returns true for \
             an rpc it has no rule for, so the scan treats it as declared by every \
             manifest and never reports it — the name is in the array and the check is \
             off. Give it a permission row, or put it in ALWAYS_ALLOWED if the daemon \
             gates it on nothing."
        );

        let both: Vec<_> = f.intersection(&r).cloned().collect();
        assert!(
            both.is_empty(),
            "{both:?} are in both ALWAYS_ALLOWED and RPC_RULES. ALWAYS_ALLOWED is \
             consulted first, so the rule never runs: it reads as a gate and is dead."
        );

        let orphan_rules: Vec<_> = r.difference(&h).cloned().collect();
        assert!(
            orphan_rules.is_empty(),
            "RPC_RULES has a row for {orphan_rules:?}, which is not in HOST_RPCS. \
             The loop only visits HOST_RPCS, so the row is unreachable — a permission \
             the bot appears to enforce and never looks for."
        );

        let orphan_free: Vec<_> = f.difference(&h).cloned().collect();
        assert!(
            orphan_free.is_empty(),
            "ALWAYS_ALLOWED names {orphan_free:?}, which is not in HOST_RPCS — \
             an exemption from a scan that was never going to look."
        );
    }

    /// The three counts `rpcscan.mjs` states in prose about its own literals.
    ///
    /// Its header opens *"ten methods, four of which every plugin may always
    /// call … and six of which act on the user's session"*, and the
    /// declaration's own doc comment says *"The ten methods"*. That sentence is
    /// what a maintainer reads before deciding whether the array is complete,
    /// which makes it the one sentence that must not outlive its truth: a
    /// literal that grew and a comment that still says `ten` tells the next
    /// reader the list is finished.
    #[test]
    fn rpcscan_mjs_prose_still_counts_the_literals_it_describes() {
        const WORDS: [&str; 21] = [
            "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
            "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
            "eighteen", "nineteen", "twenty",
        ];
        let word = |n: usize| -> &str {
            WORDS.get(n).copied().unwrap_or_else(|| {
                panic!("{n} is off the end of WORDS — extend it rather than dropping the check")
            })
        };

        let host = word(js_string_list(RPCSCAN_MJS, "export const HOST_RPCS = [").len());
        let free = word(js_string_list(RPCSCAN_MJS, "const ALWAYS_ALLOWED = new Set([").len());
        let ruled = word(rpc_rules_keys(RPCSCAN_MJS).len());

        for phrase in [
            format!("{host} methods, {free} of"),
            format!("and {ruled} of"),
            format!("names all {host}"),
            format!("The {host} methods of `PluginHostService`"),
        ] {
            assert!(
                RPCSCAN_MJS.contains(&phrase),
                "bot/lib/rpcscan.mjs no longer says {phrase:?} anywhere, so one of its \
                 own sentences is now counting a literal that has changed size. The \
                 array is the thing a reader trusts that comment about."
            );
        }
    }

    // ── the two registers of host-RPC gating, held to each other ────────────
    //
    // Two files say, for each `PluginHostService` method, which `[permissions]`
    // key and which `[capabilities]` key go with it:
    //
    //   * `RPC_RULES` and `ALWAYS_ALLOWED` in `bot/lib/rpcscan.mjs` — the pair
    //     the scan DECIDES with. `isDeclared` accepts a row's permission or its
    //     capability, either one;
    //   * the `PluginHostService` rows of `AstraPlugins/spec/hooks.yaml` — the
    //     register the three SDKs, the generated docs, and parity's R6 (which
    //     holds its `permission` column to the daemon's `HOST_RPC_PERMISSIONS`)
    //     are held to.
    //
    // Nothing compared them. Row by row they agreed on `permission` six of six
    // and on `capability` five of six, and the one that differs was found by a
    // person reading both for another reason: `SetVariable` carries the legacy
    // `capability: "actions"` here, and hooks.yaml files it under `core`, which
    // is that file's word for "no capability gates this", not a capability
    // name. The next row to disagree would have been found the same way, by
    // accident, because a disagreement has no symptom in either repository. A
    // declaration this scan accepts and the daemon does not honour is a clean
    // scan, a green listing and a permission denial on the user's machine; one
    // it demands and hooks.yaml does not is an author told to declare the wrong
    // key. Both files stay green on their own the whole time.
    //
    // hooks.yaml is read AT the pin, out of git objects, never off the
    // checkout's working tree — `bot/tests/risk-tiers.test.mjs` made the same
    // choice for the same reason. In CI `link-deps.sh --clone` leaves
    // `_deps/AstraPlugins` at the pin, but on a workstation it is a sibling
    // working copy on whatever branch somebody was last on, and a comparison
    // that answers differently on every machine is a comparison with a
    // floating branch.
    //
    // It is parsed by a port of `tools/parity/spec.py`, the dependency-free
    // reader AstraPlugins itself parses this file with. hooks.yaml declares
    // that subset in its own header — flat rows, no nesting, no multi-line
    // scalars — so that no reader needs a YAML library, and adding one to a
    // crate the ingest gate builds would buy a dependency to read a format
    // written so that nobody needs one. Anything outside the subset is
    // refused, not skipped, so a reshaped file is COULD NOT ASK rather than a
    // shorter list.

    /// Where the pin is written, and the only place (B-T1.4).
    const PIN_FILE: &str = include_str!("../astra-plugins.pin");

    /// The file, relative to the AstraPlugins root.
    const HOOKS_YAML: &str = "spec/hooks.yaml";

    /// Floors, measured at AstraPlugins `5291f29` on 2026-09-22 before any
    /// mutation: hooks.yaml has ten `PluginHostService` rows, six of them gated
    /// on a permission that is not `none`, and rpcscan.mjs governs ten rpcs —
    /// four in `ALWAYS_ALLOWED`, six in `RPC_RULES`. Floors, not equalities, so
    /// an eleventh host rpc is an ordinary upstream act; what they stop is a
    /// reader that parsed nothing on both sides and compared two empty maps.
    const FLOOR_HOST_ROWS: usize = 10;
    const FLOOR_GATED_HOST_ROWS: usize = 6;
    const FLOOR_RPCSCAN_ALWAYS: usize = 4;
    const FLOOR_RPCSCAN_RULES: usize = 6;

    /// A row on which the two registers are ALLOWED to disagree, and why.
    ///
    /// Not a tolerance: a decision somebody owes, pinned to the exact two
    /// values it excuses. When either side moves — including the day the
    /// decision is made and the two agree — the entry stops matching a
    /// difference and `every_named_exception_is_still_a_difference` goes red
    /// until the entry is deleted. So resolving it forces its removal, and the
    /// list cannot outlive its reason. It excuses one column of one row; a
    /// difference in any other column or row is red.
    struct Exception {
        rpc: &'static str,
        field: &'static str,
        rpcscan: &'static str,
        hooks_yaml: &'static str,
        why: &'static str,
    }

    const EXCEPTIONS: &[Exception] = &[Exception {
        rpc: "SetVariable",
        field: "capability",
        rpcscan: "actions",
        hooks_yaml: "core",
        why: "a policy call about legacy manifests, open and the owner's to make \
              (astra-plugins-ops couplings entry 32). `capability: \"actions\"` is the \
              arm for manifests written before `[permissions]` existed: a plugin that \
              declares `[capabilities] actions = true` — which every action plugin does \
              — and calls SetVariable passes this scan without `[permissions] \
              set_variable`. hooks.yaml gates SetVariable on `set_variable` and on no \
              capability, and the manifest crate's `[permissions]` is default-deny — its \
              own header: an absent section means no host rpc beyond Register, PluginLog \
              and GetPluginSelfConfig, and `[capabilities]` says what a plugin implements, \
              not what it may call out to — so by the crate's \
              account that plugin gets a clean scan here and a denial at run time. \
              Dropping the arm ends that, and starts failing legacy manifests the scan \
              has been passing. Neither cost is this file's to choose.",
    }];

    /// The comparison was not made. A failure, never a pass and never a skip:
    /// a cross-repository comparison that stepped aside quietly would close
    /// this gap on paper and nowhere else.
    fn could_not_ask(why: impl std::fmt::Display) -> ! {
        panic!(
            "COULD NOT ASK — bot/lib/rpcscan.mjs's host-RPC gates and AstraPlugins' \
             spec/hooks.yaml were NOT compared by this run. {why}"
        )
    }

    /// `ASTRA_PLUGINS_REF` from `astra-plugins.pin`: exactly one line, 40 hex.
    fn pinned_ref() -> String {
        let hits: Vec<&str> = PIN_FILE
            .lines()
            .filter_map(|l| l.strip_prefix("ASTRA_PLUGINS_REF="))
            .map(str::trim)
            .collect();
        match hits.as_slice() {
            [one] if one.len() == 40 && one.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) => {
                one.to_string()
            }
            [one] => could_not_ask(format!(
                "ASTRA_PLUGINS_REF in astra-plugins.pin is {one:?}, which is not a 40-hex commit"
            )),
            [] => could_not_ask(
                "astra-plugins.pin has no ASTRA_PLUGINS_REF line, and this reads hooks.yaml at the \
                 pin or not at all — master is a different question with a different answer",
            ),
            many => could_not_ask(format!(
                "astra-plugins.pin has {} ASTRA_PLUGINS_REF lines ({many:?}); the pin has to be one answer",
                many.len()
            )),
        }
    }

    fn git(dir: &std::path::Path, args: &[&str]) -> Result<String, String> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .map_err(|e| format!("could not run git: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        String::from_utf8(out.stdout).map_err(|e| format!("git printed non-UTF-8: {e}"))
    }

    /// `spec/hooks.yaml` at the pinned commit, and that commit.
    fn pinned_hooks_yaml() -> (String, String) {
        let pin = pinned_ref();
        let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let deps = here.join("_deps/AstraPlugins");
        let top = git(&deps, &["rev-parse", "--show-toplevel"]).unwrap_or_else(|e| {
            could_not_ask(format!(
                "{} is not an AstraPlugins checkout ({e}). Run `bot/manifest-probe/link-deps.sh` \
                 (with `--clone` and ASTRA_PLUGINS_REF set, as CI does).",
                deps.display()
            ))
        });
        // A `_deps/AstraPlugins` with no `.git` of its own resolves to THIS
        // repository, where the pinned commit does not exist. Said plainly,
        // because "unknown revision" would send the reader to AstraPlugins to
        // look for a commit that is sitting in front of them.
        if let Ok(ours) = git(here, &["rev-parse", "--show-toplevel"]) {
            if ours.trim() == top.trim() {
                could_not_ask(format!(
                    "{} resolves to this repository ({}), not to an AstraPlugins checkout",
                    deps.display(),
                    top.trim()
                ));
            }
        }
        if let Err(e) = git(&deps, &["cat-file", "-e", &format!("{pin}^{{commit}}")]) {
            could_not_ask(format!(
                "{} has no commit {pin} ({e}) — fetch it (`git -C {} fetch origin`), or the pin \
                 names a commit on no reachable ref",
                top.trim(),
                top.trim()
            ));
        }
        let text = git(&deps, &["cat-file", "-p", &format!("{pin}:{HOOKS_YAML}")]).unwrap_or_else(|e| {
            could_not_ask(format!(
                "{pin} has no {HOOKS_YAML} ({e}) — the file moved upstream, and this reader's path \
                 has to move with the pin"
            ))
        });
        (pin, text)
    }

    /// One flat row of `hooks:`.
    type Row = std::collections::BTreeMap<String, String>;

    /// One scalar of the subset, as `tools/parity/spec.py`'s `_scalar` reads it.
    /// Everything is kept as text; the columns compared here are all strings.
    fn hooks_scalar(raw: &str, n: usize) -> Result<String, String> {
        let raw = raw.trim();
        let b = raw.as_bytes();
        if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
            let body = &raw[1..raw.len() - 1];
            if body.contains(b[0] as char) {
                return Err(format!("line {n}: a nested quote inside a quoted scalar"));
            }
            return Ok(body.to_string());
        }
        if raw.contains('#') {
            return Err(format!("line {n}: `#` in a bare scalar is ambiguous — the subset says quote it"));
        }
        Ok(raw.to_string())
    }

    /// The `hooks:` rows of `spec/hooks.yaml`, by the file's declared subset.
    ///
    /// A line-for-line port of `parse` in AstraPlugins' `tools/parity/spec.py`,
    /// with the same refusals: an indented line outside `hooks:`, an item not
    /// indented two, a field not indented four, a field before the first `- `,
    /// a line with no `:`, a duplicate field in a row.
    fn parse_hooks_yaml(text: &str) -> Result<Vec<Row>, String> {
        let mut rows: Vec<Row> = Vec::new();
        let mut in_hooks = false;
        let mut current: Option<usize> = None;
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let stripped = line.trim();
            if stripped.is_empty() || stripped.starts_with('#') {
                continue;
            }
            let indent = line.len() - line.trim_start_matches(' ').len();
            if indent == 0 {
                current = None;
                in_hooks = stripped == "hooks:";
                if !in_hooks {
                    let (_, value) = stripped
                        .split_once(':')
                        .ok_or_else(|| format!("line {n}: expected `key: value`"))?;
                    hooks_scalar(value, n)?;
                }
                continue;
            }
            if !in_hooks {
                return Err(format!("line {n}: an indented line outside `hooks:`"));
            }
            let mut field = stripped;
            if let Some(rest) = stripped.strip_prefix("- ") {
                if indent != 2 {
                    return Err(format!("line {n}: a sequence item must be indented 2"));
                }
                rows.push(Row::new());
                current = Some(rows.len() - 1);
                field = rest.trim();
            } else if indent != 4 {
                return Err(format!("line {n}: a hook field must be indented 4"));
            }
            let at = current.ok_or_else(|| format!("line {n}: a field before the first `- `"))?;
            let (key, value) = field
                .split_once(':')
                .ok_or_else(|| format!("line {n}: expected `key: value`"))?;
            let key = key.trim().to_string();
            let value = hooks_scalar(value, n)?;
            if rows[at].insert(key.clone(), value).is_some() {
                return Err(format!("line {n}: duplicate field `{key}`"));
            }
        }
        Ok(rows)
    }

    /// What one register says gates one rpc. `none` is no permission and `core`
    /// no capability — hooks.yaml's two words, which rpcscan.mjs is read into.
    #[derive(Clone, Debug, PartialEq)]
    struct Gate {
        permission: String,
        capability: String,
    }

    type Gates = std::collections::BTreeMap<String, Gate>;

    /// Every `PluginHostService` row of hooks.yaml, as `rpc` → gate.
    ///
    /// `permission` and `capability` are required on a host row (spec.py
    /// enforces the first); a row without either is refused here rather than
    /// read as `none`, because reading an absent column as "ungated" is the
    /// permissive direction.
    fn hooks_yaml_host_gates(rows: &[Row]) -> Result<Gates, String> {
        let mut out = Gates::new();
        for row in rows.iter().filter(|r| r.get("service").map(String::as_str) == Some("PluginHostService")) {
            let rpc = row.get("rpc").ok_or("a PluginHostService row with no `rpc`")?;
            let column = |c: &str| {
                row.get(c)
                    .cloned()
                    .ok_or_else(|| format!("the PluginHostService row `{rpc}` has no `{c}`"))
            };
            let gate = Gate { permission: column("permission")?, capability: column("capability")? };
            if out.insert(rpc.clone(), gate).is_some() {
                return Err(format!("`{rpc}` has two PluginHostService rows"));
            }
        }
        Ok(out)
    }

    /// A double-quoted JS string literal's contents.
    fn js_quoted(v: &str) -> Option<String> {
        let v = v.trim();
        let body = v.strip_prefix('"')?.strip_suffix('"')?;
        (!body.contains('"')).then(|| body.to_string())
    }

    /// Every rpc rpcscan.mjs governs, as `rpc` → gate, and how many came from
    /// each literal.
    ///
    /// `ALWAYS_ALLOWED` reads as `none` / `core`. An `RPC_RULES` row with no
    /// `capability` — or `capability: null` — reads as `core`: `isDeclared`
    /// then has no capability arm for it, which is what hooks.yaml's `core`
    /// means, and what the scan's own hint text already handles. A row with no
    /// `permission` reads as a sentinel no hooks.yaml value can equal, because
    /// such a row is gated on a capability alone and hooks.yaml has no way to
    /// say that. Rows must be `Name: { key: value, … },` on one line, as all of
    /// them are; any other shape is refused rather than skipped, because a row
    /// this reader missed is a row nobody compared.
    fn rpcscan_gates(js: &str) -> Result<(Gates, usize, usize), String> {
        let mut out = Gates::new();
        let always = js_string_list(js, "const ALWAYS_ALLOWED = new Set([");
        for rpc in &always {
            let gate = Gate { permission: "none".into(), capability: "core".into() };
            if out.insert(rpc.clone(), gate).is_some() {
                return Err(format!("ALWAYS_ALLOWED lists `{rpc}` twice"));
            }
        }
        let body = js
            .split("export const RPC_RULES = {")
            .nth(1)
            .ok_or("`export const RPC_RULES = {` is not in bot/lib/rpcscan.mjs")?
            .split("\n};")
            .next()
            .ok_or("the RPC_RULES literal does not close with `};`")?;
        let mut rules = 0;
        for line in body.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            let shape = || {
                format!(
                    "RPC_RULES line {t:?} is not `Name: {{ key: value, … }},` on one line. The literal \
                     changed shape; teach this reader the new one rather than letting it skip the row"
                )
            };
            let (name, rest) = t.split_once(": {").ok_or_else(shape)?;
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(shape());
            }
            let inner = rest.strip_suffix(',').unwrap_or(rest).trim_end().strip_suffix('}').ok_or_else(shape)?;
            let mut fields = std::collections::BTreeMap::new();
            for pair in inner.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once(':').ok_or_else(shape)?;
                fields.insert(k.trim().to_string(), v.trim().to_string());
            }
            let quoted = |k: &str, v: &str| {
                js_quoted(v).ok_or_else(|| format!("RPC_RULES.{name}.{k} is {v}, not a double-quoted string"))
            };
            let permission = match fields.get("permission") {
                None => "<no permission arm>".to_string(),
                Some(v) => quoted("permission", v)?,
            };
            let capability = match fields.get("capability").map(String::as_str) {
                None | Some("null") | Some("undefined") => "core".to_string(),
                Some(v) => quoted("capability", v)?,
            };
            if out.insert(name.to_string(), Gate { permission, capability }).is_some() {
                return Err(format!("`{name}` is governed twice — ALWAYS_ALLOWED and RPC_RULES, or two rows"));
            }
            rules += 1;
        }
        Ok((out, always.len(), rules))
    }

    /// One column of one rpc on which the registers disagree.
    #[derive(Debug, PartialEq)]
    struct Difference {
        rpc: String,
        field: &'static str,
        rpcscan: String,
        hooks_yaml: String,
    }

    impl std::fmt::Display for Difference {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}: {} is {:?} in bot/lib/rpcscan.mjs and {:?} in spec/hooks.yaml",
                self.rpc, self.field, self.rpcscan, self.hooks_yaml
            )
        }
    }

    struct Comparison {
        only_rpcscan: Vec<String>,
        only_hooks_yaml: Vec<String>,
        compared: usize,
        differences: Vec<Difference>,
    }

    fn compare(ours: &Gates, theirs: &Gates) -> Comparison {
        let mut c = Comparison {
            only_rpcscan: ours.keys().filter(|k| !theirs.contains_key(*k)).cloned().collect(),
            only_hooks_yaml: theirs.keys().filter(|k| !ours.contains_key(*k)).cloned().collect(),
            compared: 0,
            differences: Vec::new(),
        };
        for (rpc, a) in ours {
            let Some(b) = theirs.get(rpc) else { continue };
            c.compared += 1;
            for (field, x, y) in [
                ("permission", &a.permission, &b.permission),
                ("capability", &a.capability, &b.capability),
            ] {
                if x != y {
                    c.differences.push(Difference {
                        rpc: rpc.clone(),
                        field,
                        rpcscan: x.clone(),
                        hooks_yaml: y.clone(),
                    });
                }
            }
        }
        c
    }

    fn excused(d: &Difference) -> bool {
        EXCEPTIONS.iter().any(|e| {
            e.rpc == d.rpc && e.field == d.field && e.rpcscan == d.rpcscan && e.hooks_yaml == d.hooks_yaml
        })
    }

    /// Both registers, parsed, with every floor asserted before anything is
    /// compared — so the tests below cannot pass over two empty maps.
    fn both_registers() -> (String, Gates, Gates) {
        let (pin, yaml) = pinned_hooks_yaml();
        let rows = parse_hooks_yaml(&yaml).unwrap_or_else(|e| {
            could_not_ask(format!("{HOOKS_YAML} at {pin} is outside the subset it declares: {e}"))
        });
        let theirs = hooks_yaml_host_gates(&rows)
            .unwrap_or_else(|e| could_not_ask(format!("{HOOKS_YAML} at {pin}: {e}")));
        let (ours, always, rules) =
            rpcscan_gates(RPCSCAN_MJS).unwrap_or_else(|e| could_not_ask(format!("bot/lib/rpcscan.mjs: {e}")));

        let gated = theirs.values().filter(|g| g.permission != "none").count();
        assert!(
            theirs.len() >= FLOOR_HOST_ROWS && gated >= FLOOR_GATED_HOST_ROWS,
            "BROKEN SCAN — {HOOKS_YAML} at {pin} parsed as {} PluginHostService row(s), {gated} gated on a \
             permission; there were {FLOOR_HOST_ROWS} and {FLOOR_GATED_HOST_ROWS} at 5291f29. Either host rpcs \
             were removed upstream or this reader has stopped finding rows.",
            theirs.len()
        );
        assert!(
            always >= FLOOR_RPCSCAN_ALWAYS && rules >= FLOOR_RPCSCAN_RULES,
            "BROKEN SCAN — bot/lib/rpcscan.mjs parsed as {always} ALWAYS_ALLOWED and {rules} RPC_RULES \
             row(s); there were {FLOOR_RPCSCAN_ALWAYS} and {FLOOR_RPCSCAN_RULES} on 2026-09-22"
        );
        (pin, ours, theirs)
    }

    /// An rpc one register governs and the other has never heard of is the
    /// same silence one level up: whichever side is missing it, nothing
    /// compares its gate with anything.
    #[test]
    fn the_two_gating_registers_name_the_same_host_rpcs() {
        let (pin, ours, theirs) = both_registers();
        let c = compare(&ours, &theirs);
        assert!(
            c.only_rpcscan.is_empty(),
            "bot/lib/rpcscan.mjs governs {:?}, which has no PluginHostService row in {HOOKS_YAML} at {pin}. \
             The scan is deciding a gate for an rpc the register the SDKs and the daemon's table are held to \
             does not describe — a row there, or a name out of ALWAYS_ALLOWED / RPC_RULES here.",
            c.only_rpcscan
        );
        assert!(
            c.only_hooks_yaml.is_empty(),
            "{HOOKS_YAML} at {pin} has PluginHostService row(s) for {:?}, which bot/lib/rpcscan.mjs neither \
             lists in ALWAYS_ALLOWED nor gives an RPC_RULES row. `isDeclared` treats an rpc with no rule as \
             declared by everybody, so the scan asks nothing about it. Give it the row hooks.yaml gives it.",
            c.only_hooks_yaml
        );
    }

    /// Every rpc both registers govern, compared on both columns, and nothing
    /// excused but the rows `EXCEPTIONS` names with their reasons.
    #[test]
    fn the_two_gating_registers_agree_on_every_row_but_the_named_exceptions() {
        let (pin, ours, theirs) = both_registers();
        let c = compare(&ours, &theirs);
        assert!(
            c.compared >= FLOOR_HOST_ROWS,
            "only {} rpc(s) are in both registers, and there were {FLOOR_HOST_ROWS} — the membership test \
             says which",
            c.compared
        );
        let unexplained: Vec<String> =
            c.differences.iter().filter(|d| !excused(d)).map(|d| format!("    {d}")).collect();
        assert!(
            unexplained.is_empty(),
            "REGISTERS DIFFER — bot/lib/rpcscan.mjs and {HOOKS_YAML} at {pin} disagree about what gates:\n{}\n  \
             `core` is hooks.yaml's word for no capability, and `none` for no permission. Decide which \
             register is right — hooks.yaml's `permission` column is the one parity R6 holds to the daemon's \
             HOST_RPC_PERMISSIONS — and change that side; if it is hooks.yaml, the pin moves in its own \
             commit first. Adding an EXCEPTIONS entry to silence this is a policy decision about what the scan \
             passes, and needs a reason somebody with that authority wrote.",
            unexplained.join("\n")
        );
    }

    /// An exception that no longer excuses anything is a decision that was
    /// made, or a disagreement that changed shape — and either way the entry
    /// now reads as a reason for something that is not happening.
    #[test]
    fn every_named_exception_is_still_a_difference() {
        let (pin, ours, theirs) = both_registers();
        let stale = stale_exceptions(&compare(&ours, &theirs), &pin);
        assert!(stale.is_empty(), "{}", stale.join("\n"));
    }

    /// Every `EXCEPTIONS` entry that no longer excuses exactly the difference
    /// it names, as the sentence that says so. Empty is the only pass.
    fn stale_exceptions(c: &Comparison, pin: &str) -> Vec<String> {
        let mut out = Vec::new();
        for e in EXCEPTIONS {
            if !matches!(e.field, "permission" | "capability") || e.why.trim().is_empty() {
                out.push(format!(
                    "the EXCEPTIONS entry for {} names column {:?} or gives no reason; an exception is one \
                     column of one row, with its reason written down",
                    e.rpc, e.field
                ));
                continue;
            }
            match c.differences.iter().find(|d| d.rpc == e.rpc && d.field == e.field) {
                None => out.push(format!(
                    "STALE EXCEPTION — {rpc}'s {field} no longer differs between bot/lib/rpcscan.mjs and \
                     {HOOKS_YAML} at {pin}; EXCEPTIONS still excuses {a:?} against {b:?}. Whatever was being \
                     waited on has been decided. In the same commit, delete the entry, the sentence in \
                     rpcscan.mjs's RPC_RULES comment that points at it, and the rows of \
                     the_comparison_goes_red_on_the_committed_registers_mutated that edit that exception's \
                     literal (their anchor no longer exists, so that test is red too) — an exception that \
                     outlives its difference will excuse the next one that happens to take its place.",
                    rpc = e.rpc,
                    field = e.field,
                    a = e.rpcscan,
                    b = e.hooks_yaml,
                )),
                Some(d) if !excused(d) => out.push(format!(
                    "STALE EXCEPTION — EXCEPTIONS excuses {rpc}'s {field} as {a:?} against {b:?}, and the \
                     difference is now {d}. That is a different disagreement, and the reason written for the \
                     first does not cover it.",
                    rpc = e.rpc,
                    field = e.field,
                    a = e.rpcscan,
                    b = e.hooks_yaml,
                )),
                Some(_) => {}
            }
        }
        out
    }

    /// The three comparisons above, watched going red on the committed
    /// material itself, so the proof is re-run on every `cargo test` rather
    /// than recorded once in a commit message. Each edit is anchored and must
    /// match exactly once, or this test fails before it proves anything.
    #[test]
    fn the_comparison_goes_red_on_the_committed_registers_mutated() {
        let (_, yaml) = pinned_hooks_yaml();
        let once = |text: &str, from: &str, to: &str| -> String {
            assert_eq!(text.matches(from).count(), 1, "mutation anchor {from:?} must occur exactly once");
            let out = text.replacen(from, to, 1);
            assert_ne!(out, text, "mutation {from:?} changed nothing");
            out
        };
        let run = |js: &str, yaml: &str| {
            let rows = parse_hooks_yaml(yaml).expect("a mutated hooks.yaml still parses");
            let theirs = hooks_yaml_host_gates(&rows).expect("host rows");
            let (ours, _, _) = rpcscan_gates(js).expect("rpcscan.mjs");
            compare(&ours, &theirs)
        };
        let unexplained = |c: &Comparison| -> Vec<String> {
            c.differences.iter().filter(|d| !excused(d)).map(|d| d.rpc.clone()).collect()
        };

        // The committed pair: nothing unexplained, nothing missing, the one
        // exception live. Without this the rows below prove nothing.
        let base = run(RPCSCAN_MJS, &yaml);
        assert!(base.only_rpcscan.is_empty() && base.only_hooks_yaml.is_empty());
        assert_eq!(unexplained(&base), Vec::<String>::new());
        assert!(base.differences.iter().any(excused));

        // Another row's permission, flipped on each side in turn.
        let js = once(RPCSCAN_MJS, "permission: \"fire_trigger\"", "permission: \"push_to_ui\"");
        assert_eq!(unexplained(&run(&js, &yaml)), vec!["FireTrigger"]);
        let y = once(&yaml, "    permission: fire_trigger\n", "    permission: push_to_ui\n");
        assert_eq!(unexplained(&run(RPCSCAN_MJS, &y)), vec!["FireTrigger"]);

        // Another row's capability, on the other column.
        let js = once(RPCSCAN_MJS, "capability: \"event_handlers\"", "capability: \"client\"");
        assert_eq!(unexplained(&run(&js, &yaml)), vec!["SubscribeEvents"]);

        // An rpc on one side only, each side in turn.
        let js = once(
            RPCSCAN_MJS,
            "export const RPC_RULES = {\n",
            "export const RPC_RULES = {\n  GetWidget: { permission: \"push_to_ui\", blocking: false },\n",
        );
        assert_eq!(run(&js, &yaml).only_rpcscan, vec!["GetWidget"]);
        let y = once(
            &yaml,
            "\nhooks:\n",
            "\nhooks:\n  - rpc: GetWidget\n    service: PluginHostService\n    capability: core\n    permission: none\n",
        );
        assert_eq!(run(RPCSCAN_MJS, &y).only_hooks_yaml, vec!["GetWidget"]);

        // The owner decides, and SetVariable agrees: the exception now
        // excuses nothing. Both spellings of "no capability arm" count.
        // These rows and the next edit the exception's own literal, so they
        // are deleted with it; `every_named_exception_is_still_a_difference`
        // says so when that day comes.
        const SET_VARIABLE_ROW: &str = "SetVariable: { permission: \"set_variable\", capability: \"actions\",";
        assert!(stale_exceptions(&base, "test").is_empty());
        for to in ["", " capability: null,"] {
            let js = once(
                RPCSCAN_MJS,
                SET_VARIABLE_ROW,
                &format!("SetVariable: {{ permission: \"set_variable\",{to}"),
            );
            let c = run(&js, &yaml);
            assert_eq!(unexplained(&c), Vec::<String>::new());
            let stale = stale_exceptions(&c, "test");
            assert!(
                stale.len() == 1 && stale[0].starts_with("STALE EXCEPTION — SetVariable's capability"),
                "{stale:?}"
            );
        }
        // The same decision taken on the other side: hooks.yaml files it
        // under `actions`. Anchored on the row, since `capability: core` is
        // five rows' value.
        let y = once(
            &yaml,
            "  - rpc: SetVariable\n    service: PluginHostService\n    direction: \"plugin->daemon\"\n    capability: core\n",
            "  - rpc: SetVariable\n    service: PluginHostService\n    direction: \"plugin->daemon\"\n    capability: actions\n",
        );
        assert_eq!(stale_exceptions(&run(RPCSCAN_MJS, &y), "test").len(), 1);

        // And the exception is exact: SetVariable's capability moving to
        // another wrong value is a new difference the old reason does not cover.
        let js = once(
            RPCSCAN_MJS,
            SET_VARIABLE_ROW,
            "SetVariable: { permission: \"set_variable\", capability: \"triggers\",",
        );
        let c = run(&js, &yaml);
        assert_eq!(unexplained(&c), vec!["SetVariable"]);
        assert_eq!(stale_exceptions(&c, "test").len(), 1);

        // The subset parser refuses rather than skips.
        assert!(parse_hooks_yaml("hooks:\n  - rpc: A\n      service: B\n").is_err());
        assert!(parse_hooks_yaml("hooks:\n  - rpc: A # comment\n").is_err());
        assert!(parse_hooks_yaml("hooks:\n  - rpc: A\n    rpc: B\n").is_err());
    }

    /// The response is the bot's whole view of the manifest. If it stops being
    /// serializable the bot sees nothing at all, so the shape is asserted rather
    /// than trusted.
    #[test]
    fn the_response_round_trips_as_json() {
        let out = probe(&req(GOOD));
        let text = serde_json::to_string(&out).expect("serializable");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema"], RESULT_SCHEMA);
        assert_eq!(v["ok"], true);
        assert_eq!(v["manifest"]["id"], "dice-roller");
        assert!(v["known_capabilities"].as_array().unwrap().contains(&"dom_access".into()));
    }
}
