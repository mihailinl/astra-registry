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
