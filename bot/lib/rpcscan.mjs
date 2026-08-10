// Does the bundle call host RPCs it did not declare?
//
// `PluginHostService` is the plugin→daemon direction: ten methods, three of
// which every plugin may always call (`Register`, `PluginLog`,
// `GetPluginSelfConfig`) and seven of which act on the user's session. The
// manifest says which of those a plugin is for. This looks in the shipped files
// for the names of the others.
//
// ── say plainly what this is ────────────────────────────────────────────────
//
// **It is a string search. It catches accidents, not a determined attacker.**
// Anyone who does not want to be caught splits the literal in two, base64s it,
// or builds it from bytes at runtime, and this finds nothing. It is here
// because the failure it actually catches is common and boring: an author
// copies a snippet, calls `fire_trigger`, ships a manifest that never declared
// `triggers`, and the plugin fails at runtime on the user's machine with a
// permission error nobody can debug from the store page. docs/BOT-CHECKS.md and
// POLICY.md must not describe it as anything more than that.
//
// ── the scope problem, which is the whole design ────────────────────────────
//
// A naive scan of every file in the bundle rejects every plugin ever written,
// for two reasons that have nothing to do with the author:
//
//   * The Python SDK ships `plugin_pb2.py`, whose serialized descriptor
//     contains the name of every method of every service in the proto. It is a
//     source file by extension and it names all ten.
//   * A Rust or Go plugin links a generated client whose stubs carry the
//     gRPC path string for each method whether or not the author calls it.
//     Whether the linker drops the unused ones is a build-configuration detail,
//     which is not a thing to hang a rejection on.
//
// So the scan classifies each file and grades the evidence:
//
//   AUTHOR SOURCE      a text file that is not vendored and not generated.
//                      A hit here is what the check is for -> block on the four
//                      high-risk methods, warn on the rest.
//   VENDORED/GENERATED site-packages, node_modules, *_pb2.py, *.pb.go, dist/…
//                      Skipped entirely. Its contents are the SDK's, not the
//                      author's.
//   OPAQUE             anything that does not decode as text. Reported as a
//                      warning with the reason it is not evidence, never as a
//                      block.
//
// The note row `N_HOST_RPC_SCAN_SCOPE` is printed on every run so nobody reads
// a clean scan as "this plugin makes no undeclared calls".

/** The ten methods of `PluginHostService`, from `proto/plugin.proto`. */
export const HOST_RPCS = [
  "Register",
  "SubscribeEvents",
  "SendChatMessage",
  "FireTrigger",
  "GetPluginSelfConfig",
  "PluginLog",
  "GetDaemonInfo",
  "SetVariable",
  "SetThemeContribution",
  "PushToUi",
];

/**
 * Callable by anything, with no declaration: `EXEMPT_PATHS` in the daemon's
 * auth interceptor contains `Register`, and the other two are how a plugin
 * reports and configures itself. Scanning for them would flag every plugin.
 */
const ALWAYS_ALLOWED = new Set(["Register", "PluginLog", "GetPluginSelfConfig"]);

/**
 * Which declaration makes each call legitimate.
 *
 * `permission` is the `[permissions]` key PRODUCTION_PLAN §5.6 introduces and
 * Phase 4 enforces; `capability` is what the manifest can say **today**, before
 * that section exists. Both are accepted, so this check does not have to be
 * rewritten when `[permissions]` lands and does not reject every current plugin
 * in the meantime.
 *
 * `blocking` is the plan's list, verbatim: these four act outside the plugin —
 * they fire the user's automations, speak as the user in their chat, write the
 * daemon's variables, and restyle the whole application.
 */
export const RPC_RULES = {
  FireTrigger: { permission: "fire_trigger", capability: "triggers", blocking: true },
  SendChatMessage: { permission: "send_chat_message", capability: "client", blocking: true },
  SetVariable: { permission: "set_variable", capability: "actions", blocking: true },
  SetThemeContribution: { permission: "set_theme_contribution", capability: "ui_contributions", blocking: true },
  PushToUi: { permission: "push_to_ui", capability: "ui_contributions", blocking: false },
  SubscribeEvents: { permission: "subscribe_events", capability: "event_handlers", blocking: false },
  GetDaemonInfo: { permission: "get_daemon_info", capability: null, blocking: false },
};

// ── what "vendored" is allowed to mean ──────────────────────────────────────
//
// A skip is a hole: the file is never searched at all. So the question for every
// pattern below is not "does this usually hold somebody else's code" but "could
// a bundle author adopt this for free". Three tiers, and the middle one is the
// fix:
//
//   1. **Names a toolchain writes.** `plugin_pb2.py`, `foo.pb.go`, `foo_pb.d.ts`,
//      `*.proto`, `*.dist-info/`. An author can name a file `evil_pb2.py`, but
//      the name is then a lie about a specific generator rather than a directory
//      convention, and the file still has to *be* somewhere. Skipped outright.
//   2. **Conventional directories.** `node_modules/`, `site-packages/`,
//      `.venv/`, `lib/pythonX.Y/`. These are chosen by a package manager in
//      honest bundles and by the author in dishonest ones, so they are skipped
//      only when something ELSE in the bundle corroborates the claim — a
//      `package.json` under the same root, a `.dist-info/` or `.egg-info/`
//      directory, a `METADATA`/`RECORD`. A lone `node_modules/evil.js` with no
//      package metadata anywhere is searched.
//   3. **`generated/` and `vendor/`.** Nothing corroborates these — they are
//      bare directory names with no manifest, no metadata and no convention a
//      tool enforces. They used to be silent skips, which meant that renaming
//      one directory turned the whole check off: the identical file at
//      `src/evil.py` produced `E_HOST_RPC_UNDECLARED` and at `generated/evil.py`
//      produced nothing, and the note row reported it as somebody else's code.
//      They are now **searched**, and a hit inside one is reported at `warn`
//      rather than `error` so a genuinely generated tree does not block a
//      release.
//
// And whatever is skipped is NAMED in `N_HOST_RPC_SCAN_SCOPE`, not just counted,
// so a reviewer can see when a plugin's whole source tree lives under one
// skipped directory.

/** Tier 1: the name is the evidence. */
const GENERATED_NAMES = [
  /_pb2(_grpc)?\.pyi?$/,
  /\.pb\.(go|cc|h|js|ts)$/,
  /_pb\.d\.ts$/,
  /\.proto$/,
  /(^|\/)[^/]*\.dist-info\//,
  /(^|\/)dist-info\//,
];

/** Tier 2: a package manager's directory, believed only when corroborated. */
const VENDOR_DIR_RE = /^(.*?)(node_modules|site-packages|\.venv|lib\/python[0-9.]+)\/(.*)$/;

/** Tier 3: bare directory names an author picks. Searched, and reported softly. */
const WEAK_VENDOR_DIRS = [/(^|\/)generated\//, /(^|\/)vendor\//];

/**
 * Which `node_modules/`-style roots in this bundle are backed by evidence.
 *
 * @param {{name: string}[]} files
 * @returns {Set<string>} root prefixes, each ending in `/`
 */
export function corroboratedVendorRoots(files) {
  const roots = new Map();
  for (const f of files) {
    const m = String(f.name).match(VENDOR_DIR_RE);
    if (!m) continue;
    const root = `${m[1]}${m[2]}/`;
    if (!roots.has(root)) roots.set(root, false);
    const rest = m[3];
    const evidence =
      /(^|\/)package\.json$/.test(rest) ||
      /\.dist-info\//.test(rest) ||
      /\.egg-info\//.test(rest) ||
      /(^|\/)(METADATA|RECORD|WHEEL|pyvenv\.cfg)$/.test(rest) ||
      /_pb2(_grpc)?\.pyi?$/.test(rest);
    if (evidence) roots.set(root, true);
  }
  return new Set([...roots].filter(([, ok]) => ok).map(([root]) => root));
}

const TEXT_EXTENSIONS = new Set([
  "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "rs", "go", "rb", "lua", "sh",
  "toml", "json", "yaml", "yml", "txt", "md", "cfg", "ini",
]);

/**
 * @param {string} name
 * @param {Buffer} bytes
 * @param {{vendorRoots?: Set<string>|null}} [opts] corroborated vendor roots, from
 *   [`corroboratedVendorRoots`]. Omitted (or `null`) means "no bundle to check
 *   against", and a conventional directory is then taken at face value — the
 *   single-file callers are documentation and tests, not the gate.
 * @returns {"vendored"|"weak-vendor"|"source"|"opaque"}
 */
export function classifyFile(name, bytes, opts = {}) {
  if (GENERATED_NAMES.some((re) => re.test(name))) return "vendored";
  const vendorMatch = String(name).match(VENDOR_DIR_RE);
  if (vendorMatch) {
    const root = `${vendorMatch[1]}${vendorMatch[2]}/`;
    const roots = opts.vendorRoots ?? null;
    if (roots === null || roots.has(root)) return "vendored";
    // A conventional directory nothing corroborates. Searched like source.
  }
  if (WEAK_VENDOR_DIRS.some((re) => re.test(name))) return "weak-vendor";
  const ext = name.includes(".") ? name.split(".").pop().toLowerCase() : "";
  if (TEXT_EXTENSIONS.has(ext)) return "source";
  // No extension, or an unknown one. Sniff: a NUL in the first 8 KiB is the
  // usual "this is a binary" test and it is good enough to keep an ELF out of
  // the source bucket.
  const head = bytes.subarray(0, 8192);
  if (head.includes(0)) return "opaque";
  // Text with an unfamiliar extension is still text somebody wrote.
  return "source";
}

/**
 * @param {{name: string, bytes: Buffer}[]} files every entry of the bundle except MANIFEST.json
 * @param {{capabilities: string[], permissions: object}} declared
 * @returns {{level: string, code: string, message: string}[]}
 */
export function scanHostRpcs(files, declared) {
  const capabilities = new Set(declared.capabilities ?? []);
  const permissions = new Set(Object.keys(declared.permissions ?? {}));
  const findings = [];

  const isDeclared = (rpc) => {
    const rule = RPC_RULES[rpc];
    if (!rule) return true;
    if (rule.permission && permissions.has(rule.permission)) return true;
    if (rule.capability && capabilities.has(rule.capability)) return true;
    return false;
  };

  // rpc -> { source: [paths], opaque: [paths], weak: [paths] }
  const hits = new Map();
  const vendorRoots = corroboratedVendorRoots(files);
  const skippedPaths = [];
  let scanned = 0;
  let opaque = 0;

  for (const f of files) {
    const kind = classifyFile(f.name, f.bytes, { vendorRoots });
    if (kind === "vendored") {
      skippedPaths.push(f.name);
      continue;
    }
    if (kind === "opaque") opaque++;
    else scanned++;

    // latin1 so a byte sequence inside a binary is still searchable, and so an
    // invalid UTF-8 sequence cannot make a whole file unsearchable.
    const text = f.bytes.toString("latin1");
    for (const rpc of HOST_RPCS) {
      if (ALWAYS_ALLOWED.has(rpc)) continue;
      if (isDeclared(rpc)) continue;
      // Both spellings the wire and the SDKs use: the method name as it appears
      // in generated clients, and the snake_case wrapper every SDK exposes.
      const snake = rpc.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
      if (!text.includes(rpc) && !text.includes(snake)) continue;
      if (!hits.has(rpc)) hits.set(rpc, { source: [], opaque: [], weak: [] });
      const bucket = kind === "opaque" ? "opaque" : kind === "weak-vendor" ? "weak" : "source";
      hits.get(rpc)[bucket].push(f.name);
    }
  }

  for (const [rpc, where] of [...hits.entries()].sort()) {
    const rule = RPC_RULES[rpc];
    const needs = rule.capability
      ? `\`[capabilities] ${rule.capability} = true\` (or \`[permissions] ${rule.permission}\` once that section exists)`
      : `\`[permissions] ${rule.permission}\``;
    if (where.source.length) {
      findings.push({
        level: rule.blocking ? "error" : "warn",
        code: rule.blocking ? "E_HOST_RPC_UNDECLARED" : "W_HOST_RPC_UNDECLARED",
        message:
          `${where.source.slice(0, 3).join(", ")}${where.source.length > 3 ? ` (+${where.source.length - 3} more)` : ""} ` +
          `names \`${rpc}\`, which the manifest does not declare. Add ${needs}, or remove the call.`,
      });
    }
    if (where.weak.length) {
      // **`review` for the four that act outside the plugin, `warn` for the
      // rest.** A silent skip meant renaming one directory turned the check off
      // entirely; downgrading it to a `warn` would leave the same bypass in
      // place, because `warn` does not hold anything — `bot/lib/policy.mjs`
      // holds on `review` and publishes through everything softer. So a
      // blocking RPC named inside a directory the author chose the name of is a
      // question for a person, not an outright rejection: `generated/` really
      // does hold generated code in honest bundles.
      findings.push({
        level: rule.blocking ? "review" : "warn",
        code: rule.blocking ? "R_HOST_RPC_IN_VENDOR_DIR" : "W_HOST_RPC_IN_VENDOR_DIR",
        message:
          `${where.weak.slice(0, 3).join(", ")}${where.weak.length > 3 ? ` (+${where.weak.length - 3} more)` : ""} ` +
          `names \`${rpc}\`, which the manifest does not declare. The path says "generated" or ` +
          `"vendor" — a directory name the bundle author chooses, not one a toolchain enforces — so ` +
          `this is a question rather than a rejection. If the code is yours, add ${needs} or remove ` +
          `the call.`,
      });
    }
    if (where.opaque.length) {
      findings.push({
        level: "warn",
        code: "W_HOST_RPC_IN_OPAQUE_FILE",
        message:
          `${where.opaque.slice(0, 3).join(", ")} contains the string \`${rpc}\`. Compiled files are ` +
          "not evidence of a call — a linked SDK client carries the name of every method on the " +
          "service — so this is recorded, not held against you.",
      });
    }
  }

  // The skipped paths are NAMED, not counted. A count of "14 vendored files
  // skipped" reads as somebody else's code no matter what those files are; the
  // list is what lets a reviewer notice that the whole plugin lives under one of
  // them.
  const shown = skippedPaths.slice(0, 8).join(", ");
  const more = skippedPaths.length > 8 ? ` (+${skippedPaths.length - 8} more)` : "";
  findings.push({
    level: "note",
    code: "N_HOST_RPC_SCAN_SCOPE",
    message:
      `${scanned} source file(s) searched, ${opaque} compiled file(s) noted, ` +
      `${skippedPaths.length} generated file(s) skipped${skippedPaths.length ? `: ${shown}${more}` : ""}. ` +
      "A string search cannot see a call assembled at runtime.",
  });

  return findings;
}
