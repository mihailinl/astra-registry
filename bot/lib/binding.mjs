// The binding line: `astra-binding: <token>` in a stranger's file.
//
// Registry plan B-T2.4. ID-22 says WHERE to read it, ID-23 says what counts as
// a line, ID-24 says what a near-miss costs. Everything below is either one of
// those three rules or the plumbing that gets the bytes to them.
//
// ── this module's whole job is to stop a string being a string ─────────────
//
// `.well-known/astra-plugin-owner` belongs to somebody else. So does the
// repository it sits in, the commit it is read at, and the tag that produced
// the commit. Every branch here is reading adversarial input, and the only two
// things that may come out the far end are **a token that matched the grammar
// exactly** or **a refusal with a code**. There is no third answer, and in
// particular there is no "probably meant this".
//
// Three consequences, each of which is a decision and not an accident:
//
//   * **The window is measured in BYTES.** Not characters, not UTF-16 code
//     units. `bot/lib/ownership.mjs:283` slices `text.slice(0, 4096)` on a
//     decoded string to find logins, which is 4096 UTF-16 units — and 1400
//     three-byte characters are 4200 bytes and 1400 units, so a line the byte
//     rule puts outside the window the unit rule puts inside it. Vector 15 of
//     `tests/binding-line/` is that file, and it is the one mutation this
//     module is most likely to suffer, because the convenient thing to write
//     in JavaScript is the wrong one.
//
//   * **The grammar is matched over bytes, through latin-1.** Every character
//     ID-23 names is ASCII, and latin-1 maps each byte to exactly one code
//     unit, so `[A-Za-z0-9_-]` over a latin-1 string is `[A-Za-z0-9_-]` over
//     the bytes with nothing in between. Decoding UTF-8 first would be wrong
//     twice: a file that is not valid UTF-8 would have its bad bytes replaced
//     by U+FFFD — three bytes where one stood — which moves every later byte
//     rightwards and can push a line out of a window it was inside; and it
//     invites a reader to normalise, which is how `astra-binding` and a
//     lookalike become the same line.
//
//   * **Nothing a stranger wrote is echoed back.** A refusal says which rule
//     failed and on which line number; it never quotes the line. The token is
//     public by DEC-2 and is the one exception, and it is quoted only after it
//     has matched `[A-Za-z0-9_-]{16,128}`, which is the same discipline
//     `bot/lib/ownership.mjs` applies to a login before it reaches a comment.
//
// ── what this module does NOT decide ──────────────────────────────────────
//
// **It never answers `B_UNBOUND`.** "No line here" and "this listing needed
// one" are different questions, and the second belongs to `listing-state.mjs`
// (M-T5.1) via ID-25, which is keyed on the deadline, on `log/cutover.json`
// and on whether the listing ever had an identity record. A parser that
// returned `B_UNBOUND` would be a second answer to "is this listing bound",
// and a second answer to that is a second identity system.
//
// It also never asks the plugins service anything. Whether the token is
// `bound`, whether its account is eligible, and whether the minted-for id
// matches `.15` are the verdict's (B-T3.1), and `B_BINDING_UNUSABLE` is the
// one public code for every way that can fail (ID-9). This module hands the
// verdict a token or a refusal; it does not form an opinion about the account.
//
// ── the read, and the one thing a 404 must not mean ───────────────────────
//
// ID-22 reads at the ATTESTED commit, by repository id, never by name, never
// `target_commitish`, never the default branch. Deleting the line from `main`
// ends nothing (B.3) — which also means the read cannot be a name lookup that
// a rename would send somewhere else.
//
// The two steps are ordered and the order is the rule. `GET
// /repositories/{id}/contents/...?ref={sha}` answers 404 both when the FILE is
// absent and when the COMMIT is not in that repository, and those lead to
// opposite places: the first is "this release has no binding line", which is a
// fact about the author, and the second is "the certificate names a commit
// this repository does not have", which is a fact about the attestation and
// pages an operator. So `commitInRepository` runs first and its own 404 is a
// wait with an alert, never an absence. Step 2's 404 means "no line" only
// because step 1 already said the commit is there.

import { commitInRepository, fileAtCommit } from "./github.mjs";
import { OWNER_FILE } from "./ownership.mjs";

export { OWNER_FILE };

/**
 * ID-23's window, in BYTES of the file as delivered.
 *
 * A BOM at the start of the file is ignored as content and still occupies the
 * first three of these bytes: the window is what was READ, and a byte that
 * was read is a byte that counts. That reading is `MBE-PENDING` Q1 — the
 * contract states the number and not the unit's edge cases — and vectors 11
 * to 15 are what a contract PATCH or a minice-be agreement would be agreeing
 * to.
 */
export const WINDOW_BYTES = 4096;

/**
 * ID-23, verbatim, as the contract writes it.
 *
 * Kept as a SOURCE string rather than only as a `RegExp` so that three copies
 * — this one, `tests/binding-line/generate.mjs`'s and the corpus's own
 * `grammar` member — can be compared by `bot/tests/binding.test.mjs`. The
 * contract is in another repository and CI has no checkout of it, so a literal
 * pinned in three places that are compared is the strongest available form of
 * "this is still what §2.3 says".
 *
 * `$` is end-of-string here and not "before a final newline", because the
 * splitter below has already removed every `\n`; a line can never contain one.
 * Every quantifier is bounded — `{16,128}` and single `*`s over disjoint
 * character classes — so a 4 KiB line of token characters costs a 4 KiB scan
 * and not a backtracking explosion.
 */
export const ID_23_SOURCE = "^[ \\t]*astra-binding:[ \\t]*([A-Za-z0-9_-]{16,128})[ \\t]*(#.*)?$";

/**
 * ID-24's near-miss prefix, case-insensitive.
 *
 * Wider than ID-23 in exactly two ways — any case, and `[ \t]*` before the
 * colon — and that width is the point: `Astra-Binding:` and `astra-binding :`
 * are lines somebody MEANT as a binding, and a reader that silently ignored
 * them would let a typo read as "this repository was never bound".
 *
 * The colon is required, which is what keeps a bare `astra-binding` a login.
 * That is not a nicety: `astra-binding` matches GitHub's login charset, the
 * owner file has held one login per line since before a token existed, and
 * `bot/lib/ownership.mjs:224` is the reader that would break.
 */
export const ID_24_PREFIX_SOURCE = "^[ \\t]*astra-binding[ \\t]*:";

/**
 * FLOW-50's MINTED grammar — the CLI's, mirrored here and owned there.
 *
 * `astra-plugin-cli`'s `init-ci --binding` refuses anything outside
 * `[A-Za-z0-9_-]{22,128}`, while this reader recognises `{16,128}` (ID-23).
 * The asymmetry is deliberate: the registry must go on recognising a line that
 * an older CLI, or a person, wrote by hand, and the CLI must not mint anything
 * a 128-bit CSPRNG would not produce.
 *
 * It is here — a second copy of another repository's rule — for one reason:
 * `tests/binding-line/vectors.json` carries a `cli_write` column, and a column
 * no program computes is a column somebody typed. The CLI asserts its writer
 * against the same column from the other side (AP-8), so the two copies are
 * joined by the corpus rather than by hope. `dev/couplings.md` carries the row.
 */
export const CLI_WRITE_SOURCE = "^[A-Za-z0-9_-]{22,128}$";

const ID_23_RE = new RegExp(ID_23_SOURCE);
const ID_24_PREFIX_RE = new RegExp(ID_24_PREFIX_SOURCE, "i");
const CLI_WRITE_RE = new RegExp(CLI_WRITE_SOURCE);

/**
 * The vocabulary this module answers in.
 *
 * CONTRACT codes (ID-24, and B.7's wait), declared here the way
 * `bot/lib/identity.mjs` declares `IDENTITY_CODES` and for the same reason:
 * the author-facing text for the bound world is written once, by reg.61a
 * (B-T3.3b), and a placeholder sentence here would be a second one.
 *
 * Both names are also declared in `bot/lib/policy/constants.mjs`'s
 * `BOUND_WORLD_CODES`, with the levels `error` and `wait`.
 * `bot/tests/binding.test.mjs` asks `policyCodeDef` about every name here, so
 * a code renamed on one side is red rather than silently undeclared — which
 * matters because an undeclared code does not throw, it falls through to
 * `level: "error"` with the title "undeclared policy code …".
 */
export const BINDING_CODES = Object.freeze({
  /** ID-24: more than one line, or a near miss that failed ID-23. */
  B_BINDING_MALFORMED: "B_BINDING_MALFORMED",
  /** A read that did not happen. Never absence, never a difference. */
  W_GITHUB_RATE_LIMITED: "W_GITHUB_RATE_LIMITED",
});

/** The three answers a file can give. `B_UNBOUND` is not one of them. */
export const OUTCOMES = Object.freeze(["none", "one", "malformed"]);

/** Would the CLI write this token? FLOW-50, mirrored — see `CLI_WRITE_SOURCE`. */
export function wouldCliWrite(token) {
  return typeof token === "string" && CLI_WRITE_RE.test(token);
}

/**
 * Whatever the caller has, as bytes.
 *
 * A `Uint8Array` or `Buffer` passes straight through, which is the path that
 * is actually correct. A **string** is encoded as UTF-8 and the result is
 * documented as lossy where it is lossy: by the time a transport has handed
 * over a decoded string, any byte that was not valid UTF-8 has already become
 * U+FFFD, and re-encoding it produces three bytes where one stood. That
 * shifts every later byte rightwards and can move a line out of the window it
 * was inside. It cannot move one IN — U+FFFD is never shorter than what it
 * replaced — so the string path errs towards `none`, which is the safe
 * direction, and `readBindingLine` says so at the call site.
 */
function toBytes(input) {
  if (input == null) return new Uint8Array(0);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (typeof input === "string") return new TextEncoder().encode(input);
  throw new TypeError(`a binding file is bytes or a string, not ${typeof input}`);
}

/** Byte-to-code-unit, one for one. No decoding, no normalisation, no throw. */
function latin1(view) {
  let s = "";
  // Chunked so a 4 KiB line does not become a 4096-argument spread.
  for (let i = 0; i < view.length; i += 1024) {
    s += String.fromCharCode(...view.subarray(i, Math.min(i + 1024, view.length)));
  }
  return s;
}

/**
 * ID-23 and ID-24 over one file's bytes.
 *
 * @param {Uint8Array|ArrayBuffer|string} input the file, as delivered
 * @returns {{outcome: "none"|"one"|"malformed", token: string|null,
 *   code: string|null, reason: string, matched: number, candidates: number,
 *   linesExamined: number, windowBytes: number, truncated: boolean}}
 */
export function parseBindingFile(input) {
  const all = toBytes(input);
  const head = all.subarray(0, WINDOW_BYTES);
  // The file ran past the window, so its last in-window line has no terminator
  // we are allowed to believe in.
  const truncated = all.length > WINDOW_BYTES;

  // Q4: only at the start of the file. A BOM anywhere else is an ordinary
  // character on an ordinary line, and that line then matches nothing.
  const hasBom = head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf;
  let i = hasBom ? 3 : 0;

  const matches = [];
  const candidates = [];
  let linesExamined = 0;

  while (i < head.length) {
    let end = -1;
    for (let j = i; j < head.length; j++) {
      if (head[j] === 0x0a) { end = j; break; }
    }
    if (end === -1) {
      // No `\n` between here and byte 4096. If the FILE ended inside the
      // window this is its last, unterminated line and it is wholly inside;
      // if the file ran on, this is a line that crosses the boundary and
      // ID-23 does not recognise it (vectors 12, 13).
      if (truncated) break;
      end = head.length;
    }
    linesExamined++;
    let lineEnd = end;
    // "minus one `\r`" — exactly one. `\r\r\n` therefore leaves a `\r` in the
    // line, `[ \t]*$` cannot match it, and ID-24 refuses (Q3).
    if (lineEnd > i && head[lineEnd - 1] === 0x0d) lineEnd--;
    const text = latin1(head.subarray(i, lineEnd));

    const m = ID_23_RE.exec(text);
    if (m) matches.push({ line: linesExamined, token: m[1] });
    else if (ID_24_PREFIX_RE.test(text)) candidates.push(linesExamined);

    if (end === head.length) break;
    i = end + 1;
  }

  const base = {
    token: null,
    code: null,
    matched: matches.length,
    candidates: candidates.length,
    linesExamined,
    windowBytes: head.length,
    truncated,
  };

  // ID-24's two clauses, in one branch because they cost the same thing.
  // A near miss BESIDE a good line still refuses: the file says two different
  // things about who owns this repository, and picking the one that parses is
  // how a reader gets chosen for by whoever wrote the file.
  if (candidates.length > 0 || matches.length > 1) {
    return {
      ...base,
      outcome: "malformed",
      code: BINDING_CODES.B_BINDING_MALFORMED,
      reason:
        matches.length > 1
          ? `${matches.length} binding lines inside the first ${WINDOW_BYTES} bytes (lines ` +
            `${matches.map((x) => x.line).join(", ")}). Exactly one line counts (ID-24), and choosing ` +
            "between two is not a thing a parser may do."
          : `line ${candidates.join(", line ")} of ${OWNER_FILE} begins \`astra-binding\` and a colon and ` +
            `does not match ID-23. That is a line somebody meant as a binding (ID-24)` +
            (matches.length === 1 ? ", and there is a well-formed line beside it" : "") + ".",
    };
  }

  if (matches.length === 1) {
    return {
      ...base,
      outcome: "one",
      token: matches[0].token,
      reason: `one binding line, line ${matches[0].line}, inside the first ${head.length} bytes`,
    };
  }

  return {
    ...base,
    outcome: "none",
    reason:
      linesExamined === 0
        ? `${OWNER_FILE} has no line wholly inside its first ${WINDOW_BYTES} bytes`
        : `none of the ${linesExamined} line(s) inside the first ${WINDOW_BYTES} bytes is a binding line`,
  };
}

/**
 * ID-22: the binding line at the attested commit, by repository id.
 *
 * Two reads, in this order, and the order carries the whole difference between
 * "no line" and "we could not look":
 *
 *   1. `commitInRepository(.15, .13)` — is the attested commit in the
 *      repository the certificate names? `transient` waits. **`not_found`
 *      waits AND alerts**: GitHub answered, and it said the commit the
 *      attestation is built on is not in that repository, which no author
 *      action fixes. Recording "no binding line" on the strength of it would
 *      write a fact about an author out of a fact about an attestation.
 *   2. `fileAtCommit(.15, .13, OWNER_FILE)` — `transient` waits, `not_found`
 *      is the real absence, and bytes go to `parseBindingFile`.
 *
 * Both reads are by id. Neither takes a name, so a repository renamed between
 * the release and this run is read exactly as well as one that was not, and a
 * freed login somebody else registered is read not at all.
 *
 * @param {{repositoryId: string, commit: string,
 *   deps?: {commitInRepository?: Function, fileAtCommit?: Function}}} opts
 * @returns {Promise<object>} a `parseBindingFile` answer, or an
 *   `{outcome: "wait"}` carrying `W_GITHUB_RATE_LIMITED` and, where it is one,
 *   `alert: true`.
 */
export async function readBindingLine({ repositoryId, commit, deps = {} }) {
  const readCommit = deps.commitInRepository ?? commitInRepository;
  const readFile = deps.fileAtCommit ?? fileAtCommit;

  const wait = (reason, alert = false) => ({
    outcome: "wait",
    code: BINDING_CODES.W_GITHUB_RATE_LIMITED,
    token: null,
    alert,
    reason,
  });

  const present = await readCommit(repositoryId, commit);
  if (present.status === "transient") {
    return wait(
      `GitHub did not answer whether ${commit} is a commit of repository ${repositoryId} ` +
      `(${present.reason}); a read that did not happen is not an absence of a binding line`,
    );
  }
  if (present.status === "not_found") {
    return wait(
      `GitHub says ${commit} is not a commit of repository ${repositoryId} (${present.reason}). The ` +
      "certificate attests that it is, so this is a disagreement to page an operator about and re-read, " +
      "never \"this release has no binding line\" — the owner file read would 404 for the same reason.",
      true,
    );
  }

  const file = await readFile(repositoryId, commit, OWNER_FILE);
  if (file.status === "transient") {
    return wait(`${OWNER_FILE} could not be read at ${commit} (${file.reason})`);
  }
  if (file.status === "not_found") {
    return {
      outcome: "none",
      token: null,
      code: null,
      alert: false,
      reason:
        `repository ${repositoryId} has no ${OWNER_FILE} at ${commit}. The commit itself was found first, ` +
        "so this 404 is the file's absence and not the commit's.",
    };
  }

  // `contentBytes` is what this parser wants and what nothing hands it today:
  // `bot/lib/github.mjs`'s `fileAtCommit` returns `res.text()`, so an owner
  // file that is not valid UTF-8 arrives with its bad bytes already replaced
  // by U+FFFD. The member is read first anyway, so the day that read returns
  // bytes this module is already using them; until then the fallback is named
  // rather than implied. See `toBytes` for which direction the loss runs in.
  const parsed = parseBindingFile(file.contentBytes ?? file.content ?? "");
  return { ...parsed, alert: false };
}
