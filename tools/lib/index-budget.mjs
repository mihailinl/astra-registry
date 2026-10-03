// The catalogue's size budget, and the early word before SERVE-49 refuses.
//
// `policy/limits.json`'s `max_index_bytes` is a wall: over it the signer carries
// `signed`'s head forward and every new listing, release and delist waits
// (SERVE-49, `tools/signer/run.mjs`). A wall is the wrong first signal. The
// catalogue grows one listing at a time, each listing looks small in its own
// verdict, and from contract 3.0.0 a new listing publishes with no moderator in
// the loop — so the first person to notice a 110 KB icon would be the one
// reading the carry alarm, after the catalogue had already stopped moving.
//
// So this is the word before the wall: at WARN_PERCENT of the cap it says so,
// loudly, and names the three listings that weigh most and what their icons
// cost, because the icon is what grew the catalogue every time it has grown.
// Measured on serial 55 (649,005 signed bytes, 16 listings): inlined icons were
// 470,540 bytes of it, READMEs 96,028, releases 36,440, translations 1,778.
//
// ONE MODULE, TWO READERS, and both need the same answer:
//
//   * `.github/workflows/build-index.yml` over the unsigned deploy candidate, on
//     every pull request and after every bot commit — an annotation on the run,
//     never a failure below the cap;
//   * `tools/signer/run.mjs` over the SIGNED bytes a client receives — a `note`
//     every run, a `::warning::` every run while over the line, and the verdict
//     code `SIGNER_INDEX_NEAR_CAP` (a page) when a run publishes a catalogue
//     that GREW while over the line. Growth, not presence: a resign of the same
//     listings is the same catalogue, and a page that repeats every hour about a
//     state nobody changed is a page on its way to being muted.
//
// Why 75, and not 80 or 90. It is the last point at which the fix still fits
// before the wall: the sanctioned fix (icons and READMEs out of the catalogue as
// URL + SHA-256 pairs; ops `notes/coordinator/index-budget.md`) is a contract
// version, a client release and a registry change, and at the growth measured
// between serials 53 and 55 (69,092 bytes over two serials, 67 KB of it one
// release's icon) the last 25% of 1 MiB is about eight more serials. A later
// line would warn after the only fix had stopped being possible in time.
//
// Nothing here reads the network, the clock or the environment: it is a pure
// function of the bytes it is handed, so both readers and the suite get the same
// answer from the same catalogue.

/** Percent of `max_index_bytes` at which the catalogue is called near its cap. */
export const WARN_PERCENT = 75;

/** How many listings the warning names. */
export const NAMED_LISTINGS = 3;

const DATA_URI = /^data:([^;,]+);base64,([A-Za-z0-9+/]*={0,2})$/;

/**
 * The first byte count the warning fires at: WARN_PERCENT of the cap, rounded
 * UP, so a catalogue one byte under three quarters is under the line on any cap.
 *
 * @param {number} cap
 */
export function warnLine(cap) {
  if (!Number.isSafeInteger(cap) || cap <= 0) throw new Error(`the cap is ${JSON.stringify(cap)}, not a positive integer`);
  return Math.ceil((cap * WARN_PERCENT) / 100);
}

/**
 * What one listing's icon costs: the decoded image, and the string the
 * catalogue carries for it. Zero and `null` for a listing with no inlined icon.
 *
 * @param {unknown} iconUrl
 * @returns {{media: string|null, raw: number, inlined: number}}
 */
export function iconCost(iconUrl) {
  const text = typeof iconUrl === "string" ? iconUrl : "";
  const m = DATA_URI.exec(text);
  if (!m) return { media: null, raw: 0, inlined: Buffer.byteLength(text, "utf8") };
  return { media: m[1], raw: Buffer.from(m[2], "base64").length, inlined: Buffer.byteLength(text, "utf8") };
}

/**
 * The listings that weigh most, heaviest first, ties broken by id so two runs
 * over one catalogue name the same three.
 *
 * `bytes` is the listing as compact JSON. It is not the listing's share of the
 * pretty-printed file, which is indented, but it ranks the same way and needs
 * no second serialisation of the whole document to compute.
 *
 * @param {object} doc  a catalogue: `{signed: {plugins: [...]}}`
 * @param {number} [n]
 */
export function largestListings(doc, n = NAMED_LISTINGS) {
  const plugins = Array.isArray(doc?.signed?.plugins) ? doc.signed.plugins : [];
  return plugins
    .map((p) => {
      const icon = iconCost(p?.icon_url);
      return {
        id: String(p?.id ?? "?"),
        bytes: Buffer.byteLength(JSON.stringify(p), "utf8"),
        icon_bytes: icon.raw,
        icon_inlined: icon.inlined,
        icon_media: icon.media,
        readme_bytes: typeof p?.readme === "string" ? Buffer.byteLength(p.readme, "utf8") : 0,
      };
    })
    .sort((a, b) => b.bytes - a.bytes || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .slice(0, n);
}

/**
 * The budget of one catalogue.
 *
 * @param {{bytes: number, cap: number, doc: object}} o
 *   `bytes` is the length of the document as it is (or would be) served, and
 *   `doc` the same document parsed, for the listing breakdown.
 */
export function indexBudget({ bytes, cap, doc }) {
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error(`the catalogue's size is ${JSON.stringify(bytes)}`);
  const line = warnLine(cap);
  return {
    bytes,
    cap,
    line,
    percent: Math.floor((bytes * 1000) / cap) / 10,
    near: bytes >= line,
    over: bytes > cap,
    largest: largestListings(doc),
  };
}

const n = (x) => String(x).replace(/\B(?=(\d{3})+(?!\d))/g, ",");

/** One line for every run: where the catalogue stands. */
export function budgetLine(b, what = "the catalogue") {
  return `${what} is ${n(b.bytes)} of ${n(b.cap)} bytes (${b.percent}%); ` +
    `the early warning is at ${n(b.line)} (${WARN_PERCENT}%) and SERVE-49 refuses over ${n(b.cap)}`;
}

/**
 * The warning itself: the size, the three listings and their icons, and what to
 * do — in that order, because the reader who acts on it needs the names first.
 */
export function budgetWarning(b, what = "the catalogue") {
  const named = b.largest.map((l) => {
    const icon = l.icon_media
      ? `icon ${n(l.icon_bytes)} bytes ${l.icon_media}, ${n(l.icon_inlined)} inlined`
      : "no inlined icon";
    return `${l.id} ${n(l.bytes)} bytes (${icon}; README ${n(l.readme_bytes)})`;
  });
  return (
    `INDEX BUDGET: ${what} is ${n(b.bytes)} bytes, ${b.percent}% of the ${n(b.cap)} max_index_bytes in ` +
    `policy/limits.json, past the ${WARN_PERCENT}% early warning at ${n(b.line)}. Over the cap the signer ` +
    `carries the served catalogue and nothing new publishes (SERVE-49). Largest listings: ` +
    `${named.join("; ") || "none"}. The fix is icons and READMEs out of the catalogue as URL + SHA-256 ` +
    `pairs (ops notes/coordinator/index-budget.md); until then, an author re-exporting an icon at ` +
    `128x128 WebP is what moves this number. Raising the cap is not a fix: SERVE-50 and every new ` +
    `client hold the same number.`
  );
}
