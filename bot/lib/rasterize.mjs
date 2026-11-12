// The one place an SVG icon becomes pixels.
//
// The signed index carries raster icons only. An author may still commit an SVG
// (it is the format a designer exports and the smallest for flat art), and
// `tools/build-index.mjs` turns it into a PNG here before it is inlined, so that
// nothing in the client or on the site ever receives a document that can hold
// script, a stylesheet, or a reference to another file. What reaches a user is
// pixels.
//
// ── deterministic, because the index is signed ──────────────────────────────
//
// The same SVG has to give the same PNG, byte for byte, on every machine: the
// index is signed and the selftests compare bytes. So:
//   * the rasterizer is resvg compiled to WebAssembly, checked in under
//     `bot/lib/third-party/resvg-wasm` and verified against the digests below before it
//     is loaded. It has no native build, no per-OS package and no install step;
//   * its PNG encoder is pure Rust inside that module. It does not call the
//     system zlib (zlib-ng here, stock zlib in CI give different bytes for the
//     same input), and `bot/tests/rasterize.test.mjs` pins the sha256 of a
//     golden PNG so a drift in either shows as a red test, not a changed index;
//   * no fonts are loaded and the wasm build has no system font access. An SVG
//     whose picture depends on text would render as blank, differently per
//     machine in any other build, so text elements are refused instead
//     (`E_SVG_TEXT`): outline the text and release again.
//
// Nothing in the SVG is fetched or run: resvg has no script engine, and the
// wasm module has no file or network access, so `<script>`, event handlers and
// external `href`s simply do not take part in the picture.

import crypto from "node:crypto";
import fs from "node:fs";

import { Resvg, initWasm } from "./third-party/resvg-wasm/index.mjs";

const VENDOR = new URL("./third-party/resvg-wasm/", import.meta.url);

/** The side, in pixels, the long edge of a rasterized icon has: the 64 px the site draws an icon at. */
export const ICON_RASTER_PX = 64;

/** Why an SVG could not become a PNG. `code` is the bot's finding code. */
export class RasterError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "RasterError";
    this.code = code;
  }
}

/**
 * The bundled rasterizer: `@resvg/resvg-wasm` 2.6.2, built from
 * https://github.com/yisibl/resvg-js at tag v2.6.2 (MPL-2.0; that repository is
 * the source of the wasm), npm tarball integrity
 * sha512-FqALmHI8D4o6lk/LRWDnhw95z5eO+eAa6ORjVg09YRR7BkcM6oPHU9uyC0gtQG5vpFLvgpeU4+zEAz2H8APHNw==.
 * The two files under `bot/lib/third-party/resvg-wasm/` are the tarball's `index.mjs`
 * and `index_bg.wasm`, unmodified. To move the pin: fetch the new tarball, check
 * its integrity, replace both files, and update the digests here and the golden
 * digest in bot/tests/rasterize.test.mjs.
 */
export const VENDORED = Object.freeze({
  "index.mjs": "10170d02d816f02ec76f9bc095b01d9becf536e7b1e12e5aa616652c84b237a1",
  "index_bg.wasm": "22bf6e9f9a100d972da0411a69c5ba504367fc1fa87b3b64e3f35e53926d2d70",
});

// Verified before it is run, every load: the wasm is code, and this file is the
// only reader of it.
{
  const bytes = {};
  for (const [name, want] of Object.entries(VENDORED)) {
    bytes[name] = fs.readFileSync(new URL(name, VENDOR));
    const got = crypto.createHash("sha256").update(bytes[name]).digest("hex");
    if (got !== want) {
      throw new Error(`bot/lib/third-party/resvg-wasm/${name} is sha256 ${got}, not the pinned ${want}; refusing to load a rasterizer that is not the pinned one`);
    }
  }
  await initWasm(bytes["index_bg.wasm"]);
}

// Text needs fonts and there are none, so it would be silently dropped.
const TEXT_ELEMENT = /<\s*(?:[\w-]+:)?(text|tspan|textPath|tref)[\s>/]/i;

/**
 * @param {Buffer|Uint8Array} svg
 * @returns {Buffer} a PNG whose longer side is ICON_RASTER_PX pixels
 * @throws {RasterError}
 */
export function rasterizeSvg(svg) {
  const source = Buffer.from(svg).toString("utf8").replace(/<!--[\s\S]*?-->/g, " ");
  if (TEXT_ELEMENT.test(source)) {
    throw new RasterError(
      "E_SVG_TEXT",
      "the SVG icon contains text, and the registry draws icons with no fonts, so the text would vanish; convert the text to outlines (paths) and release again",
    );
  }
  try {
    const probe = new Resvg(svg, { font: { loadSystemFonts: false, fontBuffers: [] } });
    const mode = probe.width >= probe.height ? "width" : "height";
    probe.free?.();
    const r = new Resvg(svg, {
      fitTo: { mode, value: ICON_RASTER_PX },
      font: { loadSystemFonts: false, fontBuffers: [] },
      shapeRendering: 2,
      textRendering: 1,
      imageRendering: 0,
    });
    const image = r.render();
    const png = Buffer.from(image.asPng());
    image.free?.();
    r.free?.();
    return png;
  } catch (e) {
    throw new RasterError("E_SVG_RASTERIZE", `the SVG icon could not be drawn (${String(e?.message ?? e).slice(0, 200)}); check that it opens in a browser, or export it as PNG`);
  }
}
