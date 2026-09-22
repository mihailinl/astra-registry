# Fixture Beta

The listing whose icon is real binary content, so the inlined `data:` URI in
the regenerated catalogue is base64 of bytes rather than base64 of a string
somebody typed.

## Why the bytes matter

`tools/build-index.mjs` reads the picture with `fs.readFileSync` and hands the
buffer to `iconDataUri`. A fixture with only an SVG would exercise one media
type and one encoding path; this one and `fixture-gamma` cover the other two
this repository accepts.

## Platforms

Two artifacts, so the flat `platform_downloads` projection has more than one key
to sort.
