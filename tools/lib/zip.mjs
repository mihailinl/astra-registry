// A ZIP reader and a deterministic stored-only ZIP writer, in node builtins.
//
// The reader exists so the bot can look inside a .astraplugin without trusting
// a third-party unzip library with an attacker-controlled archive: it reads the
// CENTRAL DIRECTORY (not the stream of local headers), which is the only part a
// well-formed archive guarantees, and it hands back the entry table so a caller
// can reject symlinks, duplicates and traversal BEFORE anything is written to a
// disk. Nothing here extracts to a filesystem — it cannot, by construction.
//
// The writer exists only to build test fixtures reproducibly. Stored entries,
// fixed 1980-01-01 timestamps, caller-controlled order: the same inputs give
// the same bytes, so a fixture's sha256 can be asserted.

import zlib from "node:zlib";

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const DOS_1980 = { time: 0, date: 0x0021 };

// Unix st_mode bits, as stored in the high 16 of external attributes.
export const S_IFMT = 0o170000;
export const S_IFLNK = 0o120000;
export const S_IFDIR = 0o040000;

/**
 * Parse the central directory.
 * @param {Buffer} buf whole archive
 * @returns {{entries: {name: string, method: number, crc32: number,
 *            compressedSize: number, size: number, externalAttributes: number,
 *            unixMode: number, offset: number, index: number}[]}}
 */
export function readZip(buf) {
  let eocd = -1;
  const from = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= from; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a ZIP archive: no end-of-central-directory record");

  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset + cdSize > buf.length) throw new Error("ZIP central directory runs past the end of the file");

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== SIG_CENTRAL) throw new Error(`ZIP central directory entry ${i} has a bad signature`);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const external = buf.readUInt32LE(p + 38);
    entries.push({
      index: i,
      name: buf.toString("utf8", p + 46, p + 46 + nameLen),
      method: buf.readUInt16LE(p + 10),
      crc32: buf.readUInt32LE(p + 16),
      compressedSize: buf.readUInt32LE(p + 20),
      size: buf.readUInt32LE(p + 24),
      externalAttributes: external,
      unixMode: (external >>> 16) & 0xffff,
      offset: buf.readUInt32LE(p + 42),
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { entries };
}

/** Read one entry's bytes. Bounded by the declared sizes; never touches disk. */
export function readEntry(buf, entry) {
  if (buf.readUInt32LE(entry.offset) !== SIG_LOCAL) {
    throw new Error(`ZIP entry ${entry.name}: local header signature is wrong`);
  }
  const nameLen = buf.readUInt16LE(entry.offset + 26);
  const extraLen = buf.readUInt16LE(entry.offset + 28);
  const start = entry.offset + 30 + nameLen + extraLen;
  const end = start + entry.compressedSize;
  if (end > buf.length) throw new Error(`ZIP entry ${entry.name}: data runs past the end of the file`);
  const raw = buf.subarray(start, end);
  if (entry.method === 0) return Buffer.from(raw);
  if (entry.method === 8) return zlib.inflateRawSync(raw);
  throw new Error(`ZIP entry ${entry.name}: unsupported compression method ${entry.method}`);
}

/**
 * Deterministic stored-only writer, for fixtures.
 * @param {{name: string, data: Buffer|string, mode?: number}[]} files in order
 */
export function writeZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const f of files) {
    const name = Buffer.from(f.name, "utf8");
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, "utf8");
    const crc = zlib.crc32(data) >>> 0;
    const mode = f.mode ?? 0o644;

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(SIG_LOCAL, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt16LE(DOS_1980.time, 10);
    local.writeUInt16LE(DOS_1980.date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);
    locals.push(local, data);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(SIG_CENTRAL, 0);
    central.writeUInt16LE(0x031e, 4); // made by unix, zip 3.0
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(DOS_1980.time, 12);
    central.writeUInt16LE(DOS_1980.date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(((mode & 0xffff) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);
    centrals.push(central);

    offset += local.length + data.length;
  }

  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, cd, eocd]);
}
