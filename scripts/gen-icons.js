import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';

const FOREST = [23, 63, 53];
const CORAL = [237, 127, 103];
const MINT = [220, 238, 230];

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = [];
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; table[n] = c >>> 0; }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function drawIcon(size) {
  const rows = [];
  const scale = 2.15;
  for (let y = 0; y < size; y++) {
    rows.push(Buffer.from([0]));
    for (let x = 0; x < size; x++) {
      let color = FOREST;
      const nx = (x - size / 2) / (size / 2) * scale;
      const ny = (y - size / 2) / (size / 2) * scale;
      const heart = Math.pow(nx * nx + ny * ny - 1, 3) - nx * nx * ny * ny * ny <= 0;
      if (heart) color = CORAL;
      rows.push(Buffer.from(color));
    }
  }
  const raw = Buffer.concat(rows);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 2;
  const png = Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  return png;
}

const out = path.resolve('mobile', 'public');
for (const size of [192, 512, 180]) {
  const name = size === 180 ? 'apple-touch-icon.png' : `icon-${size}.png`;
  fs.writeFileSync(path.join(out, name), drawIcon(size));
  console.log(`wrote ${name}`);
}