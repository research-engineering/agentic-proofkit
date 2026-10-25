import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test from "node:test";
import {crc32, deflateSync} from "node:zlib";

import {captureInventory} from "../tests/visual/capture-inventory.mjs";
import {comparedEnvironmentFields, environmentDivergence, observeEnvironment} from "../tests/visual/environment-probe.mjs";
import {canonicalRGBADigest, decodePNG} from "../tests/visual/exact-png.mjs";

function chunk(type, body) {
  const header = Buffer.alloc(8);
  header.writeUInt32BE(body.length, 0);
  header.write(type, 4, "latin1");
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([header.subarray(4), body])), 0);
  return Buffer.concat([header, body, checksum]);
}

// An independent Paeth predictor for the test encoder (PNG specification 9.4).
function paeth(left, up, upLeft) {
  const estimate = left + up - upLeft;
  const distances = [Math.abs(estimate - left), Math.abs(estimate - up), Math.abs(estimate - upLeft)];
  if (distances[0] <= distances[1] && distances[0] <= distances[2]) return left;
  return distances[1] <= distances[2] ? up : upLeft;
}

// encodePNG writes 8-bit images with one row filter per row.
function encodePNG({width, height, colorType, channels, pixels, filters = [], palette, transparency}) {
  const stride = width * channels;
  const rows = [];
  for (let row = 0; row < height; row += 1) {
    const filter = filters[row % Math.max(filters.length, 1)] ?? 0;
    const line = pixels.subarray(row * stride, (row + 1) * stride);
    const previous = row > 0 ? pixels.subarray((row - 1) * stride, row * stride) : Buffer.alloc(stride);
    const encoded = Buffer.alloc(stride);
    for (let index = 0; index < stride; index += 1) {
      const left = index >= channels ? line[index - channels] : 0;
      const up = previous[index];
      const upLeft = index >= channels ? previous[index - channels] : 0;
      const predictor = [0, left, up, (left + up) >> 1, paeth(left, up, upLeft)][filter];
      encoded[index] = (line[index] - predictor) & 0xff;
    }
    rows.push(Buffer.from([filter]), encoded);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header.set([8, colorType, 0, 0, 0], 8);
  const parts = [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", header)];
  if (palette) parts.push(chunk("PLTE", palette));
  if (transparency) parts.push(chunk("tRNS", transparency));
  parts.push(chunk("IDAT", deflateSync(Buffer.concat(rows))), chunk("IEND", Buffer.alloc(0)));
  return Buffer.concat(parts);
}

function gradient(width, height) {
  const pixels = Buffer.alloc(width * height * 4);
  for (let pixel = 0; pixel < width * height; pixel += 1) {
    pixels.set([(pixel * 7) & 0xff, (pixel * 13) & 0xff, (pixel * 29) & 0xff, 255], pixel * 4);
  }
  return pixels;
}

test("exact PNG decoding reverses every row filter and color type", () => {
  const width = 9;
  const height = 6;
  const rgba = gradient(width, height);
  const decoded = decodePNG(encodePNG({width, height, colorType: 6, channels: 4, pixels: rgba, filters: [0, 1, 2, 3, 4]}));
  assert.deepEqual([decoded.width, decoded.height], [width, height]);
  assert.ok(decoded.rgba.equals(rgba));
  const rgb = Buffer.alloc(width * height * 3);
  for (let pixel = 0; pixel < width * height; pixel += 1) rgb.set(rgba.subarray(pixel * 4, pixel * 4 + 3), pixel * 3);
  assert.ok(decodePNG(encodePNG({width, height, colorType: 2, channels: 3, pixels: rgb, filters: [4, 3, 2, 1, 0]})).rgba.equals(rgba));
  const palette = Buffer.from([10, 20, 30, 40, 50, 60]);
  const indexed = decodePNG(encodePNG({width: 2, height: 1, colorType: 3, channels: 1, pixels: Buffer.from([0, 1]), palette, transparency: Buffer.from([128])}));
  assert.deepEqual([...indexed.rgba], [10, 20, 30, 128, 40, 50, 60, 255]);
});

test("the canonical RGBA digest covers dimensions and every channel of every pixel", () => {
  const width = 16;
  const height = 8;
  const reference = decodePNG(encodePNG({width, height, colorType: 6, channels: 4, pixels: gradient(width, height)}));
  // A known-answer vector for a 2x1 image fixes the encoded bytes.
  assert.equal(canonicalRGBADigest({width: 2, height: 1, rgba: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])}), "5c3a27f684eb264dbc461a30e8265ffd30c21207e24e8aa1756e04bb5ed61636");
  const digest = canonicalRGBADigest(reference);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(canonicalRGBADigest({...reference, rgba: Buffer.from(reference.rgba)}), digest);
  const differs = (rgba, size = {width, height}) => canonicalRGBADigest({...size, rgba}) !== digest;
  const unit = Buffer.from(reference.rgba);
  unit[5 * 4 + 2] = (unit[5 * 4 + 2] + 1) & 0xff;
  assert.ok(differs(unit), "one unit in one channel");
  const alpha = Buffer.from(reference.rgba);
  alpha[3] = 254;
  assert.ok(differs(alpha), "alpha");
  const shifted = Buffer.alloc(reference.rgba.length);
  for (let row = 0; row < height; row += 1) {
    reference.rgba.copy(shifted, row * width * 4 + 4, row * width * 4, (row + 1) * width * 4 - 4);
    reference.rgba.copy(shifted, row * width * 4, row * width * 4, row * width * 4 + 4);
  }
  assert.ok(differs(shifted), "one-pixel shift");
  assert.ok(differs(reference.rgba, {width: height, height: width}), "same bytes, transposed dimensions");
  assert.throws(() => canonicalRGBADigest({width, height: height + 1, rgba: reference.rgba}), /exactly width\*height/);
});

test("the capture inventory digests every PNG capture and refuses other files", () => {
  const directory = mkdtempSync(join(tmpdir(), "proofkit-capture-inventory-"));
  try {
    mkdirSync(join(directory, "webkit"));
    mkdirSync(join(directory, "chromium"));
    const pixels = gradient(3, 2);
    writeFileSync(join(directory, "webkit", "view.dark.320.png"), encodePNG({width: 3, height: 2, colorType: 6, channels: 4, pixels}));
    writeFileSync(join(directory, "chromium", "view.light.320.png"), encodePNG({width: 3, height: 2, colorType: 6, channels: 4, pixels, filters: [4, 1]}));
    const entries = captureInventory(directory);
    assert.deepEqual(entries.map((entry) => entry.id), ["chromium/view.light.320", "webkit/view.dark.320"]);
    assert.equal(entries[0].rgbaSHA256, entries[1].rgbaSHA256, "filters do not change the canonical digest");
    assert.deepEqual([entries[0].width, entries[0].height], [3, 2]);
    writeFileSync(join(directory, "notes.txt"), "x");
    assert.throws(() => captureInventory(directory), /only PNG captures/);
    rmSync(join(directory, "notes.txt"));
    symlinkSync(join(directory, "webkit", "view.dark.320.png"), join(directory, "webkit", "link.png"));
    assert.throws(() => captureInventory(directory), /symlinks/);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});

test("exact PNG decoding refuses malformed, unsupported or oversized images", () => {
  const valid = encodePNG({width: 2, height: 2, colorType: 6, channels: 4, pixels: gradient(2, 2)});
  const corrupt = Buffer.from(valid);
  corrupt[30] ^= 0xff;
  assert.throws(() => decodePNG(corrupt), /checksum/);
  assert.throws(() => decodePNG(valid.subarray(0, valid.length - 4)), /truncated|IEND/);
  assert.throws(() => decodePNG(Buffer.from("not a png")), /not a PNG/);
  const sixteenBit = Buffer.from(valid);
  sixteenBit[24] = 16;
  sixteenBit.writeUInt32BE(crc32(sixteenBit.subarray(12, 29)), 29);
  assert.throws(() => decodePNG(sixteenBit), /8-bit/);
  const huge = Buffer.from(valid);
  huge.writeUInt32BE(1441, 16);
  huge.writeUInt32BE(2400, 20);
  huge.writeUInt32BE(crc32(huge.subarray(12, 29)), 29);
  assert.throws(() => decodePNG(huge), /bounds/);
});

test("exact PNG decoding refuses transparency outside palette images and a second header", () => {
  const rgb = Buffer.from([1, 2, 3, 4, 5, 6]);
  assert.throws(() => decodePNG(encodePNG({width: 2, height: 1, colorType: 2, channels: 3, pixels: rgb, transparency: Buffer.from([0, 1, 0, 2, 0, 3])})), /tRNS is admitted only for palette images/);
  assert.throws(() => decodePNG(encodePNG({width: 2, height: 1, colorType: 0, channels: 1, pixels: Buffer.from([7, 9]), transparency: Buffer.from([0, 7])})), /tRNS is admitted only for palette images/);
  assert.throws(() => decodePNG(encodePNG({width: 1, height: 1, colorType: 6, channels: 4, pixels: Buffer.from([1, 2, 3, 4]), transparency: Buffer.from([0])})), /tRNS is admitted only for palette images/);
  const valid = encodePNG({width: 2, height: 1, colorType: 2, channels: 3, pixels: rgb});
  assert.deepEqual([...decodePNG(valid).rgba], [1, 2, 3, 255, 4, 5, 6, 255]);
  // A second IHDR after the first whose 3x1 grayscale-alpha layout fits the
  // same image data, so only refusing it keeps the data from being reread.
  const secondHeader = Buffer.alloc(13);
  secondHeader.writeUInt32BE(3, 0);
  secondHeader.writeUInt32BE(1, 4);
  secondHeader.set([8, 4, 0, 0, 0], 8);
  const headerEnd = 8 + 12 + 13;
  const twoHeaders = Buffer.concat([valid.subarray(0, headerEnd), chunk("IHDR", secondHeader), valid.subarray(headerEnd)]);
  assert.throws(() => decodePNG(twoHeaders), /exactly one IHDR/);
});

test("environment divergence names exactly the compared fields that differ", () => {
  const reference = {architecture: "aarch64", dockerImage: {dockerImageName: "image:tag"}, emulation: "none", engines: {chromium: "1"}, fontConfig: "sha256:1", fontMatches: {serif: "a"}, os: {id: "ubuntu", versionId: "24.04"}, packages: {fontconfig: "1"}};
  assert.deepEqual(environmentDivergence(reference, structuredClone(reference)), []);
  assert.deepEqual(environmentDivergence(reference, {...structuredClone(reference), architecture: "x86_64", packages: null}), ["architecture", "packages"]);
  assert.deepEqual(environmentDivergence(reference, {...structuredClone(reference), engines: {chromium: "2"}, cpu: {model: "other"}}), ["engines"]);
  assert.deepEqual(environmentDivergence(reference, {...structuredClone(reference), fontConfig: "sha256:2"}), ["fontConfig"]);
  assert.deepEqual(comparedEnvironmentFields, ["architecture", "dockerImage", "emulation", "engines", "fontConfig", "fontMatches", "os", "packages"]);
});

test("environment observation marks emulation and missing observations without launching a browser", () => {
  const files = {
    "/proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Example CPU\nflags\t\t: fpu avx2 hypervisor\n",
    "/proc/self/maps": "",
    "/etc/os-release": "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
    "/ms-playwright/.docker-info": "{\"dockerImageName\":\"image:tag\",\"driverVersion\":\"1.0.0\"}",
  };
  const read = (path) => files[path] ?? null;
  const commands = {"uname -m": "aarch64"};
  const run = (command, args) => commands[[command, ...args].join(" ")] ?? null;
  const observed = observeEnvironment({platform: "linux", read, run, environment: {}});
  assert.equal(observed.emulation, "foreign-cpu");
  assert.deepEqual(observed.cpu, {avx2: true, avx512f: false, features: "fpu avx2 hypervisor", hypervisor: true, model: "Example CPU", vendor: "GenuineIntel"});
  assert.equal(observed.fontConfig, null);
  assert.deepEqual(observed.os, {id: "ubuntu", versionId: "24.04"});
  assert.deepEqual(observed.dockerImage, {dockerImageName: "image:tag", driverVersion: "1.0.0"});
  assert.equal(observed.packages, null);
  assert.equal(observed.fontMatches, null);
  commands["uname -m"] = "x86_64";
  assert.equal(observeEnvironment({platform: "linux", read, run, environment: {}}).emulation, "none");
  files["/proc/self/maps"] = "00400000-00401000 r-xp 00000000 00:00 0 /run/rosetta/rosetta\n";
  assert.equal(observeEnvironment({platform: "linux", read, run, environment: {}}).emulation, "translator-mapped");
});

test("font matches query fc-match with each family's whole name", () => {
  const queries = [];
  const run = (command, args) => {
    if (command !== "fc-match") return null;
    queries.push(args);
    return `match for ${args[0]}`;
  };
  const observed = observeEnvironment({platform: "linux", read: () => null, run, environment: {}});
  // fc-match reads text after an unescaped hyphen as a point size, so
  // "sans-serif" would query the family "sans"; every hyphen is escaped.
  assert.deepEqual(queries, [["monospace"], ["sans\\-serif"], ["serif"], ["system\\-ui"], ["ui\\-monospace"]]);
  assert.deepEqual(observed.fontMatches, {
    "monospace": "match for monospace",
    "sans-serif": "match for sans\\-serif",
    "serif": "match for serif",
    "system-ui": "match for system\\-ui",
    "ui-monospace": "match for ui\\-monospace",
  });
});

test("arm64 CPU observation records the Features line and leaves x86 flags unobserved", () => {
  const files = {"/proc/cpuinfo": "processor\t: 0\nBogoMIPS\t: 48.00\nFeatures\t: fp asimd sve sve2\nCPU implementer\t: 0x41\nCPU part\t: 0xd49\n"};
  const directory = mkdtempSync(join(tmpdir(), "proofkit-fontconfig-"));
  try {
    const config = join(directory, "fonts.conf");
    writeFileSync(config, "<fontconfig/>\n");
    const observed = observeEnvironment({platform: "linux", read: (path) => files[path] ?? null, run: (command) => (command === "uname" ? "aarch64" : null), environment: {FONTCONFIG_FILE: config}});
    assert.deepEqual(observed.cpu, {avx2: null, avx512f: null, features: "fp asimd sve sve2", hypervisor: null, model: "part 0xd49", vendor: "implementer 0x41"});
    assert.equal(observed.emulation, "none");
    assert.equal(observed.fontConfig, `sha256:${createHash("sha256").update("<fontconfig/>\n").digest("hex")}`);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});
