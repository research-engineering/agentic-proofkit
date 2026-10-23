import {createHash} from "node:crypto";
import {crc32, inflateSync} from "node:zlib";

// PNG decoding and the canonical pixel digest of the visual reference gate.
// Decoding uses only node:zlib; no image library and no tolerance exist here.

const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const maximumPixels = 1440 * 2400;
const channelsByColorType = new Map([[0, 1], [2, 3], [3, 1], [4, 2], [6, 4]]);

export function decodePNG(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length < signature.length || !buffer.subarray(0, signature.length).equals(signature)) {
    throw new Error("image is not a PNG file");
  }
  let offset = signature.length;
  let header;
  let palette;
  let transparency;
  const data = [];
  let ended = false;
  while (offset < buffer.length) {
    if (offset + 12 > buffer.length) throw new Error("PNG chunk is truncated");
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString("latin1", offset + 4, offset + 8);
    const end = offset + 12 + length;
    if (length > 0x7fffffff || end > buffer.length) throw new Error("PNG chunk is truncated");
    const body = buffer.subarray(offset + 8, offset + 8 + length);
    if (crc32(buffer.subarray(offset + 4, offset + 8 + length)) !== buffer.readUInt32BE(offset + 8 + length)) {
      throw new Error("PNG chunk checksum mismatch");
    }
    if (header === undefined && type !== "IHDR") throw new Error("PNG must start with IHDR");
    if (type === "IHDR") {
      if (header !== undefined) throw new Error("PNG must contain exactly one IHDR");
      header = decodeHeader(body);
    } else if (type === "PLTE") palette = body;
    else if (type === "tRNS") {
      // Transparency of a grayscale or RGB image would change alpha without a
      // palette; only palette images may carry tRNS here.
      if (header.colorType !== 3) throw new Error("PNG tRNS is admitted only for palette images");
      transparency = body;
    }
    else if (type === "IDAT") data.push(body);
    else if (type === "IEND") {
      ended = true;
      offset = end;
      break;
    } else if ((type.charCodeAt(0) & 0x20) === 0) {
      throw new Error("PNG contains an unsupported critical chunk");
    }
    offset = end;
  }
  if (!ended || offset !== buffer.length) throw new Error("PNG must end with IEND");
  if (data.length === 0) throw new Error("PNG has no image data");
  if (header.colorType === 3 && palette === undefined) throw new Error("palette PNG has no palette");
  const channels = channelsByColorType.get(header.colorType);
  const stride = header.width * channels;
  const raw = inflateSync(Buffer.concat(data), {maxOutputLength: (stride + 1) * header.height + 1});
  if (raw.length !== (stride + 1) * header.height) throw new Error("PNG image data has an unexpected length");
  const pixels = unfilter(raw, stride, channels, header.height);
  return {width: header.width, height: header.height, rgba: toRGBA(pixels, header, palette, transparency)};
}

function decodeHeader(body) {
  if (body.length !== 13) throw new Error("PNG header is invalid");
  const width = body.readUInt32BE(0);
  const height = body.readUInt32BE(4);
  const [bitDepth, colorType, compression, filter, interlace] = body.subarray(8, 13);
  if (width === 0 || height === 0 || width * height > maximumPixels) throw new Error("PNG dimensions are outside the admitted bounds");
  if (bitDepth !== 8 || !channelsByColorType.has(colorType)) throw new Error("PNG must be 8-bit grayscale, RGB, palette, grayscale-alpha or RGBA");
  if (compression !== 0 || filter !== 0 || interlace !== 0) throw new Error("PNG must use standard compression, filtering and no interlacing");
  return {width, height, colorType};
}

function unfilter(raw, stride, channels, height) {
  const output = Buffer.alloc(stride * height);
  for (let row = 0; row < height; row += 1) {
    const filter = raw[row * (stride + 1)];
    const source = row * (stride + 1) + 1;
    const target = row * stride;
    for (let index = 0; index < stride; index += 1) {
      const value = raw[source + index];
      const left = index >= channels ? output[target + index - channels] : 0;
      const up = row > 0 ? output[target - stride + index] : 0;
      const upLeft = row > 0 && index >= channels ? output[target - stride + index - channels] : 0;
      let predictor;
      if (filter === 0) predictor = 0;
      else if (filter === 1) predictor = left;
      else if (filter === 2) predictor = up;
      else if (filter === 3) predictor = (left + up) >> 1;
      else if (filter === 4) predictor = paeth(left, up, upLeft);
      else throw new Error("PNG row filter is invalid");
      output[target + index] = (value + predictor) & 0xff;
    }
  }
  return output;
}

function paeth(left, up, upLeft) {
  const estimate = left + up - upLeft;
  const toLeft = Math.abs(estimate - left);
  const toUp = Math.abs(estimate - up);
  const toUpLeft = Math.abs(estimate - upLeft);
  if (toLeft <= toUp && toLeft <= toUpLeft) return left;
  return toUp <= toUpLeft ? up : upLeft;
}

function toRGBA(pixels, header, palette, transparency) {
  const count = header.width * header.height;
  const rgba = Buffer.alloc(count * 4);
  for (let pixel = 0; pixel < count; pixel += 1) {
    let red, green, blue, alpha = 255;
    if (header.colorType === 6) {
      [red, green, blue, alpha] = pixels.subarray(pixel * 4, pixel * 4 + 4);
    } else if (header.colorType === 2) {
      [red, green, blue] = pixels.subarray(pixel * 3, pixel * 3 + 3);
    } else if (header.colorType === 0) {
      red = green = blue = pixels[pixel];
    } else if (header.colorType === 4) {
      red = green = blue = pixels[pixel * 2];
      alpha = pixels[pixel * 2 + 1];
    } else {
      const entry = pixels[pixel];
      if (entry * 3 + 2 >= palette.length) throw new Error("PNG palette index is out of range");
      [red, green, blue] = palette.subarray(entry * 3, entry * 3 + 3);
      if (transparency !== undefined && entry < transparency.length) alpha = transparency[entry];
    }
    rgba[pixel * 4] = red;
    rgba[pixel * 4 + 1] = green;
    rgba[pixel * 4 + 2] = blue;
    rgba[pixel * 4 + 3] = alpha;
  }
  return rgba;
}

// canonicalRGBADigest is the single code owner of the canonical pixel
// encoding: the 14 ASCII bytes "PROOFKIT-RGBA8", the width and the height as
// big-endian uint32, then the 8-bit non-premultiplied RGBA rows from top to
// bottom with no padding. A capture matches its reference only when this
// digest and the dimensions are equal: no pixel may differ in any channel.
export function canonicalRGBADigest({width, height, rgba}) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0 || rgba.length !== width * height * 4) {
    throw new Error("canonical RGBA digest needs positive dimensions and exactly width*height RGBA pixels");
  }
  const dimensions = Buffer.alloc(8);
  dimensions.writeUInt32BE(width, 0);
  dimensions.writeUInt32BE(height, 4);
  return createHash("sha256").update("PROOFKIT-RGBA8", "ascii").update(dimensions).update(rgba).digest("hex");
}
