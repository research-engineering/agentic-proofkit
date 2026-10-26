// Address CSS-pixel evidence in the exact capture, never clamp a missing sample
// to another pixel or accept a resized capture as the observed clip.
export function sampleFocusPaint(image, clip, probe) {
  if (image.width !== clip.width || image.height !== clip.height) {
    throw new Error("focus paint capture dimensions differ from the observed clip");
  }
  const pixel = (x, y) => {
    if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
    const column = Math.floor(x) - clip.x, row = Math.floor(y) - clip.y;
    if (column < 0 || row < 0 || column >= image.width || row >= image.height) return null;
    const offset = (row * image.width + column) * 4;
    return [...image.rgba.subarray(offset, offset + 4)];
  };
  return probe.samples.map(sample => {
    const ring = pixel(sample.x, sample.y), background = pixel(sample.backgroundX, sample.backgroundY);
    const colorMatches = probe.color[3] === 1 && ring !== null && background !== null
      && ring[3] === 255 && background[3] === 255
      && ring.slice(0, 3).every((value, index) => value === probe.color[index]);
    return {sample, ring, background, colorMatches};
  });
}
