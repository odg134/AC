const SESSION_KEY = new Uint8Array([
  0x6a, 0xc3, 0xf7, 0x2b, 0x8d, 0x14, 0xe9, 0x55,
  0x3f, 0xa1, 0x72, 0xc8, 0x0b, 0xd4, 0x91, 0x6e,
  0xb2, 0x47, 0xda, 0x83, 0x1c, 0x90, 0x5a, 0xf3,
  0xe6, 0x28, 0x74, 0xcb, 0x0f, 0x39, 0xb5, 0x7d,
]);

const NONCE_SUFFIX = new Uint8Array([0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88]);

function rotl(v: number, n: number): number {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function qr(w: Uint32Array, a: number, b: number, c: number, d: number): void {
  w[a] = (w[a] + w[b]) >>> 0; w[d] ^= w[a]; w[d] = rotl(w[d], 16);
  w[c] = (w[c] + w[d]) >>> 0; w[b] ^= w[c]; w[b] = rotl(w[b], 12);
  w[a] = (w[a] + w[b]) >>> 0; w[d] ^= w[a]; w[d] = rotl(w[d], 8);
  w[c] = (w[c] + w[d]) >>> 0; w[b] ^= w[c]; w[b] = rotl(w[b], 7);
}

function load32le(buf: Uint8Array, off: number): number {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}

function block(state: Uint32Array, out: Uint8Array): void {
  const w = new Uint32Array(state);
  for (let r = 0; r < 10; r++) {
    qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
    qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
  }
  const view = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) view.setUint32(i * 4, (w[i] + state[i]) >>> 0, true);
}

function nonceFromSeq(seq: number): Uint8Array {
  const n = new Uint8Array(12);
  n[0] = seq & 0xff; n[1] = (seq >>> 8) & 0xff;
  n[2] = (seq >>> 16) & 0xff; n[3] = (seq >>> 24) & 0xff;
  n.set(NONCE_SUFFIX, 4);
  return n;
}

export const LAUNCHER_KEY = new Uint8Array([
  0xb3, 0x7e, 0x2a, 0xc9, 0x5f, 0x01, 0xd8, 0x44,
  0xa6, 0x3c, 0x88, 0xf2, 0x17, 0xeb, 0x6d, 0x93,
  0x4a, 0xb0, 0xcc, 0x71, 0x29, 0x5e, 0x87, 0x3f,
  0xd1, 0x94, 0x62, 0xac, 0x0e, 0x57, 0xf9, 0x26,
]);

function chacha20(data: Uint8Array, key: Uint8Array, nonce: Uint8Array): void {
  const state = new Uint32Array(16);
  state[0] = 0x61707865; state[1] = 0x3320646e;
  state[2] = 0x79622d32; state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) state[4 + i] = load32le(key, i * 4);
  state[12] = 0;
  state[13] = load32le(nonce, 0);
  state[14] = load32le(nonce, 4);
  state[15] = load32le(nonce, 8);

  for (let off = 0; off < data.length; off += 64) {
    state[12] = (off / 64) >>> 0;
    const ks = new Uint8Array(64);
    block(state, ks);
    const chunk = Math.min(64, data.length - off);
    for (let i = 0; i < chunk; i++) data[off + i] ^= ks[i];
  }
}

export function encryptBuffer(data: Uint8Array, key: Uint8Array): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(data);
  chacha20(encrypted, key, nonce);
  const out = new Uint8Array(12 + encrypted.length);
  out.set(nonce);
  out.set(encrypted, 12);
  return out;
}

export function decryptPayload(data: Uint8Array, seq: number): void {
  chacha20(data, SESSION_KEY, nonceFromSeq(seq));
}
