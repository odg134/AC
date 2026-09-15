// BLAKE2b with configurable output length, no key/salt/personalization.
// Matches Hash::Blake2b in the driver (B2Hash with OutLen=8).

const M64 = 0xFFFFFFFFFFFFFFFFn;

const IV: bigint[] = [
    0x6A09E667F3BCC908n, 0xBB67AE8584CAA73Bn,
    0x3C6EF372FE94F82Bn, 0xA54FF53A5F1D36F1n,
    0x510E527FADE682D1n, 0x9B05688C2B3E6C1Fn,
    0x1F83D9ABFB41BD6Bn, 0x5BE0CD19137E2179n,
];

const SIGMA: number[][] = [
    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
    [14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3],
    [11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4],
    [ 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8],
    [ 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13],
    [ 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9],
    [12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11],
    [13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10],
    [ 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0],
    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
    [14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3],
];

function rotr64(x: bigint, n: bigint): bigint {
    return ((x >> n) | (x << (64n - n))) & M64;
}

function load64le(buf: Uint8Array, off: number): bigint {
    const dv = new DataView(buf.buffer, buf.byteOffset + off, 8);
    return dv.getBigUint64(0, true);
}

function g(v: bigint[], a: number, b: number, c: number, d: number, x: bigint, y: bigint) {
    v[a] = (v[a] + v[b] + x) & M64;
    v[d] = rotr64(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d]) & M64;
    v[b] = rotr64(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + y) & M64;
    v[d] = rotr64(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d]) & M64;
    v[b] = rotr64(v[b] ^ v[c], 63n);
}

function compress(h: bigint[], block: Uint8Array, t0: bigint, t1: bigint, last: boolean) {
    const m: bigint[] = [];
    for (let i = 0; i < 16; i++) m.push(load64le(block, i * 8));

    const v: bigint[] = [...h, ...IV];
    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] ^= M64;

    for (let r = 0; r < 12; r++) {
        const s = SIGMA[r];
        g(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        g(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        g(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        g(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        g(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        g(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

export function blake2b8(data: Uint8Array): bigint {
    const outLen = 8;
    const h = [...IV];
    h[0] ^= 0x01010000n | BigInt(outLen);

    const buf = new Uint8Array(128);
    let bufLen = 0;
    let t = 0n;

    function update(chunk: Uint8Array) {
        let off = 0;
        while (off < chunk.length) {
            if (bufLen === 128) {
                t = (t + 128n) & M64;
                compress(h, buf, t, 0n, false);
                bufLen = 0;
            }
            const take = Math.min(chunk.length - off, 128 - bufLen);
            buf.set(chunk.subarray(off, off + take), bufLen);
            bufLen += take;
            off += take;
        }
    }

    function finalize(): bigint {
        t = (t + BigInt(bufLen)) & M64;
        buf.fill(0, bufLen);
        compress(h, buf, t, 0n, true);
        const out = new DataView(new ArrayBuffer(8));
        // h[0] little-endian → first 8 bytes
        out.setBigUint64(0, h[0], true);
        return out.getBigUint64(0, true);
    }

    update(data);
    return finalize();
}

export function blake2b8Str(name: string, encoding: "utf16le" | "ascii" = "utf16le"): bigint {
    let buf: Uint8Array;
    if (encoding === "utf16le") {
        buf = new Uint8Array(name.length * 2);
        const dv = new DataView(buf.buffer);
        for (let i = 0; i < name.length; i++)
            dv.setUint16(i * 2, name.charCodeAt(i), true);
    } else {
        buf = new Uint8Array(name.length);
        for (let i = 0; i < name.length; i++)
            buf[i] = name.charCodeAt(i) & 0xff;
    }
    return blake2b8(buf);
}
