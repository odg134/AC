import { decryptPayload } from "./crypto";

export const PACKET_MAGIC = 0xac010000;
const HEADER_SIZE = 24;

export interface ParsedPacket {
  header: {
    magic: number;
    packetType: number;
    version: number;
    sequence: number;
    timestamp: bigint;
    payloadSize: number;
  };
  hwid: {
    identityCount: number;
    hashes: bigint[];
    diskCount: number;
    disks: { hashAta: bigint; hashStorage: bigint; mismatch: boolean }[];
  };
}

export function parsePacket(raw: Uint8Array): ParsedPacket {
  if (raw.length < HEADER_SIZE) throw new Error("packet too small");

  const hv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const header = {
    magic: hv.getUint32(0, true),
    packetType: hv.getUint16(4, true),
    version: hv.getUint16(6, true),
    sequence: hv.getUint32(8, true),
    timestamp: hv.getBigUint64(12, true),
    payloadSize: hv.getUint32(20, true),
  };

  if (header.magic !== PACKET_MAGIC) throw new Error("bad magic");
  if (header.packetType !== 1) throw new Error("unknown type");
  if (raw.length < HEADER_SIZE + header.payloadSize) throw new Error("truncated");

  const payload = new Uint8Array(header.payloadSize);
  payload.set(raw.subarray(HEADER_SIZE, HEADER_SIZE + header.payloadSize));
  decryptPayload(payload, header.sequence);

  const pv = new DataView(payload.buffer);
  const identityCount = pv.getUint32(0, true);
  const hashes: bigint[] = [];
  for (let i = 0; i < Math.min(identityCount, 8); i++) {
    hashes.push(pv.getBigUint64(4 + i * 8, true));
  }

  const diskCount = pv.getUint32(68, true);
  const disks: ParsedPacket["hwid"]["disks"] = [];
  for (let i = 0; i < Math.min(diskCount, 8); i++) {
    const base = 72 + i * 17;
    disks.push({
      hashAta: pv.getBigUint64(base, true),
      hashStorage: pv.getBigUint64(base + 8, true),
      mismatch: pv.getUint8(base + 16) !== 0,
    });
  }

  return { header, hwid: { identityCount, hashes, diskCount, disks } };
}
