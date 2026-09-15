import { decryptPayload } from "./crypto";

export const PACKET_MAGIC = 0xac010000;
const HEADER_SIZE = 24;

// Payload layout (all little-endian, #pragma pack(1)):
//   +0   ULONG  identityCount
//   +4   ULONG64[8] hashes (64 bytes)
//   +68  ULONG  diskCount
//   +72  DiskEntry[8]  (each 17 bytes: hashAta:8, hashStorage:8, mismatch:1)
//   +208 SmbiosEntry (240 bytes)
//     +0   UUID[16]
//     +16  systemSerial:8
//     +24  baseboardSerial:8
//     +32  chassisSerial:8
//     +40  processorCount:4
//     +44  processorHashes[8]:64
//     +108 memoryCount:4
//     +112 memoryHashes[16]:128
//   +448 ULONG  networkCount
//   +452 NetworkEntry[2]  (each 17 bytes: hashCurrentMac:8, hashPermanentMac:8, macMismatch:1)
//   +486 DnsData (hashDomain:8, hashHostname:8)
//   Total: 502 bytes

const SMBIOS_OFF   = 208;
const NETWORK_OFF  = 448;

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
  smbios: {
    systemUUID: string;           // 32-char hex
    systemSerial: bigint;
    baseboardSerial: bigint;
    chassisSerial: bigint;
    processorCount: number;
    processorHashes: bigint[];
    memoryCount: number;
    memoryHashes: bigint[];
  };
  network: {
    networkCount: number;
    adapters: { hashCurrentMac: bigint; hashPermanentMac: bigint; macMismatch: boolean }[];
    hashDnsDomain: bigint;
    hashDnsHostname: bigint;
  };
}

function bytesToHex(view: DataView, off: number, len: number): string {
  let s = "";
  for (let i = 0; i < len; i++) {
    s += view.getUint8(off + i).toString(16).padStart(2, "0");
  }
  return s;
}

// Integrity payload layout (all LE, #pragma pack(1)):
//   +0   ULONG  findingCount
//   +4   Finding[8]  each 48 bytes:
//     +0  ULONG64 moduleBase
//     +8  ULONG   offset
//     +12 ULONG   length
//     +16 UCHAR   kind  (1=patch 2=cave 3=rwx 4=unbacked)
//     +17 CHAR[31] moduleName (null-terminated, 0-padded)
//   Total: 4 + 8*48 = 388 bytes

const INTEGRITY_FINDING_SIZE = 48;
const INTEGRITY_MAX_FINDINGS = 8;

export interface IntegrityFinding {
  moduleBase: bigint;
  offset: number;
  length: number;
  kind: number;
  moduleName: string;
}

export interface ParsedIntegrityPacket {
  header: {
    magic: number;
    packetType: number;
    version: number;
    sequence: number;
    timestamp: bigint;
    payloadSize: number;
  };
  findings: IntegrityFinding[];
}

export function parseIntegrityPacket(raw: Uint8Array): ParsedIntegrityPacket {
  if (raw.length < HEADER_SIZE) throw new Error("packet too small");

  const hv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const header = {
    magic:       hv.getUint32(0, true),
    packetType:  hv.getUint16(4, true),
    version:     hv.getUint16(6, true),
    sequence:    hv.getUint32(8, true),
    timestamp:   hv.getBigUint64(12, true),
    payloadSize: hv.getUint32(20, true),
  };

  if (header.magic !== PACKET_MAGIC) throw new Error("bad magic");
  if (header.packetType !== 4) throw new Error("not an integrity packet");
  if (raw.length < HEADER_SIZE + header.payloadSize) throw new Error("truncated");

  const payload = new Uint8Array(header.payloadSize);
  payload.set(raw.subarray(HEADER_SIZE, HEADER_SIZE + header.payloadSize));
  decryptPayload(payload, header.sequence);

  const pv = new DataView(payload.buffer);
  const findingCount = pv.getUint32(0, true);
  const findings: IntegrityFinding[] = [];

  for (let i = 0; i < Math.min(findingCount, INTEGRITY_MAX_FINDINGS); i++) {
    const base = 4 + i * INTEGRITY_FINDING_SIZE;
    const nameBytes: number[] = [];
    for (let j = 0; j < 31; j++) {
      const b = pv.getUint8(base + 17 + j);
      if (b === 0) break;
      nameBytes.push(b);
    }
    findings.push({
      moduleBase: pv.getBigUint64(base,      true),
      offset:     pv.getUint32(base + 8,     true),
      length:     pv.getUint32(base + 12,    true),
      kind:       pv.getUint8(base + 16),
      moduleName: String.fromCharCode(...nameBytes),
    });
  }

  return { header, findings };
}

// Drivers payload layout (all LE, #pragma pack(1)):
//   +0  ULONG driverCount
//   +4  DriverEntry[count]  each 17 bytes: hashPath:8, hashName:8, isUnloaded:1
//   Max 29 entries = 4 + 29*17 = 497 bytes

const DRIVERS_ENTRY_SIZE = 13;
const DRIVERS_MAX        = 39;

export interface ParsedDriverEntry {
  hashName: bigint;
  timeDateStamp: number;
  isUnloaded: boolean;
}

export interface ParsedDriversPacket {
  header: {
    magic: number;
    packetType: number;
    version: number;
    sequence: number;
    timestamp: bigint;
    payloadSize: number;
  };
  drivers: ParsedDriverEntry[];
}

export function parseDriversPacket(raw: Uint8Array): ParsedDriversPacket {
  if (raw.length < HEADER_SIZE) throw new Error("packet too small");

  const hv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const header = {
    magic:       hv.getUint32(0, true),
    packetType:  hv.getUint16(4, true),
    version:     hv.getUint16(6, true),
    sequence:    hv.getUint32(8, true),
    timestamp:   hv.getBigUint64(12, true),
    payloadSize: hv.getUint32(20, true),
  };

  if (header.magic !== PACKET_MAGIC) throw new Error("bad magic");
  if (header.packetType !== 5) throw new Error("not a drivers packet");
  if (raw.length < HEADER_SIZE + header.payloadSize) throw new Error("truncated");

  const payload = new Uint8Array(header.payloadSize);
  payload.set(raw.subarray(HEADER_SIZE, HEADER_SIZE + header.payloadSize));
  decryptPayload(payload, header.sequence);

  const pv = new DataView(payload.buffer);
  const driverCount = pv.getUint32(0, true);
  const drivers: ParsedDriverEntry[] = [];

  for (let i = 0; i < Math.min(driverCount, DRIVERS_MAX); i++) {
    const base = 4 + i * DRIVERS_ENTRY_SIZE;
    drivers.push({
      hashName:     pv.getBigUint64(base,     true),
      timeDateStamp: pv.getUint32(base + 8,   true),
      isUnloaded:   pv.getUint8(base + 12) !== 0,
    });
  }

  return { header, drivers };
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

  const so = SMBIOS_OFF;
  const systemUUID = bytesToHex(pv, so, 16);
  const systemSerial = pv.getBigUint64(so + 16, true);
  const baseboardSerial = pv.getBigUint64(so + 24, true);
  const chassisSerial = pv.getBigUint64(so + 32, true);
  const processorCount = pv.getUint32(so + 40, true);
  const processorHashes: bigint[] = [];
  for (let i = 0; i < Math.min(processorCount, 8); i++) {
    processorHashes.push(pv.getBigUint64(so + 44 + i * 8, true));
  }
  const memoryCount = pv.getUint32(so + 108, true);
  const memoryHashes: bigint[] = [];
  for (let i = 0; i < Math.min(memoryCount, 16); i++) {
    memoryHashes.push(pv.getBigUint64(so + 112 + i * 8, true));
  }

  const no = NETWORK_OFF;
  const networkCount = pv.getUint32(no, true);
  const adapters: ParsedPacket["network"]["adapters"] = [];
  for (let i = 0; i < Math.min(networkCount, 2); i++) {
    const base = no + 4 + i * 17;
    adapters.push({
      hashCurrentMac:   pv.getBigUint64(base,      true),
      hashPermanentMac: pv.getBigUint64(base + 8,  true),
      macMismatch:      pv.getUint8(base + 16) !== 0,
    });
  }
  const hashDnsDomain   = pv.getBigUint64(no + 4 + 2 * 17,     true);
  const hashDnsHostname = pv.getBigUint64(no + 4 + 2 * 17 + 8, true);

  return {
    header,
    hwid: { identityCount, hashes, diskCount, disks },
    smbios: {
      systemUUID,
      systemSerial,
      baseboardSerial,
      chassisSerial,
      processorCount,
      processorHashes,
      memoryCount,
      memoryHashes,
    },
    network: { networkCount, adapters, hashDnsDomain, hashDnsHostname },
  };
}
