import { Hono } from "hono";
import { and, desc, eq } from "drizzle-orm";
import { db } from "../db/client";
import { sessions, telemetry, users, hwidBans } from "../db/schema";
import { parsePacket } from "../packet/parse";
import { recordDetection } from "../services/detection";
import { resetHeartbeat } from "../services/watchdog";

const router = new Hono();

function hashHex(h: bigint): string {
  return h.toString(16).padStart(16, "0");
}

function buildFingerprint(pkt: ReturnType<typeof parsePacket>): string {
  const all: string[] = [
    ...pkt.hwid.hashes.map(hashHex),
    hashHex(pkt.smbios.systemSerial),
    hashHex(pkt.smbios.baseboardSerial),
    hashHex(pkt.smbios.chassisSerial),
    ...pkt.smbios.processorHashes.map(hashHex),
    ...pkt.smbios.memoryHashes.map(hashHex),
    // Permanent MAC is the burned-in hardware address; current MAC may be spoofed.
    ...pkt.network.adapters.map((a) => hashHex(a.hashPermanentMac)),
  ].filter((h) => h !== "0000000000000000");

  return [...all].sort().join(",");
}

router.post("/:token", async (c) => {
  const token = c.req.param("token");

  const [session] = await db.select()
    .from(sessions)
    .where(and(eq(sessions.token, token), eq(sessions.status, "active")))
    .limit(1);
  if (!session) return c.json({ error: "invalid session" }, 404);

  let pkt;
  try {
    pkt = parsePacket(new Uint8Array(await c.req.arrayBuffer()));
  } catch {
    return c.json({ error: "bad packet" }, 400);
  }

  const [last] = await db.select({ sequence: telemetry.sequence })
    .from(telemetry)
    .where(eq(telemetry.sessionId, session.id))
    .orderBy(desc(telemetry.sequence))
    .limit(1);

  if (last && pkt.header.sequence <= last.sequence) {
    await recordDetection(session.id, session.userId, "replay_attack", {
      expected: last.sequence + 1,
      got: pkt.header.sequence,
    });
    return c.json({ ok: false, reason: "replay" }, 400);
  }

  const now = Math.floor(Date.now() / 1000);
  const sortedFp = buildFingerprint(pkt);

  const smbiosJson = JSON.stringify({
    uuid: pkt.smbios.systemUUID,
    systemSerial: hashHex(pkt.smbios.systemSerial),
    baseboardSerial: hashHex(pkt.smbios.baseboardSerial),
    chassisSerial: hashHex(pkt.smbios.chassisSerial),
    processors: pkt.smbios.processorHashes.map(hashHex),
    memory: pkt.smbios.memoryHashes.map(hashHex),
  });

  const networkJson = JSON.stringify({
    adapters: pkt.network.adapters.map((a) => ({
      currentMac:   hashHex(a.hashCurrentMac),
      permanentMac: hashHex(a.hashPermanentMac),
      macMismatch:  a.macMismatch,
    })),
    dnsDomain:   hashHex(pkt.network.hashDnsDomain),
    dnsHostname: hashHex(pkt.network.hashDnsHostname),
  });

  await db.insert(telemetry).values({
    id: crypto.randomUUID(),
    sessionId: session.id,
    sequence: pkt.header.sequence,
    packetTimestamp: pkt.header.timestamp,
    identityCount: pkt.hwid.identityCount,
    identityHashes: JSON.stringify(pkt.hwid.hashes.map(hashHex)),
    diskCount: pkt.hwid.diskCount,
    disks: JSON.stringify(
      pkt.hwid.disks.map((d) => ({
        ata: hashHex(d.hashAta),
        storage: hashHex(d.hashStorage),
        mismatch: d.mismatch,
      })),
    ),
    smbios: smbiosJson,
    network: networkJson,
    receivedAt: now,
  });

  await db.update(sessions).set({ lastHeartbeat: now }).where(eq(sessions.id, session.id));
  resetHeartbeat(session.id, session.userId);

  const [user] = await db.select({ hwidFingerprint: users.hwidFingerprint })
    .from(users)
    .where(eq(users.id, session.userId))
    .limit(1);
  if (!user) return c.json({ error: "user not found" }, 500);

  if (!user.hwidFingerprint) {
    const [hwidBan] = await db.select({ fingerprint: hwidBans.fingerprint })
      .from(hwidBans).where(eq(hwidBans.fingerprint, sortedFp)).limit(1);
    if (hwidBan) {
      await recordDetection(session.id, session.userId, "hwid_change", { reason: "hwid_banned" });
      return c.json({ ok: false, reason: "hwid_banned" });
    }
    await db.update(users).set({ hwidFingerprint: sortedFp }).where(eq(users.id, session.userId));
  } else if (user.hwidFingerprint !== sortedFp) {
    await recordDetection(session.id, session.userId, "hwid_change", {
      stored: user.hwidFingerprint,
      received: sortedFp,
    });
    return c.json({ ok: false, reason: "hwid_change" });
  }

  if (pkt.hwid.disks.some((d) => d.mismatch)) {
    await recordDetection(session.id, session.userId, "disk_mismatch", {
      disks: pkt.hwid.disks
        .filter((d) => d.mismatch)
        .map((d) => ({
          ata: hashHex(d.hashAta),
          storage: hashHex(d.hashStorage),
        })),
    });
    return c.json({ ok: false, reason: "disk_mismatch" });
  }

  if (pkt.network.adapters.some((a) => a.macMismatch)) {
    await recordDetection(session.id, session.userId, "mac_spoof", {
      adapters: pkt.network.adapters
        .filter((a) => a.macMismatch)
        .map((a) => ({
          currentMac:   hashHex(a.hashCurrentMac),
          permanentMac: hashHex(a.hashPermanentMac),
        })),
    });
    return c.json({ ok: false, reason: "mac_spoof" });
  }

  return c.json({ ok: true });
});

export default router;
