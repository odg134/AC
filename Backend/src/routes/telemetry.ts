import { Hono } from "hono";
import { and, desc, eq } from "drizzle-orm";
import { db } from "../db/client";
import { sessions, telemetry, users } from "../db/schema";
import { parsePacket } from "../packet/parse";
import { recordDetection } from "../services/detection";
import { resetHeartbeat } from "../services/watchdog";

const router = new Hono();

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
  const hashes = pkt.hwid.hashes.map((h) => h.toString(16).padStart(16, "0"));
  const sortedFp = [...hashes].sort().join(",");

  await db.insert(telemetry).values({
    id: crypto.randomUUID(),
    sessionId: session.id,
    sequence: pkt.header.sequence,
    packetTimestamp: pkt.header.timestamp,
    identityCount: pkt.hwid.identityCount,
    identityHashes: JSON.stringify(hashes),
    diskCount: pkt.hwid.diskCount,
    disks: JSON.stringify(
      pkt.hwid.disks.map((d) => ({
        ata: d.hashAta.toString(16).padStart(16, "0"),
        storage: d.hashStorage.toString(16).padStart(16, "0"),
        mismatch: d.mismatch,
      })),
    ),
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
          ata: d.hashAta.toString(16).padStart(16, "0"),
          storage: d.hashStorage.toString(16).padStart(16, "0"),
        })),
    });
    return c.json({ ok: false, reason: "disk_mismatch" });
  }

  return c.json({ ok: true });
});

export default router;
