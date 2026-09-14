import { Hono } from "hono";
import { and, eq } from "drizzle-orm";
import { db } from "../db/client";
import { sessions, users, hwidBans } from "../db/schema";
import { auth } from "../middleware/auth";
import { clearHeartbeat } from "../services/watchdog";

const router = new Hono<{ Variables: { userId: string } }>();

router.use("*", auth);

router.post("/start", async (c) => {
  const userId = c.get("userId");

  const [user] = await db.select({ bannedAt: users.bannedAt, hwidFingerprint: users.hwidFingerprint })
    .from(users).where(eq(users.id, userId)).limit(1);
  if (!user) return c.json({ error: "user not found" }, 404);
  if (user.bannedAt) return c.json({ error: "banned" }, 403);

  if (user.hwidFingerprint) {
    const [hwidBan] = await db.select({ fingerprint: hwidBans.fingerprint })
      .from(hwidBans).where(eq(hwidBans.fingerprint, user.hwidFingerprint)).limit(1);
    if (hwidBan) return c.json({ error: "banned" }, 403);
  }

  const [active] = await db.select({ id: sessions.id })
    .from(sessions)
    .where(and(eq(sessions.userId, userId), eq(sessions.status, "active")))
    .limit(1);
  if (active) return c.json({ error: "session already active", sessionId: active.id }, 409);

  const id = crypto.randomUUID();
  const token = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  await db.insert(sessions).values({ id, userId, token, startedAt: now, lastHeartbeat: now });

  return c.json({ sessionId: id, token }, 201);
});

router.post("/:id/end", async (c) => {
  const userId = c.get("userId");
  const sessionId = c.req.param("id");

  const [session] = await db.select({ status: sessions.status })
    .from(sessions)
    .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId)))
    .limit(1);

  if (!session) return c.json({ error: "not found" }, 404);
  if (session.status !== "active") return c.json({ error: "session not active" }, 409);

  clearHeartbeat(sessionId);
  await db.update(sessions)
    .set({ status: "completed", endedAt: Math.floor(Date.now() / 1000) })
    .where(eq(sessions.id, sessionId));

  return c.json({ ok: true });
});

export default router;
