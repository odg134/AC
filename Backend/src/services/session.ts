import { db } from "../db/client";
import { sessions, users, hwidBans } from "../db/schema";
import { eq } from "drizzle-orm";

export async function stopSession(sessionId: string, reason: string): Promise<void> {
  await db.update(sessions)
    .set({ status: "stopped", stopReason: reason, endedAt: Math.floor(Date.now() / 1000) })
    .where(eq(sessions.id, sessionId));
}

export async function banUser(userId: string, reason: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);

  await db.update(users)
    .set({ bannedAt: now, banReason: reason })
    .where(eq(users.id, userId));

  const [user] = await db.select({ hwidFingerprint: users.hwidFingerprint })
    .from(users).where(eq(users.id, userId)).limit(1);

  if (user?.hwidFingerprint) {
    await db.insert(hwidBans)
      .values({ fingerprint: user.hwidFingerprint, bannedAt: now, reason })
      .onConflictDoNothing();
  }
}
