import { db } from "../db/client";
import { sessions, users } from "../db/schema";
import { eq } from "drizzle-orm";

export async function stopSession(sessionId: string, reason: string): Promise<void> {
  await db.update(sessions)
    .set({ status: "stopped", stopReason: reason, endedAt: Math.floor(Date.now() / 1000) })
    .where(eq(sessions.id, sessionId));
}

export async function banUser(userId: string, reason: string): Promise<void> {
  await db.update(users)
    .set({ bannedAt: Math.floor(Date.now() / 1000), banReason: reason })
    .where(eq(users.id, userId));
}
