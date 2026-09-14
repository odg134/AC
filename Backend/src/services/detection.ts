import { db } from "../db/client";
import { detections } from "../db/schema";
import { banUser, stopSession } from "./session";

type DetectionType =
  | "disk_mismatch"
  | "hwid_change"
  | "telemetry_timeout"
  | "replay_attack"
  | "driver_patch"
  | "code_cave"
  | "rwx_region"
  | "unbacked_exec";

const BAN_TYPES: DetectionType[] = ["disk_mismatch", "hwid_change", "replay_attack",
  "driver_patch", "code_cave", "rwx_region", "unbacked_exec"];

export async function recordDetection(
  sessionId: string,
  userId: string,
  type: DetectionType,
  detail: object,
): Promise<void> {
  await db.insert(detections).values({
    id: crypto.randomUUID(),
    sessionId,
    userId,
    type,
    detail: JSON.stringify(detail),
    detectedAt: Math.floor(Date.now() / 1000),
  });

  if (BAN_TYPES.includes(type)) await banUser(userId, type);
  await stopSession(sessionId, type);
}
