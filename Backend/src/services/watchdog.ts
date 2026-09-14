import { stopSession } from "./session";
import { recordDetection } from "./detection";

const TIMEOUT_MS = 30_000;
const timers = new Map<string, ReturnType<typeof setTimeout>>();

export function resetHeartbeat(sessionId: string, userId: string): void {
  const existing = timers.get(sessionId);
  if (existing) clearTimeout(existing);

  timers.set(
    sessionId,
    setTimeout(async () => {
      timers.delete(sessionId);
      await recordDetection(sessionId, userId, "telemetry_timeout", {});
    }, TIMEOUT_MS),
  );
}

export function clearHeartbeat(sessionId: string): void {
  const t = timers.get(sessionId);
  if (t) { clearTimeout(t); timers.delete(sessionId); }
}
