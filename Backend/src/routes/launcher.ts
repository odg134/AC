import { Hono } from "hono";
import { readFileSync, existsSync } from "fs";
import { auth } from "../middleware/auth";
import { encryptBuffer, LAUNCHER_KEY } from "../packet/crypto";

const LAUNCHER_PATH = "assets/launcher.dll";

const router = new Hono<{ Variables: { userId: string } }>();

router.use("*", auth);

router.get("/", (c) => {
  if (!existsSync(LAUNCHER_PATH)) return c.json({ error: "launcher not available" }, 503);

  const dll = readFileSync(LAUNCHER_PATH);
  const payload = encryptBuffer(new Uint8Array(dll), LAUNCHER_KEY);

  return c.body(payload, 200, {
    "Content-Type": "application/octet-stream",
    "Content-Length": String(payload.byteLength),
  });
});

export default router;
