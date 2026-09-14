import { Hono } from "hono";
import { readFileSync, existsSync } from "fs";
import { auth } from "../middleware/auth";
import { encryptBuffer, MODULE_KEY } from "../packet/crypto";

const MODULE_PATH = "assets/module.dll";

const router = new Hono<{ Variables: { userId: string } }>();

router.use("*", auth);

router.get("/", (c) => {
  if (!existsSync(MODULE_PATH)) return c.json({ error: "module not available" }, 503);

  const dll = readFileSync(MODULE_PATH);
  const payload = encryptBuffer(new Uint8Array(dll), MODULE_KEY);

  return c.body(payload, 200, {
    "Content-Type": "application/octet-stream",
    "Content-Length": String(payload.byteLength),
  });
});

export default router;
