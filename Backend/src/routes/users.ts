import { Hono } from "hono";
import { sign } from "hono/jwt";
import { eq } from "drizzle-orm";
import { db } from "../db/client";
import { users } from "../db/schema";
import { JWT_SECRET } from "../middleware/auth";

const router = new Hono();

router.post("/register", async (c) => {
  const { username, password } = await c.req.json();
  if (!username || !password) return c.json({ error: "missing fields" }, 400);

  const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.username, username)).limit(1);
  if (existing) return c.json({ error: "username taken" }, 409);

  const id = crypto.randomUUID();
  await db.insert(users).values({
    id,
    username,
    passwordHash: await Bun.password.hash(password),
    createdAt: Math.floor(Date.now() / 1000),
  });

  return c.json({ id }, 201);
});

router.post("/login", async (c) => {
  const { username, password } = await c.req.json();
  const [user] = await db.select().from(users).where(eq(users.username, username)).limit(1);

  if (!user || !(await Bun.password.verify(password, user.passwordHash))) {
    return c.json({ error: "invalid credentials" }, 401);
  }
  if (user.bannedAt) return c.json({ error: "banned", reason: user.banReason }, 403);

  const token = await sign(
    { sub: user.id, exp: Math.floor(Date.now() / 1000) + 86400 },
    JWT_SECRET,
  );

  return c.json({ token });
});

export default router;
