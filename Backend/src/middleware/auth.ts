import { createMiddleware } from "hono/factory";
import { verify } from "hono/jwt";

export const JWT_SECRET = process.env.JWT_SECRET ?? "change-me";

export const auth = createMiddleware<{ Variables: { userId: string } }>(async (c, next) => {
  const header = c.req.header("Authorization");
  if (!header?.startsWith("Bearer ")) return c.json({ error: "unauthorized" }, 401);

  try {
    const payload = await verify(header.slice(7), JWT_SECRET);
    c.set("userId", payload.sub as string);
    await next();
  } catch {
    return c.json({ error: "unauthorized" }, 401);
  }
});
