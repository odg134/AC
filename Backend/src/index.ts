import { Hono } from "hono";
import { logger } from "hono/logger";
import userRoutes from "./routes/users";
import sessionRoutes from "./routes/sessions";
import telemetryRoutes from "./routes/telemetry";
import moduleRoutes from "./routes/module";

const app = new Hono();

app.use("*", logger());

app.route("/users", userRoutes);
app.route("/sessions", sessionRoutes);
app.route("/telemetry", telemetryRoutes);
app.route("/module", moduleRoutes);

app.get("/health", (c) => c.json({ status: "ok" }));

export default {
  port: 3000,
  fetch: app.fetch,
};
