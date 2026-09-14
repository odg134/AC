import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  hwidFingerprint: text("hwid_fingerprint"),
  createdAt: integer("created_at").notNull(),
  bannedAt: integer("banned_at"),
  banReason: text("ban_reason"),
});

export const sessions = sqliteTable("sessions", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id),
  token: text("token").notNull().unique(),
  startedAt: integer("started_at").notNull(),
  endedAt: integer("ended_at"),
  status: text("status").notNull().default("active"),
  stopReason: text("stop_reason"),
  lastHeartbeat: integer("last_heartbeat").notNull(),
});

export const telemetry = sqliteTable("telemetry", {
  id: text("id").primaryKey(),
  sessionId: text("session_id").notNull().references(() => sessions.id),
  sequence: integer("sequence").notNull(),
  packetTimestamp: integer("packet_timestamp", { mode: "bigint" }).notNull(),
  identityCount: integer("identity_count").notNull(),
  identityHashes: text("identity_hashes").notNull(),
  diskCount: integer("disk_count").notNull(),
  disks: text("disks").notNull(),
  receivedAt: integer("received_at").notNull(),
});

export const hwidBans = sqliteTable("hwid_bans", {
  fingerprint: text("fingerprint").primaryKey(),
  bannedAt: integer("banned_at").notNull(),
  reason: text("reason"),
});

export const detections = sqliteTable("detections", {
  id: text("id").primaryKey(),
  sessionId: text("session_id").notNull().references(() => sessions.id),
  userId: text("user_id").notNull().references(() => users.id),
  type: text("type").notNull(),
  detail: text("detail").notNull(),
  detectedAt: integer("detected_at").notNull(),
});
