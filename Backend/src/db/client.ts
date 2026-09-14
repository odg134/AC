import { Database } from "bun:sqlite";
import { drizzle } from "drizzle-orm/bun-sqlite";
import * as schema from "./schema";
import { mkdirSync } from "fs";

mkdirSync("data", { recursive: true });

const sqlite = new Database("data/ac.db");
sqlite.exec("PRAGMA journal_mode = WAL");
sqlite.exec("PRAGMA foreign_keys = ON");
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    hwid_fingerprint TEXT,
    created_at INTEGER NOT NULL,
    banned_at INTEGER,
    ban_reason TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token TEXT NOT NULL UNIQUE,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    stop_reason TEXT,
    last_heartbeat INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS telemetry (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    sequence INTEGER NOT NULL,
    packet_timestamp INTEGER NOT NULL,
    identity_count INTEGER NOT NULL,
    identity_hashes TEXT NOT NULL,
    disk_count INTEGER NOT NULL,
    disks TEXT NOT NULL,
    received_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS hwid_bans (
    fingerprint TEXT PRIMARY KEY,
    banned_at INTEGER NOT NULL,
    reason TEXT
  );
  CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    type TEXT NOT NULL,
    detail TEXT NOT NULL,
    detected_at INTEGER NOT NULL
  );
`);

export const db = drizzle(sqlite, { schema });
