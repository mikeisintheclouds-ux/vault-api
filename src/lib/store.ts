/**
 * In-memory secret store with audit trail.
 * Swap for Postgres/SQLite in production — interface stays the same.
 */

import { randomUUID } from "node:crypto";
import { encrypt, decrypt } from "./crypto.js";

export interface SecretMeta {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  version: number;
}

export interface AuditEntry {
  id: string;
  action: "create" | "read" | "update" | "delete" | "login" | "login_failed";
  secretId?: string;
  userId: string;
  ip?: string;
  at: string;
}

interface StoredSecret extends SecretMeta {
  ciphertext: string;
}

const secrets = new Map<string, StoredSecret>();
const audit: AuditEntry[] = [];
const MAX_AUDIT = 10_000;

function pushAudit(entry: Omit<AuditEntry, "id" | "at">) {
  audit.unshift({
    ...entry,
    id: randomUUID(),
    at: new Date().toISOString(),
  });
  if (audit.length > MAX_AUDIT) audit.length = MAX_AUDIT;
}

export function createSecret(
  name: string,
  value: string,
  userId: string
): SecretMeta {
  const id = randomUUID();
  const now = new Date().toISOString();
  const record: StoredSecret = {
    id,
    name,
    ciphertext: encrypt(value),
    createdAt: now,
    updatedAt: now,
    createdBy: userId,
    version: 1,
  };
  secrets.set(id, record);
  pushAudit({ action: "create", secretId: id, userId });
  const { ciphertext: _, ...meta } = record;
  return meta;
}

export function getSecret(
  id: string,
  userId: string,
  ip?: string
): { meta: SecretMeta; value: string } | null {
  const record = secrets.get(id);
  if (!record) return null;
  pushAudit({ action: "read", secretId: id, userId, ip });
  const { ciphertext, ...meta } = record;
  return { meta, value: decrypt(ciphertext) };
}

export function listSecrets(): SecretMeta[] {
  return [...secrets.values()].map(({ ciphertext: _, ...meta }) => meta);
}

export function updateSecret(
  id: string,
  value: string,
  userId: string
): SecretMeta | null {
  const record = secrets.get(id);
  if (!record) return null;
  record.ciphertext = encrypt(value);
  record.updatedAt = new Date().toISOString();
  record.version += 1;
  pushAudit({ action: "update", secretId: id, userId });
  const { ciphertext: _, ...meta } = record;
  return meta;
}

export function deleteSecret(id: string, userId: string): boolean {
  const ok = secrets.delete(id);
  if (ok) pushAudit({ action: "delete", secretId: id, userId });
  return ok;
}

export function getAuditLog(limit = 100): AuditEntry[] {
  return audit.slice(0, limit);
}

export function recordLogin(userId: string, ok: boolean, ip?: string) {
  pushAudit({
    action: ok ? "login" : "login_failed",
    userId,
    ip,
  });
}
