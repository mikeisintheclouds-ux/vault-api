/**
 * Demo user store. Replace with real IdP / DB in production.
 */

import { createHash, timingSafeEqual } from "node:crypto";

export interface User {
  id: string;
  email: string;
  role: "admin" | "operator";
}

const users: Array<User & { passwordHash: string }> = [
  {
    id: "usr_admin",
    email: "admin@vault.local",
    role: "admin",
    passwordHash: hash("admin-change-me"),
  },
  {
    id: "usr_ops",
    email: "ops@vault.local",
    role: "operator",
    passwordHash: hash("ops-change-me"),
  },
];

function hash(password: string): string {
  return createHash("sha256").update(password).digest("hex");
}

export function authenticate(
  email: string,
  password: string
): User | null {
  const user = users.find((u) => u.email === email);
  if (!user) return null;
  const attempt = Buffer.from(hash(password));
  const stored = Buffer.from(user.passwordHash);
  if (attempt.length !== stored.length || !timingSafeEqual(attempt, stored)) {
    return null;
  }
  return { id: user.id, email: user.email, role: user.role };
}
