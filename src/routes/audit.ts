import type { FastifyInstance } from "fastify";
import { getAuditLog } from "../lib/store.js";

export async function auditRoutes(app: FastifyInstance) {
  app.get(
    "/audit",
    { onRequest: [app.authenticate] },
    async (req, reply) => {
      const user = req.user as { role?: string };
      if (user.role !== "admin") {
        return reply.code(403).send({ error: "Admin role required" });
      }
      const limit = Math.min(
        Number((req.query as { limit?: string }).limit ?? 100),
        500
      );
      return { entries: getAuditLog(limit) };
    }
  );
}
