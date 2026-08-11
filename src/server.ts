/**
 * Vault API — secure secrets service
 */

import Fastify from "fastify";
import fjwt from "@fastify/jwt";
import rateLimit from "@fastify/rate-limit";
import { authRoutes } from "./routes/auth.js";
import { secretRoutes } from "./routes/secrets.js";
import { auditRoutes } from "./routes/audit.js";

declare module "fastify" {
  interface FastifyInstance {
    authenticate: (req: any, reply: any) => Promise<void>;
  }
}

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: { sub: string; email: string; role: string };
    user: { sub: string; email: string; role: string };
  }
}

const PORT = Number(process.env.PORT ?? 3080);
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-only-change-me-in-production";

async function main() {
  const app = Fastify({
    logger: true,
    trustProxy: true,
  });

  await app.register(rateLimit, {
    max: 100,
    timeWindow: "1 minute",
  });

  await app.register(fjwt, {
    secret: JWT_SECRET,
    sign: { expiresIn: "8h" },
  });

  app.decorate("authenticate", async function (req: any, reply: any) {
    try {
      await req.jwtVerify();
    } catch {
      return reply.code(401).send({ error: "Unauthorized" });
    }
  });

  app.get("/health", async () => ({
    status: "ok",
    service: "vault-api",
    ts: new Date().toISOString(),
  }));

  await app.register(authRoutes);
  await app.register(secretRoutes);
  await app.register(auditRoutes);

  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`Vault API listening on :${PORT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
