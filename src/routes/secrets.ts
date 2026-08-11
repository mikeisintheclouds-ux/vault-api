import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  createSecret,
  getSecret,
  listSecrets,
  updateSecret,
  deleteSecret,
} from "../lib/store.js";

const createBody = z.object({
  name: z.string().min(1).max(128),
  value: z.string().min(1).max(64_000),
});

const updateBody = z.object({
  value: z.string().min(1).max(64_000),
});

export async function secretRoutes(app: FastifyInstance) {
  app.addHook("onRequest", app.authenticate);

  app.get("/secrets", async () => {
    return { secrets: listSecrets() };
  });

  app.post("/secrets", async (req, reply) => {
    const parsed = createBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: parsed.error.flatten() });
    }
    const userId = (req.user as { sub: string }).sub;
    const meta = createSecret(parsed.data.name, parsed.data.value, userId);
    return reply.code(201).send({ secret: meta });
  });

  app.get<{ Params: { id: string } }>("/secrets/:id", async (req, reply) => {
    const userId = (req.user as { sub: string }).sub;
    const result = getSecret(req.params.id, userId, req.ip);
    if (!result) return reply.code(404).send({ error: "Secret not found" });
    return {
      secret: result.meta,
      value: result.value,
    };
  });

  app.put<{ Params: { id: string } }>("/secrets/:id", async (req, reply) => {
    const parsed = updateBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: parsed.error.flatten() });
    }
    const userId = (req.user as { sub: string }).sub;
    const meta = updateSecret(req.params.id, parsed.data.value, userId);
    if (!meta) return reply.code(404).send({ error: "Secret not found" });
    return { secret: meta };
  });

  app.delete<{ Params: { id: string } }>("/secrets/:id", async (req, reply) => {
    const userId = (req.user as { sub: string }).sub;
    const ok = deleteSecret(req.params.id, userId);
    if (!ok) return reply.code(404).send({ error: "Secret not found" });
    return reply.code(204).send();
  });
}
