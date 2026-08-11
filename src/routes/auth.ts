import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { authenticate } from "../lib/users.js";
import { recordLogin } from "../lib/store.js";

const loginBody = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export async function authRoutes(app: FastifyInstance) {
  app.post("/auth/login", async (req, reply) => {
    const parsed = loginBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid credentials payload" });
    }
    const { email, password } = parsed.data;
    const ip = req.ip;
    const user = authenticate(email, password);
    if (!user) {
      recordLogin(email, false, ip);
      return reply.code(401).send({ error: "Invalid email or password" });
    }
    recordLogin(user.id, true, ip);
    const token = await reply.jwtSign({
      sub: user.id,
      email: user.email,
      role: user.role,
    });
    return { token, user: { id: user.id, email: user.email, role: user.role } };
  });

  app.get(
    "/auth/me",
    { onRequest: [app.authenticate] },
    async (req) => {
      return { user: req.user };
    }
  );
}
