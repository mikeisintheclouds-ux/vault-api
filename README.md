# Vault API

**Secure secrets vault REST API** — JWT auth, rate limiting, AES-256-GCM encryption at rest, full audit log.

Portfolio-grade backend: the patterns you want in a production secrets or config service.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)
[![Fastify](https://img.shields.io/badge/Fastify-5-black)](https://fastify.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

| Capability | Implementation |
|------------|----------------|
| Auth | JWT (`@fastify/jwt`), 8h expiry |
| Rate limit | 100 req/min per IP |
| Encryption | AES-256-GCM, random IV per secret |
| Audit | Append-only log: login, create, read, update, delete |
| Validation | Zod on all write bodies |
| RBAC | Admin-only `/audit`; operators manage secrets |
| Health | `GET /health` |

## Quick start

```bash
git clone https://github.com/mikeisintheclouds-ux/vault-api.git
cd vault-api && npm install
cp .env.example .env
npm run dev
```

Demo users: `admin@vault.local` / `admin-change-me` (admin), `ops@vault.local` / `ops-change-me` (operator).

## API

```bash
# Login
curl -s -X POST http://localhost:3080/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@vault.local","password":"admin-change-me"}'

# Create secret
curl -s -X POST http://localhost:3080/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"db-password","value":"s3cret"}'
```

## License

MIT © Mike O'Connor
