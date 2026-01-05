## ZedAuth

ZedAuth is a Rust authentication microservice built to demonstrate a **production-grade auth flow** in a compact codebase: access JWTs, HttpOnly refresh cookies, refresh-token rotation, reuse detection, and server-side session revocation.

### Table of Contents

- [Overview](#overview)
- [Why Rust](#why-rust)
- [Architecture](#architecture)
- [Quickstart (local)](#quickstart-local)
- [API](#api)
  - [Auth](#auth)
  - [Users](#users)
  - [Health](#health)
- [Security model](#security-model)
- [Testing and CI](#testing-and-ci)
- [Configuration](#configuration)
- [License](#license)

### Overview

What this project showcases:
- **Access JWT + session id (`sid`)**: stateless auth at the edge, with server-side revocation.
- **Refresh token in HttpOnly cookie**: refresh never goes into local storage.
- **Rotation + reuse revocation**: old rotated refresh tokens revoke the session.
- **Typed auth context**: protected handlers require `AuthContext` (Axum extractor).
- **Unit + integration tests**: DB-backed tests run with `DATABASE_URL`; CI boots Postgres.

### Why Rust

I chose Rust for an auth microservice because it optimizes for **correctness and reliability under concurrency**:
- **Memory safety**: eliminates whole classes of vulnerabilities (use-after-free, null deref) that are especially painful in security-critical services.
- **Data-race prevention**: safe concurrency patterns are enforced by the type system; shared state is explicit and thread-safe.
- **Predictable performance**: minimal runtime overhead; real costs are in crypto (Argon2/JWT) and I/O (Postgres), not a GC/runtime.
- **Explicit error handling**: failures are explicit `Result` paths; auth failures return clear HTTP status codes.

### Architecture

- **Framework**: Axum (Rust)
- **DB**: Postgres via SQLx
- **Access tokens**: JWT (HMAC secret) with claims:
  - `sub`: user id
  - `sid`: session id
  - `exp/iat`
- **Refresh tokens**: opaque random token stored in an **HttpOnly cookie** (`refresh_token`)
  - Stored server-side as a **hash** (`sessions.refresh_token_hash`)
  - Rotated on each refresh
  - Reuse detection via `previous_refresh_token_hash` → **session revoked**

### Quickstart (local)

Prereqs:
- Rust (stable)
- Postgres

1) Create env file:

```bash
cp env.example .env
```

2) Update `.env` values as needed (the service loads `.env` automatically on startup). Minimum required:

```bash
APP_ENVIRONMENT=local
APP_DATABASE__USERNAME=postgres
APP_DATABASE__PASSWORD=your_db_password
APP_DATABASE__HOST=localhost
APP_DATABASE__PORT=5432
APP_DATABASE__DATABASE_NAME=zedauth_local
APP_JWT__SECRET=your-secret-key-here-change-me
APP_JWT__EXPIRATION=3600
```

3) Create the database:

```bash
createdb zedauth_local
```

4) Run the service:

```bash
cargo run
```

The server listens on `http://127.0.0.1:3000` by default and runs migrations on startup.

### API

Common notes:
- **Access token** goes in: `Authorization: Bearer <access_token>`
- **Refresh token** is an HttpOnly cookie named: `refresh_token`

#### Auth

##### `POST /auth/login`

Request:

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

Response (200):

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Also sets:
- `Set-Cookie: refresh_token=...; HttpOnly; SameSite=Strict; Path=/auth; Max-Age=...`

Curl:

```bash
curl -i -X POST http://127.0.0.1:3000/auth/login \
  -H 'Content-Type: application/json' \
  -c cookies.txt \
  -d '{"email":"user@example.com","password":"password123"}'
```

Status codes:
- `200`: success
- `401`: invalid credentials
- `500`: server error

##### `POST /auth/refresh`

Uses the refresh cookie to rotate the refresh token and issue a new access token.

Response (200):

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Also rotates:
- `Set-Cookie: refresh_token=...` (new token)

Curl (cookie jar):

```bash
curl -i -X POST http://127.0.0.1:3000/auth/refresh \
  -b cookies.txt -c cookies.txt
```

Status codes:
- `200`: refreshed
- `401`: missing/invalid refresh cookie, or reuse detected (session revoked)
- `500`: server error

##### `POST /auth/logout`

Revokes the session and clears the refresh cookie.

Curl:

```bash
curl -i -X POST http://127.0.0.1:3000/auth/logout \
  -b cookies.txt -c cookies.txt
```

Status codes:
- `204`: logged out
- `500`: server error

#### Users

All `/users` endpoints require `Authorization: Bearer <access_token>`.

##### `POST /users`

Request:

```json
{
  "email": "user@example.com",
  "password": "password123",
  "first_name": "John",
  "last_name": "Doe"
}
```

Curl:

```bash
curl -i -X POST http://127.0.0.1:3000/users \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123","first_name":"John","last_name":"Doe"}'
```

Response (200):

```json
{
  "id": "<uuid>",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_active": true,
  "is_verified": false,
  "created_at": "2026-01-05T00:00:00Z",
  "updated_at": "2026-01-05T00:00:00Z"
}
```

##### `GET /users/:id`

Curl:

```bash
curl -i http://127.0.0.1:3000/users/<uuid> \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

Status codes (users endpoints):
- `200`: success
- `204`: deleted
- `401`: missing/invalid access token (AuthContext extraction failed)
- `404`: not found
- `409`: conflicts (e.g., duplicate email on create)
- `500`: server error

##### `POST /users/:id`

Request:

```json
{
  "first_name": "Updated",
  "last_name": "Name",
  "is_active": true
}
```

##### `DELETE /users/:id`

Curl:

```bash
curl -i -X DELETE http://127.0.0.1:3000/users/<uuid> \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

#### Health

##### `GET /health_check`

```bash
curl -i http://127.0.0.1:3000/health_check
```

### Security model

- **Route protection**
  - Protected handlers require `AuthContext` (extractor), not router-level middleware.
  - If extraction fails, the handler is never executed and the client receives `401`.
- **Session-backed JWTs**
  - JWT contains `sid`; `AuthContext` checks the session is active (not revoked/expired).
- **Refresh token storage**
  - Only hashes are stored in DB (`sessions.refresh_token_hash`).
- **Rotation + reuse revocation**
  - Refresh rotates the token and stores `previous_refresh_token_hash`.
  - If an old rotated token is presented again, the session is revoked and the client must log in again.
- **Timing hardening (best-effort)**
  - Auth failure responses add a small jittered minimum delay to reduce obvious timing signals.
  - This is not constant-time end-to-end; DB and network latency still vary.

### Upcoming improvements

- **CORS configuration**
  - CORS is currently permissive by default for developer convenience.
  - Production deployments should restrict CORS to trusted origins.
- **Rate limiting**
  - There is no rate limiting yet; adding a simple per-IP and/or per-account rate limit on `POST /auth/login` would reduce brute-force risk.
- **Account security lifecycle**
  - As the project grows, features like account lockout after repeated failures, email verification, and password reset flows would bring it closer to real-world auth system requirements.

### Testing and CI

Run tests (unit + integration where configured):

```bash
cargo test
```

Integration tests require Postgres and `DATABASE_URL` (they are skipped if `DATABASE_URL` is not set):

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/zedauth_test
cargo test
```

Style + lint checks (what CI runs):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Quick Postgres via Docker:

```bash
docker run --rm -p 5432:5432 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=zedauth_test \
  postgres:16
```

CI:
- GitHub Actions runs `fmt`, `clippy -D warnings`, and `cargo test`
- A Postgres service is started for integration tests

### Configuration

Config layers:
1. `configuration/base.yaml`
2. Optional environment-specific file: `configuration/local.yaml` or `configuration/production.yaml`
3. Environment variables prefixed with `APP_` (take precedence)

Secrets:
- In production, provide secrets (DB password, JWT secret) via environment variables or a secrets manager.
- The committed YAML files intentionally omit credentials.

Example config templates:
- `configuration/local.example.yaml`
- `configuration/production.example.yaml`

### License

MIT
