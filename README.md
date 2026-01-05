# ZedAuth

A high-performance authentication microservice built with Rust and Axum.

## Features

- JWT-based authentication with access and refresh tokens
- Secure password hashing using Argon2
- User management (CRUD operations)
- PostgreSQL database integration
- Environment-based configuration
- CORS support
- Health check endpoint

## Environment Setup

1. Copy the example environment file:
```bash
cp env.example .env
```

2. Edit the `.env` file with your local configuration:
```bash
# Application Environment
APP_ENVIRONMENT=local

# Database Configuration
APP_DATABASE__USERNAME=your_db_username
APP_DATABASE__PASSWORD=your_db_password
APP_DATABASE__HOST=localhost
APP_DATABASE__PORT=5432
APP_DATABASE__DATABASE_NAME=your_db_name

# JWT Configuration
APP_JWT__SECRET=your-secret-key-here

# Logging
RUST_LOG=info
```

3. Source your environment variables:
```bash
source .env
```

Note: Never commit your `.env` file or any file containing sensitive credentials to version control.

## API Endpoints

### Authentication

- `POST /auth/login` - Login with email and password
  ```json
  {
    "email": "user@example.com",
    "password": "your_password"
  }
  ```
- `POST /auth/refresh` - Refresh access token using the HttpOnly refresh cookie
- `POST /auth/logout` - Revoke the current session and clear the refresh cookie (Authorization header preferred)

Notes:
- Access tokens are sent via `Authorization: Bearer <access_token>`.
- Refresh tokens are stored as an HttpOnly cookie named `refresh_token`.
- Refresh tokens rotate on every successful refresh. If a previously-rotated (old) refresh token is presented again, the server treats it as reuse and **revokes the session** (returns 401; user must log in again).

## Security model (simple, for now)

For this project’s current scope, we keep the surface area minimal and the guarantees explicit:

- **Minimal auth surface**
  - `POST /auth/login`: issues an access JWT and sets an HttpOnly refresh cookie
  - `POST /auth/refresh`: rotates the refresh token and issues a new access JWT
  - `POST /auth/logout`: revokes the session and clears the refresh cookie
  - `GET /health_check`: liveness check
- **Per-request auth context**
  - Protected handlers require an `AuthContext` extracted per request from the `Authorization` header.
  - The access JWT carries `sub` (user id) and `sid` (session id).
  - The service checks the referenced session is active (not revoked, not expired) before accepting the request.
- **How routes are protected (extractor vs middleware)**
  - Routes are protected by requiring `AuthContext` as a handler argument (Axum extractor), not by a router-level middleware layer.
  - If `AuthContext` extraction fails, Axum returns **401** and the handler is never executed.
  - This is a common production pattern; as the codebase grows, teams often also organize routers into `public` vs `authed` route groups to make it harder to accidentally expose an unprotected sensitive endpoint.
- **Refresh token safety**
  - Refresh tokens are stored server-side as a hash in the database (never stored in plaintext).
  - Refresh token rotation is enforced; reuse triggers session revocation.
- **Timing hardening (best-effort)**
  - Authentication failure responses apply a small **jittered minimum delay** to reduce obvious timing signals (e.g., user enumeration and refresh-token probing).
  - This is **not** a guarantee of constant-time responses end-to-end (DB and network latency still vary); it just makes timing harder to reliably exploit.

## Concurrency + state model

- **No global mutable state**
  - There are no global singletons, `static mut`, or global `Mutex/RwLock`-protected variables.
  - Auth state is computed per request (e.g., `AuthContext` is extracted from the request and not stored globally).
- **Shared, concurrency-safe state**
  - The service uses Axum `State(AppState)` to share a database pool (`sqlx::PgPool`) and immutable configuration across requests.
  - This is normal for a microservice: the pool is designed to be safely shared; requests do not “own” the pool, they borrow it.

## Rust memory safety (why it matters here)

- **Memory safety by default**
  - Request parsing, JWT handling, and DB interactions use safe Rust types (`String`, `Uuid`, `Option`, etc.), avoiding whole classes of bugs like use-after-free and null pointer dereferences.
- **Data-race prevention**
  - Shared state (`sqlx::PgPool` + immutable settings) is thread-safe, and Rust’s type system prevents accidental concurrent mutation without explicit synchronization.
- **Security note**
  - Memory safety complements (but does not replace) correct security logic: tokens still must be validated and sessions still must be checked, which this service does at runtime.

### Users

- `POST /users` - Create a new user (requires authentication)
  ```json
  {
    "email": "user@example.com",
    "password": "your_password",
    "first_name": "John",
    "last_name": "Doe"
  }
  ```
- `GET /users/:id` - Get user by ID (requires authentication)
- `POST /users/:id` - Update user (requires authentication)
  ```json
  {
    "first_name": "Updated",
    "last_name": "Name",
    "is_active": true
  }
  ```
- `DELETE /users/:id` - Delete user (requires authentication)

### Health Check

- `GET /health_check` - Check if the service is running

## Getting Started

### Prerequisites

- Rust (latest stable version)
- PostgreSQL
- Cargo

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Zed-CSP/zedauth.git
cd zedauth
```

2. Create a PostgreSQL database:
```bash
createdb zedauth_local
```

3. Set up environment variables:
```bash
export APP_ENVIRONMENT=local
export APP_DATABASE__USERNAME=postgres
export APP_DATABASE__PASSWORD=password
export APP_DATABASE__HOST=localhost
export APP_DATABASE__PORT=5432
export APP_DATABASE__DATABASE_NAME=zedauth_local
export APP_JWT__SECRET=your-secret-key-here
```

4. Run migrations:
```bash
cargo sqlx migrate run
```

5. Start the server:
```bash
cargo run
```

The server will start on `http://localhost:3000`.

## Configuration

The service uses a layered configuration system:

1. Base configuration (`configuration/base.yaml`)
2. Environment-specific configuration (`configuration/local.yaml` or `configuration/production.yaml`, optional)
3. Environment variables (prefixed with `APP_`)

Example environment-specific configs are provided as:
- `configuration/local.example.yaml`
- `configuration/production.example.yaml`

## Security Features


- Passwords are hashed using Argon2
- JWT tokens are used for authentication
- Refresh tokens are stored in the database
- CORS is configured to allow all origins (configure for production)
- Environment variables for sensitive data

## Development

### Running Tests

```bash
cargo test
```

### Database Migrations

Create a new migration:
```bash
cargo sqlx migrate add <migration_name>
```

Run migrations:
```bash
cargo sqlx migrate run
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
