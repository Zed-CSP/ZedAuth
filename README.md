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

## API Endpoints

### Authentication

- `POST /auth/login` - Login with email and password
- `POST /auth/refresh` - Refresh access token using refresh token
- `POST /auth/logout` - Invalidate refresh token

### Users

- `POST /users` - Create a new user
- `GET /users/:id` - Get user by ID
- `POST /users/:id` - Update user
- `DELETE /users/:id` - Delete user

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
git clone https://github.com/yourusername/zedauth.git
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
2. Environment-specific configuration (`configuration/local.yaml` or `configuration/production.yaml`)
3. Environment variables (prefixed with `APP_`)

## Security

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
