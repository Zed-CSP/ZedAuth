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
cp .env.example .env
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
- `POST /auth/refresh` - Refresh access token using refresh token
  ```json
  {
    "refresh_token": "your_refresh_token"
  }
  ```
- `POST /auth/logout` - Invalidate refresh token
  ```json
  {
    "refresh_token": "your_refresh_token"
  }
  ```

### Users

- `POST /users` - Create a new user
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
2. Environment-specific configuration (`configuration/local.yaml` or `configuration/production.yaml`)
3. Environment variables (prefixed with `APP_`)

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
