# ZedAuth

A high-performance authentication microservice built with Rust and Axum.

## Features

- User registration and authentication
- JWT-based authentication
- Refresh token support
- Password hashing with Argon2
- PostgreSQL database support
- Configuration management
- CORS support
- Health check endpoint

## Prerequisites

- Rust (latest stable version)
- PostgreSQL
- Cargo

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/zedauth.git
cd zedauth
```

2. Create a PostgreSQL database:
```bash
createdb zedauth_local
```

3. Configure the application:
   - Copy `configuration/base.yaml` to `configuration/local.yaml`
   - Update the database credentials in `configuration/local.yaml`

4. Run migrations:
```bash
cargo install sqlx-cli
sqlx database create
sqlx migrate run
```

5. Run the application:
```bash
cargo run
```

## API Endpoints

### Health Check
- `GET /health_check`
  - Returns "OK" if the service is running

## Development

### Running Tests
```bash
cargo test
```

### Running Migrations
```bash
sqlx migrate run
```

## License

MIT
