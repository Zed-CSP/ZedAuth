#!/bin/bash

export APP_ENVIRONMENT=local
export APP_DATABASE__USERNAME=postgres
export APP_DATABASE__PASSWORD=password
export APP_DATABASE__HOST=localhost
export APP_DATABASE__PORT=5432
export APP_DATABASE__DATABASE_NAME=zedauth_local
export APP_JWT__SECRET=development-secret-key
export RUST_LOG=info 