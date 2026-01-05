mod auth;
mod config;
mod db;
mod users;

use axum::{
    routing::{delete, get, post},
    Router,
};
use std::net::{IpAddr, SocketAddr};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    auth::handlers::{login, logout, refresh_token},
    config::{get_configuration, Settings},
    users::handlers::{create_user, delete_user, get_user, update_user},
};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub settings: Settings,
}

#[tokio::main]
async fn main() {
    // Load local environment variables from `.env` if present.
    // (Production should prefer real environment variables.)
    dotenv::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let configuration = get_configuration().expect("Failed to read configuration.");

    // Set up database connection pool
    let pool = db::get_connection_pool(&configuration).await;

    // Run migrations
    db::run_migrations(&pool)
        .await
        .expect("Failed to run database migrations");

    // Set up CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Create app state
    let state = AppState {
        pool,
        settings: configuration.clone(),
    };

    let app = build_app(state).layer(cors);

    // Run our app with hyper
    let host: IpAddr = configuration
        .application
        .host
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let addr = SocketAddr::from((host, configuration.application.port));
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(&addr).await.unwrap(), app)
        .await
        .unwrap();
}

fn build_app(state: AppState) -> Router {
    Router::new()
        // Health check
        .route("/health_check", get(health_check))
        // Auth routes
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh_token))
        .route("/auth/logout", post(logout))
        // User routes
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/users/:id", post(update_user))
        .route("/users/:id", delete(delete_user))
        .with_state(state)
}

async fn health_check() -> &'static str {
    "OK"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use chrono::{Duration, Utc};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;
    use uuid::Uuid;

    fn test_settings() -> Settings {
        Settings {
            database: crate::config::DatabaseSettings {
                username: "test".to_string(),
                password: "test".to_string(),
                host: "localhost".to_string(),
                port: 5432,
                database_name: "test".to_string(),
            },
            application: crate::config::ApplicationSettings {
                port: 3000,
                host: "127.0.0.1".to_string(),
            },
            jwt: crate::config::JwtSettings {
                secret: "test_secret".to_string(),
                expiration: 3600,
            },
        }
    }

    #[tokio::test]
    async fn users_routes_require_auth_context() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return, // skip unless a DB is configured
        };

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        // Seed a user
        let user_id = Uuid::new_v4();
        let email = format!("users-auth-{}@example.com", Uuid::new_v4());
        let password_hash = crate::auth::hash_password("password123").unwrap();

        sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash, is_active, is_verified)
            VALUES ($1, $2, $3, true, false)
            "#,
        )
        .bind(user_id)
        .bind(&email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();

        // Create a session for AuthContext validation
        let session_id = Uuid::new_v4();
        let refresh_token = format!("refresh-{}", Uuid::new_v4());
        let refresh_hash = crate::auth::hash_refresh_token(&refresh_token);
        let expires_at = Utc::now() + Duration::days(7);

        sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .bind(&refresh_hash)
        .bind(expires_at)
        .execute(&pool)
        .await
        .unwrap();

        let state = AppState {
            pool,
            settings: test_settings(),
        };
        let app = build_app(state);

        // Without Authorization -> 401 (AuthContext extraction fails)
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/users/{user_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // With Authorization -> 200
        let access = crate::auth::create_jwt(user_id, session_id, &test_settings()).unwrap();
        let res = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/users/{user_id}"))
                    .header("Authorization", format!("Bearer {access}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
