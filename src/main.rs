mod auth;
mod config;
mod db;
mod users;

use axum::{
    routing::{get, post, delete},
    Router,
};
use std::net::SocketAddr;
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

    // Build our application with routes
    let app = Router::new()
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
        .layer(cors)
        .with_state(state);

    // Run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], configuration.application.port));
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(&addr).await.unwrap(), app).await.unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}
