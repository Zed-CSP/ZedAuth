mod auth;
mod config;
mod db;
mod users;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::get_configuration;

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

    // Build our application with routes
    let app = Router::new()
        .route("/health_check", get(health_check))
        .layer(cors)
        .with_state(pool);

    // Run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], configuration.application.port));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}
