use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{users::model::{User, UserResponse}, AppState};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: Option<bool>,
}

pub async fn create_user(
    State(state): State<AppState>,
    Json(user): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let password_hash = bcrypt::hash(user.password.as_bytes(), bcrypt::DEFAULT_COST)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = Utc::now();
    let user = sqlx::query!(
        r#"
        INSERT INTO users (email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, false, $5, $6)
        RETURNING id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        "#,
        user.email,
        password_hash,
        user.first_name,
        user.last_name,
        now,
        now
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(e) if e.is_unique_violation() => {
            (StatusCode::CONFLICT, "Email already exists".to_string())
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    })?;

    Ok(Json(User {
        id: user.id,
        email: user.email,
        password_hash: user.password_hash,
        first_name: user.first_name,
        last_name: user.last_name,
        is_active: user.is_active.unwrap_or(true),
        is_verified: user.is_verified.unwrap_or(false),
        created_at: user.created_at.unwrap_or_else(Utc::now),
        updated_at: user.updated_at.unwrap_or_else(Utc::now),
    }.into()))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let user = sqlx::query!(
        r#"
        SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        FROM users WHERE id = $1
        "#,
        user_id
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(User {
        id: user.id,
        email: user.email,
        password_hash: user.password_hash,
        first_name: user.first_name,
        last_name: user.last_name,
        is_active: user.is_active.unwrap_or(true),
        is_verified: user.is_verified.unwrap_or(false),
        created_at: user.created_at.unwrap_or_else(Utc::now),
        updated_at: user.updated_at.unwrap_or_else(Utc::now),
    }.into()))
}

pub async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(update): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let now = Utc::now();
    let user = sqlx::query!(
        r#"
        UPDATE users
        SET first_name = COALESCE($1, first_name),
            last_name = COALESCE($2, last_name),
            is_active = COALESCE($3, is_active),
            updated_at = $4
        WHERE id = $5
        RETURNING id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        "#,
        update.first_name,
        update.last_name,
        update.is_active,
        now,
        user_id
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(User {
        id: user.id,
        email: user.email,
        password_hash: user.password_hash,
        first_name: user.first_name,
        last_name: user.last_name,
        is_active: user.is_active.unwrap_or(true),
        is_verified: user.is_verified.unwrap_or(false),
        created_at: user.created_at.unwrap_or_else(Utc::now),
        updated_at: user.updated_at.unwrap_or_else(Utc::now),
    }.into()))
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query!(
        r#"
        DELETE FROM users WHERE id = $1
        "#,
        user_id
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
} 