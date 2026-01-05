use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use uuid::Uuid;

use crate::{
    auth::hash_password,
    auth::AuthContext,
    users::model::{CreateUser, UpdateUser, User, UserResponse},
    AppState,
};

pub async fn create_user(
    _auth: AuthContext,
    State(state): State<AppState>,
    Json(user): Json<CreateUser>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let password_hash = hash_password(&user.password)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = Utc::now();
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, false, $5, $6)
        RETURNING id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        "#,
    )
    .bind(&user.email)
    .bind(&password_hash)
    .bind(&user.first_name)
    .bind(&user.last_name)
    .bind(now)
    .bind(now)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(e) if e.is_unique_violation() => {
            (StatusCode::CONFLICT, "Email already exists".to_string())
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    })?;

    Ok(Json(user.into()))
}

pub async fn get_user(
    _auth: AuthContext,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        FROM users WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(user.into()))
}

pub async fn update_user(
    _auth: AuthContext,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(update): Json<UpdateUser>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let now = Utc::now();
    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET first_name = COALESCE($1, first_name),
            last_name = COALESCE($2, last_name),
            is_active = COALESCE($3, is_active),
            updated_at = $4
        WHERE id = $5
        RETURNING id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        "#,
    )
    .bind(&update.first_name)
    .bind(&update.last_name)
    .bind(update.is_active)
    .bind(now)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(user.into()))
}

pub async fn delete_user(
    _auth: AuthContext,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query(
        r#"
        DELETE FROM users WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}
