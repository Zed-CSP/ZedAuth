use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{create_jwt, create_refresh_token, verify_password},
    users::model::User,
    AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(login): Json<LoginRequest>,
) -> Result<Json<crate::auth::TokenResponse>, (StatusCode, String)> {
    let user = sqlx::query!(
        r#"
        SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        FROM users WHERE email = $1
        "#,
        login.email
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

    let user = User {
        id: user.id,
        email: user.email,
        password_hash: user.password_hash,
        first_name: user.first_name,
        last_name: user.last_name,
        is_active: user.is_active.unwrap_or(true),
        is_verified: user.is_verified.unwrap_or(false),
        created_at: user.created_at.unwrap_or_else(Utc::now),
        updated_at: user.updated_at.unwrap_or_else(Utc::now),
    };

    if !user.is_active {
        return Err((StatusCode::UNAUTHORIZED, "Account is not active".to_string()));
    }

    if !verify_password(&login.password, &user.password_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
    }

    let access_token = create_jwt(user.id, &state.settings)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let refresh_token = create_refresh_token();
    let expires_at = Utc::now() + Duration::days(7);

    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
        "#,
        user.id,
        refresh_token,
        expires_at
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(crate::auth::TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.settings.jwt.expiration,
    }))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(refresh): Json<RefreshTokenRequest>,
) -> Result<Json<crate::auth::TokenResponse>, (StatusCode, String)> {
    let token = sqlx::query!(
        r#"
        SELECT user_id FROM refresh_tokens
        WHERE token = $1 AND expires_at > CURRENT_TIMESTAMP
        "#,
        refresh.refresh_token
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid refresh token".to_string()))?;

    let access_token = create_jwt(token.user_id, &state.settings)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let new_refresh_token = create_refresh_token();
    let expires_at = Utc::now() + Duration::days(7);

    sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET token = $1, expires_at = $2
        WHERE token = $3
        "#,
        new_refresh_token,
        expires_at,
        refresh.refresh_token
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(crate::auth::TokenResponse {
        access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.settings.jwt.expiration,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(refresh): Json<RefreshTokenRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query!(
        r#"
        DELETE FROM refresh_tokens WHERE token = $1
        "#,
        refresh.refresh_token
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
} 