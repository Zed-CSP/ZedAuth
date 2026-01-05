use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::config::Settings;
use crate::AppState;

pub mod handlers;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn create_jwt(
    user_id: Uuid,
    session_id: Uuid,
    settings: &Settings,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = now + Duration::seconds(settings.jwt.expiration);

    let claims = Claims {
        sub: user_id,
        sid: session_id,
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(settings.jwt.secret.as_bytes()),
    )
}

pub fn create_refresh_token() -> String {
    Uuid::new_v4().to_string()
}

/// Hash a refresh token for safe-at-rest storage.
/// We store the hex-encoded SHA-256 digest.
pub fn hash_refresh_token(refresh_token: &str) -> String {
    let digest = sha2::Sha256::digest(refresh_token.as_bytes());
    hex::encode(digest)
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

#[derive(Debug)]
pub enum AuthRejection {
    MissingAuthHeader,
    InvalidAuthHeader,
    InvalidToken,
    RevokedSession,
    Internal,
}

impl AuthRejection {
    pub fn into_response(self) -> (StatusCode, String) {
        match self {
            AuthRejection::MissingAuthHeader => (
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header".to_string(),
            ),
            AuthRejection::InvalidAuthHeader => (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization header".to_string(),
            ),
            AuthRejection::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AuthRejection::RevokedSession => {
                (StatusCode::UNAUTHORIZED, "Session revoked".to_string())
            }
            AuthRejection::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            ),
        }
    }
}

fn decode_access_token(token: &str, settings: &Settings) -> Result<Claims, AuthRejection> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(settings.jwt.secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| AuthRejection::InvalidToken)
}

fn parse_bearer(parts: &Parts) -> Result<&str, AuthRejection> {
    let header = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(AuthRejection::MissingAuthHeader)?
        .to_str()
        .map_err(|_| AuthRejection::InvalidAuthHeader)?;

    header
        .strip_prefix("Bearer ")
        .ok_or(AuthRejection::InvalidAuthHeader)
}

#[async_trait]
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parse_bearer(parts).map_err(|e| e.into_response())?;
        let claims = decode_access_token(token, &state.settings).map_err(|e| e.into_response())?;

        // Optional but recommended: ensure session is still valid/revocable server-side.
        let is_valid = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
              SELECT 1
              FROM sessions
              WHERE id = $1
                AND user_id = $2
                AND revoked_at IS NULL
                AND expires_at > CURRENT_TIMESTAMP
            )
            "#,
        )
        .bind(claims.sid)
        .bind(claims.sub)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AuthRejection::Internal.into_response())?;

        if !is_valid {
            return Err(AuthRejection::RevokedSession.into_response());
        }

        Ok(Self {
            user_id: claims.sub,
            session_id: claims.sid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

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
                host: "localhost".to_string(),
            },
            jwt: crate::config::JwtSettings {
                secret: "test_secret".to_string(),
                expiration: 3600,
            },
        }
    }

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "test_password123";

        // Test password hashing
        let hash = hash_password(password).unwrap();
        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2id$")); // Verify it's using Argon2id

        // Test password verification
        let verification_result = verify_password(password, &hash).unwrap();
        assert!(verification_result);

        // Test wrong password
        let wrong_password = "wrong_password";
        let wrong_verification = verify_password(wrong_password, &hash).unwrap();
        assert!(!wrong_verification);
    }

    #[test]
    fn test_jwt_creation() {
        let settings = test_settings();

        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let token = create_jwt(user_id, session_id, &settings).unwrap();

        // Basic JWT validation
        assert!(!token.is_empty());
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3); // JWT should have 3 parts: header.payload.signature
    }

    #[test]
    fn test_refresh_token_creation() {
        let token1 = create_refresh_token();
        let token2 = create_refresh_token();

        // Verify tokens are UUIDs
        assert!(Uuid::parse_str(&token1).is_ok());
        assert!(Uuid::parse_str(&token2).is_ok());

        // Verify tokens are unique
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_refresh_token_hashing_is_deterministic() {
        let token = "refresh_token_example";
        let h1 = hash_refresh_token(token);
        let h2 = hash_refresh_token(token);
        assert_eq!(h1, h2);
        assert!(!h1.is_empty());
    }

    #[test]
    fn test_parse_bearer_header() {
        let req = axum::http::Request::builder()
            .header("Authorization", "Bearer abc.def.ghi")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(parse_bearer(&parts).unwrap(), "abc.def.ghi");

        let req = axum::http::Request::builder().body(()).unwrap();
        let (parts, _) = req.into_parts();
        assert!(matches!(
            parse_bearer(&parts),
            Err(AuthRejection::MissingAuthHeader)
        ));
    }

    #[test]
    fn test_decode_access_token_round_trip() {
        let settings = test_settings();
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let token = create_jwt(user_id, session_id, &settings).unwrap();

        let claims = decode_access_token(&token, &settings).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.sid, session_id);
    }

    #[tokio::test]
    async fn integration_auth_context_requires_valid_session() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return, // skip unless a DB is configured
        };

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        // Create user + active session
        let user_id = Uuid::new_v4();
        let email = format!("authctx-{}@example.com", Uuid::new_v4());
        let password_hash = hash_password("password123").unwrap();

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

        let session_id = Uuid::new_v4();
        let refresh_hash = hash_refresh_token(&format!("refresh-{}", Uuid::new_v4()));
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

        let settings = test_settings();
        let state = crate::AppState {
            pool,
            settings: settings.clone(),
        };

        let access = create_jwt(user_id, session_id, &settings).unwrap();
        let req = axum::http::Request::builder()
            .header("Authorization", format!("Bearer {access}"))
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        let ctx = AuthContext::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(ctx.user_id, user_id);
        assert_eq!(ctx.session_id, session_id);

        // Revoke and ensure it fails
        sqlx::query("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1")
            .bind(session_id)
            .execute(&state.pool)
            .await
            .unwrap();

        let req = axum::http::Request::builder()
            .header("Authorization", format!("Bearer {access}"))
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let err = AuthContext::from_request_parts(&mut parts, &state)
            .await
            .err()
            .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}
