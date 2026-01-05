use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{Duration as StdDuration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    auth::{create_jwt, create_refresh_token, hash_refresh_token, verify_password, AuthContext},
    users::model::User,
    AppState,
};

fn is_production() -> bool {
    std::env::var("APP_ENVIRONMENT")
        .ok()
        .is_some_and(|v| v.eq_ignore_ascii_case("production"))
}

fn build_refresh_cookie(refresh_token: String, is_prod: bool) -> Cookie<'static> {
    Cookie::build(("refresh_token", refresh_token))
        .http_only(true)
        // CSRF hardening: do not send refresh token in cross-site requests.
        // If you *need* cross-site refresh, switch to SameSite::None + Secure and add CSRF protections.
        .same_site(SameSite::Strict)
        // Only send the refresh cookie to auth endpoints.
        .path("/auth")
        // Secure cookies require HTTPS. Keep dev usable by only enforcing in production.
        .secure(is_prod)
        .max_age(time::Duration::days(7))
        .build()
}

async fn jittered_min_delay(start: Instant) {
    // Best-effort timing hardening (not constant time end-to-end).
    // Adds a jittered minimum duration on auth failures to reduce obvious timing signals.
    let min = StdDuration::from_millis(180);
    let jitter_ms: u64 = rand::thread_rng().gen_range(0..=120);
    let target = min + StdDuration::from_millis(jitter_ms);
    let elapsed = start.elapsed();
    if elapsed < target {
        sleep(target - elapsed).await;
    }
}

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
) -> Result<(CookieJar, Json<crate::auth::TokenResponse>), (StatusCode, String)> {
    let start = Instant::now();

    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(&login.email)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    ;

    let Some(user) = user else {
        jittered_min_delay(start).await;
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
    };

    if !user.is_active {
        jittered_min_delay(start).await;
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
    }

    if !verify_password(&login.password, &user.password_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        jittered_min_delay(start).await;
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
    }

    let refresh_token = create_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::days(7);
    let refresh_token_hash = hash_refresh_token(&refresh_token);
    let session_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(session_id)
    .bind(user.id)
    .bind(&refresh_token_hash)
    .bind(refresh_expires_at)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let access_token = create_jwt(user.id, session_id, &state.settings)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let jar = CookieJar::new().add(build_refresh_cookie(refresh_token, is_production()));

    Ok((
        jar,
        Json(crate::auth::TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: state.settings.jwt.expiration,
        }),
    ))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    jar: CookieJar,
    // Backwards compatible: if a client still sends the refresh token in JSON, we can use it.
    // Cookie takes precedence.
    refresh: Option<Json<RefreshTokenRequest>>,
) -> Result<(CookieJar, Json<crate::auth::TokenResponse>), (StatusCode, String)> {
    let start = Instant::now();

    let refresh_token = jar
        .get("refresh_token")
        .map(|c| c.value().to_string())
        .or_else(|| refresh.map(|r| r.0.refresh_token))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Missing refresh token".to_string(),
            )
        })?;

    let refresh_token_hash = hash_refresh_token(&refresh_token);

    let session = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>)>(
        r#"
        SELECT id, user_id, refresh_token_hash, previous_refresh_token_hash
        FROM sessions
        WHERE (refresh_token_hash = $1 OR previous_refresh_token_hash = $1)
          AND revoked_at IS NULL
          AND expires_at > CURRENT_TIMESTAMP
        "#,
    )
    .bind(&refresh_token_hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid refresh token".to_string(),
        )
    })?;

    let (session_id, user_id, current_hash, previous_hash) = session;

    // Reuse detection: if the presented token matches the previous refresh token hash,
    // assume compromise and revoke the whole session.
    if previous_hash.as_deref() == Some(refresh_token_hash.as_str()) {
        sqlx::query("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1")
            .bind(session_id)
            .execute(&state.pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        jittered_min_delay(start).await;
        return Err((
            StatusCode::UNAUTHORIZED,
            "Refresh token reuse detected; session revoked".to_string(),
        ));
    }

    // Defensive: ensure we only rotate on the current token.
    if current_hash != refresh_token_hash {
        jittered_min_delay(start).await;
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid refresh token".to_string(),
        ));
    }

    let new_refresh_token = create_refresh_token();
    let new_refresh_token_hash = hash_refresh_token(&new_refresh_token);
    let new_expires_at = Utc::now() + Duration::days(7);

    sqlx::query(
        r#"
        UPDATE sessions
        SET previous_refresh_token_hash = refresh_token_hash,
            refresh_token_hash = $1,
            expires_at = $2
        WHERE id = $3
        "#,
    )
    .bind(&new_refresh_token_hash)
    .bind(new_expires_at)
    .bind(session_id)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let access_token = create_jwt(user_id, session_id, &state.settings)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let jar = jar.add(build_refresh_cookie(new_refresh_token, is_production()));

    Ok((
        jar,
        Json(crate::auth::TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: state.settings.jwt.expiration,
        }),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    auth: Option<AuthContext>,
) -> Result<(CookieJar, StatusCode), (StatusCode, String)> {
    // Prefer Authorization-based logout (revoke session_id), fallback to cookie-based.
    if let Some(auth) = auth {
        sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(auth.session_id)
        .bind(auth.user_id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    } else if let Some(cookie) = jar.get("refresh_token") {
        let refresh_token_hash = hash_refresh_token(cookie.value());
        sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE refresh_token_hash = $1
            "#,
        )
        .bind(refresh_token_hash)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Match the Path we set on the cookie.
    let jar = jar.remove(Cookie::build(("refresh_token", "")).path("/auth").build());
    Ok((jar, StatusCode::NO_CONTENT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::Json;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    fn test_settings() -> crate::config::Settings {
        crate::config::Settings {
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

    #[test]
    fn refresh_cookie_attributes_are_strict_and_scoped() {
        let c = build_refresh_cookie("t".to_string(), true);
        assert_eq!(c.name(), "refresh_token");
        assert_eq!(c.path(), Some("/auth"));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Strict));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.max_age(), Some(time::Duration::days(7)));
    }

    #[tokio::test]
    async fn refresh_rotates_and_invalidates_old_token() {
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

        // Create a user
        let user_id = Uuid::new_v4();
        let email = format!("user-{}@example.com", Uuid::new_v4());
        let password = "password123";
        let password_hash = crate::auth::hash_password(password).unwrap();

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

        let state = crate::AppState {
            pool: pool.clone(),
            settings: test_settings(),
        };

        let (jar1, _resp) = super::login(
            State(state.clone()),
            Json(LoginRequest {
                email: email.clone(),
                password: password.to_string(),
            }),
        )
        .await
        .unwrap();

        let old_refresh = jar1.get("refresh_token").unwrap().value().to_string();

        let session_id: Uuid = sqlx::query_scalar(
            r#"
            SELECT id FROM sessions
            WHERE user_id = $1 AND revoked_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let old_hash: String =
            sqlx::query_scalar("SELECT refresh_token_hash FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let (jar2, _resp2) = super::refresh_token(State(state), jar1.clone(), None)
            .await
            .unwrap();

        let new_refresh = jar2.get("refresh_token").unwrap().value().to_string();
        assert_ne!(old_refresh, new_refresh);

        let new_hash: String =
            sqlx::query_scalar("SELECT refresh_token_hash FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_ne!(old_hash, new_hash);

        // Old cookie should trigger reuse detection, revoking the session.
        let err = super::refresh_token(
            State(crate::AppState {
                pool: pool.clone(),
                settings: test_settings(),
            }),
            jar1,
            None,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked_at.is_some());

        // And the new refresh token should no longer work since the session is revoked.
        let err2 = super::refresh_token(
            State(crate::AppState {
                pool,
                settings: test_settings(),
            }),
            jar2,
            None,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err2.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_reuse_revokes_session() {
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

        // Create a user
        let user_id = Uuid::new_v4();
        let email = format!("reuse-{}@example.com", Uuid::new_v4());
        let password = "password123";
        let password_hash = crate::auth::hash_password(password).unwrap();

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

        let state = crate::AppState {
            pool: pool.clone(),
            settings: test_settings(),
        };

        // Login -> get initial refresh cookie
        let (jar_initial, _resp) = super::login(
            State(state.clone()),
            Json(LoginRequest {
                email: email.clone(),
                password: password.to_string(),
            }),
        )
        .await
        .unwrap();

        // Rotate once using the initial cookie -> get new cookie
        let (jar_rotated, _resp2) =
            super::refresh_token(State(state.clone()), jar_initial.clone(), None)
                .await
                .unwrap();

        // Find the session id (created by login)
        let session_id: Uuid = sqlx::query_scalar(
            r#"
            SELECT id FROM sessions
            WHERE user_id = $1 AND revoked_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // Now reuse the *previous* refresh token (the initial cookie) -> should revoke the session
        let err = super::refresh_token(State(state.clone()), jar_initial, None)
            .await
            .err()
            .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked_at.is_some());

        // And the rotated refresh token should no longer work because the session is revoked.
        let err2 = super::refresh_token(State(state), jar_rotated, None)
            .await
            .err()
            .unwrap();
        assert_eq!(err2.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_sets_refresh_cookie_and_creates_session_row() {
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

        // Create a user
        let user_id = Uuid::new_v4();
        let email = format!("login-{}@example.com", Uuid::new_v4());
        let password = "password123";
        let password_hash = crate::auth::hash_password(password).unwrap();

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

        let state = crate::AppState {
            pool: pool.clone(),
            settings: test_settings(),
        };

        let (jar, _resp) = super::login(
            State(state),
            Json(LoginRequest {
                email: email.clone(),
                password: password.to_string(),
            }),
        )
        .await
        .unwrap();

        let cookie = jar
            .get("refresh_token")
            .expect("refresh cookie should be set");
        let refresh_token = cookie.value().to_string();
        assert!(!refresh_token.is_empty());

        let refresh_hash = crate::auth::hash_refresh_token(&refresh_token);
        let session_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM sessions WHERE user_id = $1 AND refresh_token_hash = $2",
        )
        .bind(user_id)
        .bind(refresh_hash)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_ne!(session_id, Uuid::nil());
    }

    #[tokio::test]
    async fn logout_revokes_session_and_clears_cookie() {
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

        // Create a user and a session
        let user_id = Uuid::new_v4();
        let email = format!("logout-{}@example.com", Uuid::new_v4());
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

        let session_id = Uuid::new_v4();
        let refresh_token = "rt";
        let refresh_hash = crate::auth::hash_refresh_token(refresh_token);
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

        let state = crate::AppState {
            pool: pool.clone(),
            settings: test_settings(),
        };

        let jar = CookieJar::new().add(
            Cookie::build(("refresh_token", refresh_token))
                .path("/auth")
                .build(),
        );

        let auth = AuthContext {
            user_id,
            session_id,
        };

        let (jar, status) = super::logout(State(state), jar, Some(auth)).await.unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(jar.get("refresh_token").is_none());

        let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked_at.is_some());
    }

    #[tokio::test]
    async fn login_failures_do_not_create_sessions() {
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

        // Wrong password case
        let user_id = Uuid::new_v4();
        let email = format!("badpw-{}@example.com", Uuid::new_v4());
        let password_hash = crate::auth::hash_password("correct_password123").unwrap();

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

        let state = crate::AppState {
            pool: pool.clone(),
            settings: test_settings(),
        };

        let err = super::login(
            State(state.clone()),
            Json(LoginRequest {
                email: email.clone(),
                password: "wrong_password".to_string(),
            }),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(session_count, 0);

        // Inactive user case
        let inactive_user_id = Uuid::new_v4();
        let inactive_email = format!("inactive-{}@example.com", Uuid::new_v4());
        let inactive_password = "inactive_password123";
        let inactive_password_hash = crate::auth::hash_password(inactive_password).unwrap();

        sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash, is_active, is_verified)
            VALUES ($1, $2, $3, false, false)
            "#,
        )
        .bind(inactive_user_id)
        .bind(&inactive_email)
        .bind(&inactive_password_hash)
        .execute(&pool)
        .await
        .unwrap();

        let err = super::login(
            State(state),
            Json(LoginRequest {
                email: inactive_email.clone(),
                password: inactive_password.to_string(),
            }),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
                .bind(inactive_user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(session_count, 0);
    }

    #[tokio::test]
    async fn logout_without_auth_uses_refresh_cookie_to_revoke_session() {
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

        // Create a user and a session
        let user_id = Uuid::new_v4();
        let email = format!("logout-cookie-{}@example.com", Uuid::new_v4());
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

        let session_id = Uuid::new_v4();
        let refresh_token = "logout_cookie_rt";
        let refresh_hash = crate::auth::hash_refresh_token(refresh_token);
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

        let state = crate::AppState {
            pool: pool.clone(),
            settings: test_settings(),
        };

        let jar = CookieJar::new().add(
            Cookie::build(("refresh_token", refresh_token))
                .path("/auth")
                .build(),
        );

        let (_jar, status) = super::logout(State(state), jar, None).await.unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);

        let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked_at.is_some());
    }
}
