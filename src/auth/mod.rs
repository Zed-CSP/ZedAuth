use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Settings;

pub mod handlers;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
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

pub fn create_jwt(user_id: Uuid, settings: &Settings) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = now + Duration::seconds(settings.jwt.expiration);
    
    let claims = Claims {
        sub: user_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

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
        let settings = Settings {
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
        };

        let user_id = Uuid::new_v4();
        let token = create_jwt(user_id, &settings).unwrap();
        
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
} 