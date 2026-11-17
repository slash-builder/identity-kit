//! Token cache — platform-appropriate secure storage for OAuth tokens.
//!
//! Implementation deferred. Default backend will be the OS keychain via
//! the `keyring` crate.

use crate::IdentityError;

/// A secure cache for refresh tokens and short-lived access tokens.
pub trait TokenCache: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>, IdentityError>;
    fn set(&self, key: &str, value: &str) -> Result<(), IdentityError>;
    fn delete(&self, key: &str) -> Result<(), IdentityError>;
}
