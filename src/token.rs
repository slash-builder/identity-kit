//! Token cache — platform-appropriate secure storage for OAuth tokens.
//!
//! Implementation deferred. Default backend will be the OS keychain via
//! the `keyring` crate.

use crate::IdentityError;

/// A secure cache for refresh tokens and short-lived access tokens.
///
/// This crate provides no implementation and adds no protection of its own; keeping the stored values secure is up to
/// the implementer.
pub trait TokenCache: Send + Sync {
    /// Returns the value stored under `key`, or `Ok(None)` if there is none.
    fn get(&self, key: &str) -> Result<Option<String>, IdentityError>;
    /// Stores `value` under `key`. The Keycloak flow in [`AuthN`](crate::authn::AuthN) stores a JSON-serialised
    /// [`Session`](crate::authn::Session) under a key of the form `identity-kit:keycloak:{realm}:{client_id}`. That JSON
    /// contains the access token, the refresh token (if any) and the account, all in plain text, so treat the value as a
    /// secret. [`AuthN::refresh`](crate::authn::AuthN::refresh) reads it back and uses it as stored; this crate adds no
    /// integrity check.
    fn set(&self, key: &str, value: &str) -> Result<(), IdentityError>;
    /// Removes the entry for `key`. [`AuthN::sign_out`](crate::authn::AuthN::sign_out) calls it to drop the cached session.
    fn delete(&self, key: &str) -> Result<(), IdentityError>;
}
