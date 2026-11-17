//! AuthN — interactive and silent sign-in against an OIDC IdP.
//!
//! Phase 1: Auth0 — still a stub. The identity-provider decision landed on
//! Keycloak, and Auth0 was never brought up, so [`AuthN::auth0`] returns
//! [`IdentityError::NotImplemented`].
//!
//! Phase 2: Keycloak — **implemented**, in [`keycloak`]. Real OIDC
//! discovery + Authorization Code + PKCE against a Keycloak realm. Nothing
//! here hardcodes a host, a realm name or an endpoint shape — the same
//! [`KeycloakConfig`] type works unmodified against any realm of any
//! Keycloak instance.
//!
//! ## Security architecture (not open for reconsideration)
//!
//! The only supported interactive flow is Authorization Code + PKCE via a
//! real browser/webview redirect to the IdP's own hosted login page. This
//! Kit does not implement, and will not implement, Resource Owner Password
//! Credentials (ROPC) or any flow that lets a caller hand a plaintext
//! password to this library or forward one server-to-server. That flow was
//! explicitly rejected: it forecloses WebAuthn/passkeys (which
//! are origin-bound), and it puts plaintext passwords through a code path
//! they should never touch. Tests exercise this with a mock token
//! endpoint (`wiremock`), never a password grant.
//!
//! The one non-interactive path this Kit does support,
//! [`AuthN::service_principal_keycloak`], is the OAuth2 **Client
//! Credentials** grant, not ROPC — it authenticates a confidential client
//! application on behalf of no human at all, never a person's password.
//! See `keycloak::KeycloakAuthN::service_principal`'s doc comment for
//! the full distinction; the refusal above is unchanged and this is not
//! an exception to it.

use std::sync::Arc;

use crate::authz::ServicePrincipal;
use crate::token::TokenCache;
use crate::IdentityError;

pub mod keycloak;

pub use keycloak::{KeycloakConfig, KeycloakServicePrincipalConfig, PendingAuthorization, Session};

/// Provider-agnostic AuthN handle. Construct via [`AuthN::auth0`] or
/// [`AuthN::keycloak`].
pub struct AuthN {
    inner: Provider,
}

enum Provider {
    Keycloak(keycloak::KeycloakAuthN),
}

/// Configuration for the Auth0 provider.
pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
}

impl AuthN {
    /// Future: build an Auth0-backed AuthN client.
    ///
    /// Deferred — out of scope for the Keycloak work landed alongside this
    /// doc comment; it is on the open-work list.
    pub async fn auth0(_config: Auth0Config) -> Result<Self, IdentityError> {
        Err(IdentityError::NotImplemented("Auth0 AuthN client"))
    }

    /// Build a Keycloak-backed AuthN client.
    ///
    /// Performs OIDC discovery against
    /// `{base_url}/realms/{realm}/.well-known/openid-configuration` and
    /// resolves the `authorization`/`token`/`userinfo`/`end_session`
    /// endpoints from that document rather than hardcoding their paths.
    ///
    /// `token_cache` is the seam this flow persists and refreshes tokens
    /// through — see [`TokenCache`]. A concrete `keyring`-backed
    /// implementation is separate, still-open Kit work; pass any
    /// implementer here. An in-memory one is fine for tests or
    /// short-lived CLI invocations that don't need persistence across
    /// process restarts.
    pub async fn keycloak(
        config: KeycloakConfig,
        token_cache: Arc<dyn TokenCache>,
    ) -> Result<Self, IdentityError> {
        let inner = keycloak::KeycloakAuthN::connect(config, token_cache).await?;
        Ok(AuthN {
            inner: Provider::Keycloak(inner),
        })
    }

    /// Build a headless `ServicePrincipal` via a non-interactive Keycloak
    /// Client Credentials grant — see the module doc comment's "Security
    /// architecture" section and
    /// `keycloak::KeycloakAuthN::service_principal` for the full
    /// rationale and error shape.
    ///
    /// Unlike [`AuthN::keycloak`], this doesn't return (or need) a
    /// connected `AuthN` instance — there is no interactive session, no
    /// cached token, and no human account behind the result.
    pub async fn service_principal_keycloak(
        config: KeycloakServicePrincipalConfig,
    ) -> Result<ServicePrincipal, IdentityError> {
        keycloak::KeycloakAuthN::service_principal(config).await
    }

    /// Begin an interactive sign-in.
    ///
    /// Builds the Keycloak-hosted authorization URL (Authorization Code +
    /// PKCE, `S256`) that the caller must open in a real browser or
    /// webview — this Kit never collects credentials itself. The returned
    /// [`PendingAuthorization`] must be held by the caller (in memory, for
    /// the lifetime of the sign-in attempt) until the IdP redirects back
    /// with a `code`/`state` pair, which then goes to
    /// [`AuthN::complete_sign_in`].
    pub fn begin_sign_in(&self) -> PendingAuthorization {
        match &self.inner {
            Provider::Keycloak(kc) => kc.begin_sign_in(),
        }
    }

    /// Complete an interactive sign-in after the IdP's redirect delivers a
    /// `code` and `state` back to the caller's redirect URI.
    ///
    /// Verifies `state` against the CSRF token minted in
    /// [`AuthN::begin_sign_in`], exchanges `code` for tokens using the
    /// matching PKCE verifier, resolves the account via the userinfo
    /// endpoint, and persists the resulting [`Session`] through
    /// `token_cache`.
    pub async fn complete_sign_in(
        &self,
        pending: PendingAuthorization,
        code: String,
        state: String,
    ) -> Result<Session, IdentityError> {
        match &self.inner {
            Provider::Keycloak(kc) => kc.complete_sign_in(pending, code, state).await,
        }
    }

    /// Silent sign-in: exchange the cached refresh token for a fresh
    /// access token via the standard OIDC `refresh_token` grant against
    /// the same token endpoint discovery resolved.
    ///
    /// Fails if no session is cached, or the cached session has no refresh
    /// token.
    pub async fn refresh(&self) -> Result<Session, IdentityError> {
        match &self.inner {
            Provider::Keycloak(kc) => kc.refresh().await,
        }
    }

    /// Drop the locally cached session and, if the realm's discovery
    /// document advertised an `end_session_endpoint`, return the IdP
    /// logout URL for the caller to navigate the user to.
    ///
    /// Returns `Ok(None)` (after still clearing the local cache) if the
    /// realm didn't advertise a logout endpoint.
    pub fn sign_out(
        &self,
        post_logout_redirect_uri: Option<&str>,
    ) -> Result<Option<url::Url>, IdentityError> {
        match &self.inner {
            Provider::Keycloak(kc) => kc.sign_out(post_logout_redirect_uri),
        }
    }
}
