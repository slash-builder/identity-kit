//! Error type for Identity Kit operations.

use thiserror::Error;
use uuid::Uuid;

/// The error type returned by this crate's fallible operations.
///
/// The variants that carry a `String` carry a human-readable message. The wording is not stable and can include text
/// received from a remote server, so do not match on it.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// An authentication step, or a configuration value it depends on, was invalid or was refused. The payload is a
    /// human-readable message.
    ///
    /// Returned, among other cases, for a blank or unparseable value in a [`KeycloakConfig`](crate::authn::KeycloakConfig),
    /// a [`KeycloakServicePrincipalConfig`](crate::authn::KeycloakServicePrincipalConfig) or an
    /// [`AccountClient::new`](crate::account::AccountClient::new) argument (for example an empty `base_url`), a failed
    /// OAuth2 token exchange, a sign-in callback whose `state` does not match, a missing cached session or refresh
    /// token, a client-credentials access token that is not a well-formed JWT, a userinfo `sub` that is not a UUID, an
    /// empty session id passed to
    /// [`AccountClient::revoke_session`](crate::account::AccountClient::revoke_session), and a `401` or `403` from the
    /// identity service ([`FamilyClient`](crate::family::FamilyClient)). A `401` from Keycloak's userinfo endpoint or
    /// Account REST API is reported as [`IdentityError::Transport`] instead.
    #[error("auth flow failed: {0}")]
    Auth(String),

    /// A cached session could not be serialised to, or deserialised from, its JSON form. The payload is a human-readable
    /// message. This crate returns it only in those two cases.
    #[error("token cache: {0}")]
    Cache(String),

    /// An HTTP exchange failed or its result was unusable. The payload is a human-readable message.
    ///
    /// Returned, among other cases, when a request cannot be built or sent (including an unparseable
    /// [`FamilyClient`](crate::family::FamilyClient) base URL), when a response has an error status or is not valid JSON,
    /// when the identity service answers with a status this crate does not map to a more specific variant, and when a
    /// response cannot be used (for example a household id that differs from the one targeted, or a membership `state`
    /// this build does not recognise).
    #[error("transport: {0}")]
    Transport(String),

    /// This crate does not implement the operation that was called; the payload says which. No network call is made.
    ///
    /// Distinct from [`IdentityError::NotYetSupported`], where the server answered `501`.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// An I/O error, wrapped via `From<std::io::Error>`. Nothing in this crate returns it itself; the conversion lets a
    /// [`TokenCache`](crate::token::TokenCache) implementation use `?` on I/O errors.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A household must keep at least one `Owner` membership; this
    /// leave would have dropped it to zero. Can come from the client-side
    /// pre-flight guard (`family::guard_last_owner_leave`) or from
    /// the identity service refusing the request authoritatively.
    #[error("household {household} would be left without an owner")]
    LastOwner {
        /// The household that would be left without an owner.
        household: Uuid,
    },

    /// A [`crate::account::GuardianEdge`] was attempted on a child whose
    /// `origin` isn't `AccountOrigin::CreatedInHousehold` (guardian
    /// edges only exist for created children).
    ///
    /// Purely a client-side invariant now: the identity service removed
    /// its client-supplied-`child_account_id` `create_child` path entirely
    /// (it let any household adult capture an existing identity as a
    /// "child"), and with it the `409 invalid_guardian_edge` response this
    /// variant used to also reconstruct from the wire — that mapping is
    /// gone from `family::error_from_parts`. `GuardianEdge::new` still
    /// enforces this locally, for whenever a safe, server-minted
    /// implementation replaces the removed one.
    #[error("account {child} has no created-in-household origin; a guardian edge is invalid")]
    InvalidGuardianEdge {
        /// The `id` of the account that is not a created-in-household child.
        child: Uuid,
    },

    /// A real, reachable identity-service endpoint answered `501 {"error":
    /// "not_implemented"}` — the route exists and was called for real, but
    /// the server deliberately hasn't implemented it yet (today that covers
    /// emancipation and child creation). Distinct from [`IdentityError::NotImplemented`], which
    /// means *this Kit's* client code is a stub that never made a network
    /// call at all.
    #[error("identity-service has not implemented this endpoint yet: {0}")]
    NotYetSupported(String),

    /// [`crate::family::FamilyClient::new`] refused to construct a client
    /// that would send a bearer token to a non-`https` origin. `http` is
    /// allowed only for `localhost`/`127.0.0.1`/`::1`, so tests (and a
    /// mocked server bound to loopback) keep working without weakening the
    /// production guarantee: a real access token must never cross the
    /// network in the clear.
    #[error("refusing to send a bearer token over an insecure transport: {0}")]
    InsecureTransport(String),
}
