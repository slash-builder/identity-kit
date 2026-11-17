//! Error type for Identity Kit operations.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("auth flow failed: {0}")]
    Auth(String),

    #[error("token cache: {0}")]
    Cache(String),

    #[error("transport: {0}")]
    Transport(String),

    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A household must keep at least one `Owner` membership; this
    /// leave would have dropped it to zero. Can come from the client-side
    /// pre-flight guard (`family::guard_last_owner_leave`) or from
    /// the identity service refusing the request authoritatively.
    #[error("household {household} would be left without an owner")]
    LastOwner { household: Uuid },

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
    InvalidGuardianEdge { child: Uuid },

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
