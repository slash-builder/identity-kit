//! AuthZ primitives — capability tokens and scope evaluation.
//!
//! The authorization engine and its client primitives are deferred.
//!
//! [`ServicePrincipal`] is the exception: it is the grant-holding subject
//! type that other Kits (substrate-kit, fabric-kit) embody rather than
//! redefine. It is a data model, not an enforcement mechanism —
//! enforcement (for example capability tokens with proof of possession) is
//! the job of the consuming application, not this Kit.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A scope of action — a single capability a token may grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope(pub String);

/// A bundle of scopes presented during an authorization check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    pub scopes: Vec<Scope>,
}

impl Capabilities {
    /// Build a capability bundle from an explicit set of scopes.
    pub fn new(scopes: Vec<Scope>) -> Self {
        Self { scopes }
    }

    pub fn includes(&self, required: &Scope) -> bool {
        self.scopes.contains(required)
    }
}

/// Opaque, stable identifier for a [`ServicePrincipal`].
///
/// Wraps a UUID rather than exposing one directly so callers can't rely on
/// UUID-specific structure (version, generation scheme) as part of the
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(Uuid);

impl PrincipalId {
    /// Generate a new, random principal id.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an already-known UUID as a principal id (e.g. when rehydrating
    /// a principal from storage).
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// The underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for PrincipalId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A plain, grant-holding subject.
///
/// `ServicePrincipal` pairs a stable [`PrincipalId`] with the
/// [`Capabilities`] it holds, plus an optional link to the device/family
/// identity that established it. It is the linchpin type that other Kits'
/// principal and capability seams consume verbatim.
///
/// **Hard constraint:** this type carries no persisted circle, no trust
/// tier, and no role-as-trust — those are enforcement concerns that live
/// in the enforcing application, not here. A `ServicePrincipal` *holds* grants; it does not
/// decide what they're worth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePrincipal {
    id: PrincipalId,
    device: Option<Uuid>,
    capabilities: Capabilities,
}

impl ServicePrincipal {
    /// Construct a new principal with a freshly generated id.
    pub fn new(device: Option<Uuid>, capabilities: Capabilities) -> Self {
        Self {
            id: PrincipalId::new(),
            device,
            capabilities,
        }
    }

    /// Construct a principal with an explicit, already-known id — e.g.
    /// when rehydrating one from storage or a wire payload.
    pub fn with_id(id: PrincipalId, device: Option<Uuid>, capabilities: Capabilities) -> Self {
        Self {
            id,
            device,
            capabilities,
        }
    }

    /// The principal's stable, opaque id.
    pub fn id(&self) -> PrincipalId {
        self.id
    }

    /// The device/family identity this principal is linked to, if any.
    pub fn device(&self) -> Option<Uuid> {
        self.device
    }

    /// The capabilities this principal holds.
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Whether this principal holds the given scope. Delegates to
    /// [`Capabilities::includes`].
    pub fn has(&self, scope: &Scope) -> bool {
        self.capabilities.includes(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(s: &str) -> Scope {
        Scope(s.to_string())
    }

    #[test]
    fn capabilities_includes_present_scope() {
        let caps = Capabilities::new(vec![scope("read:account"), scope("write:family")]);
        assert!(caps.includes(&scope("read:account")));
        assert!(!caps.includes(&scope("admin:everything")));
    }

    #[test]
    fn service_principal_new_generates_a_fresh_id() {
        let a = ServicePrincipal::new(None, Capabilities::default());
        let b = ServicePrincipal::new(None, Capabilities::default());
        assert_ne!(
            a.id(),
            b.id(),
            "each new() principal should get a distinct id"
        );
    }

    #[test]
    fn service_principal_with_id_round_trips() {
        let id = PrincipalId::new();
        let principal = ServicePrincipal::with_id(id, None, Capabilities::default());
        assert_eq!(principal.id(), id);
    }

    #[test]
    fn principal_id_from_uuid_and_as_uuid_round_trip() {
        // The rehydrate-from-storage path this type exists for (see
        // `from_uuid`'s doc comment) — previously untested; every other
        // test here only ever exercises `PrincipalId::new()`.
        let raw = Uuid::new_v4();
        let id = PrincipalId::from_uuid(raw);
        assert_eq!(id.as_uuid(), raw);
        assert_eq!(id.to_string(), raw.to_string());
    }

    #[test]
    fn service_principal_carries_optional_device_link() {
        let device = Uuid::new_v4();
        let with_device = ServicePrincipal::new(Some(device), Capabilities::default());
        let without_device = ServicePrincipal::new(None, Capabilities::default());

        assert_eq!(with_device.device(), Some(device));
        assert_eq!(without_device.device(), None);
    }

    /// Guard test for the new client-credentials construction site
    /// (`crate::authn::keycloak::client_role_capabilities`, LS-service-
    /// principals): a `ServicePrincipal` built from a Client Credentials
    /// access token never carries a `FamilyRole` or household-group-
    /// derived scope, even when the token's claims include a `groups`
    /// entry (the interactive PKCE path's household-membership claim).
    /// `ServicePrincipalClaims` has no field for `groups` at all, so this
    /// is proven structurally, not merely by inspection — same
    /// discipline as `service_principal_carries_no_tier_or_circle_field`
    /// above, applied to the new construction site.
    #[test]
    fn service_principal_capabilities_never_reflect_a_groups_claim() {
        use crate::authn::keycloak::client_role_capabilities;
        use jsonwebtoken::{encode, EncodingKey, Header};

        let claims = serde_json::json!({
            "resource_access": { "division-ci": { "roles": ["read:builds"] } },
            "groups": ["/households/11111111-1111-1111-1111-111111111111/owner"],
            // `client_role_capabilities`'s `Validation` requires `exp`
            // present (a real Keycloak token always carries one); not
            // otherwise checked by this test.
            "exp": 9_999_999_999_i64,
        });
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-signing-key"),
        )
        .unwrap();

        let capabilities = client_role_capabilities(&token, "division-ci").unwrap();
        let principal = ServicePrincipal::new(None, capabilities);

        assert!(principal.has(&scope("read:builds")));
        // Nothing in the `groups` claim above could have produced this —
        // `ServicePrincipalClaims` never parses `groups` in the first
        // place.
        assert!(!principal.has(&scope("owner")));
    }

    #[test]
    fn service_principal_has_delegates_to_capabilities_includes() {
        let caps = Capabilities::new(vec![scope("pair:device")]);
        let principal = ServicePrincipal::new(None, caps);

        assert!(principal.has(&scope("pair:device")));
        assert!(!principal.has(&scope("pair:other")));
    }

    /// Guard test, not a behavioural one: this exhaustively destructures
    /// `ServicePrincipal`'s private fields. If anyone adds a `tier`,
    /// `circle`, or other trust-as-role field to the struct, this pattern
    /// stops compiling and the PR has to face the hard constraint
    /// explicitly rather than slip past review unnoticed.
    #[test]
    fn service_principal_carries_no_tier_or_circle_field() {
        let principal = ServicePrincipal::new(None, Capabilities::default());
        let ServicePrincipal {
            id: _,
            device: _,
            capabilities: _,
        } = principal;
    }
}
