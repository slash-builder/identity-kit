//! # Identity Kit
//!
//! Account, family-graph, AuthN/AuthZ primitives for the SlashBuilder
//! Kit ecosystem. The *client* side of identity — talks to an IdP and an
//! AuthZ engine; doesn't implement either.

#![forbid(unsafe_code)]

pub mod account;
pub mod authn;
pub mod authz;
pub mod error;
pub mod family;
pub mod token;
mod transport;

#[allow(deprecated)]
pub use account::FamilyMember;
pub use account::{
    Account, AccountClient, AccountOrigin, Device, DeviceKind, FamilyRole, GuardianEdge, Household,
    Membership, MembershipState,
};
pub use authn::AuthN;
pub use authz::{Capabilities, PrincipalId, Scope, ServicePrincipal};
pub use error::IdentityError;
pub use token::TokenCache;

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
