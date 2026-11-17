//! Account model — the person, the household, and the person↔household
//! graph between them.
//!
//! Rooted on the person ("standalone-first identity"): a person is fully
//! standalone first, then joins one household or several. `Account` carries no
//! scalar household id; membership and guardianship are their own records
//! below; this file is the client-side half of that data model.
//!
//! Mutation and storage of any of this lives in an identity service
//! (a separate server, not part of this crate) — this Kit only defines
//! the wire-shape types and the client that talks to it
//! (`crate::family::FamilyClient`).
//!
//! [`keycloak::AccountClient`] is a separate, unrelated thing living in this
//! same module: a stateless, token-scoped client against Keycloak's real
//! Account REST API (self-service account maintenance — profile
//! read/update, password change, session/device listing + revocation). It
//! doesn't touch or depend on the person/household model above — see that
//! module's header comment for why it is deliberately not folded into
//! `authn::AuthN` either.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod keycloak;

pub use keycloak::{
    AccountClient, AccountDevice, AccountProfile, AccountProfileUpdate, AccountSession,
    AccountSessionClient,
};

use crate::error::IdentityError;

/// How a person's account came to exist.
///
/// This is provenance, not current membership — a `Standalone` person can
/// still join any number of households, and a `CreatedInHousehold` child
/// keeps that origin even after emancipation (emancipation ends the
/// guardian edges and keeps `account_id`; it does not rewrite history).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountOrigin {
    /// Self-registered; the default and only path for an adult.
    Standalone,
    /// Provisioned by a guardian inside a household. Only this origin may
    /// carry a [`GuardianEdge`] — see [`GuardianEdge::new`].
    CreatedInHousehold,
}

/// A person. The identity root — exists independently of any household.
///
/// `id` is the `account_id` the shared data model keys everything else
/// off of, and is **never reissued**. Deliberately carries no
/// scalar household id: which households this person belongs to, and
/// with what role, lives in [`Membership`] rows, not here,
/// because a person can hold more than one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub display_name: String,
    pub email: Option<String>,
    pub origin: AccountOrigin,
}

impl Account {
    /// Construct an `Account`. Prefer this over a struct literal from
    /// outside the crate so a future additive field here doesn't force
    /// every caller to change at once.
    pub fn new(
        id: Uuid,
        display_name: impl Into<String>,
        email: Option<String>,
        origin: AccountOrigin,
    ) -> Self {
        Self {
            id,
            display_name: display_name.into(),
            email,
            origin,
        }
    }
}

/// A device claimed by an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub kind: DeviceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Desktop,
    Mobile,
    Cumulus,
    Anvil,
    Wisp,
    Squall,
    Halcyon,
    Other,
}

/// A household. Retired household ids (`hid`) are never reused.
///
/// Deliberately carries **no `kind`/type field** — the model rules out any
/// `operator`/business/org/team segmentation on a household, and there is
/// no merge primitive: members join the surviving household and the old
/// id is retired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Household {
    pub id: Uuid,
    pub display_name: String,
}

impl Household {
    pub fn new(id: Uuid, display_name: impl Into<String>) -> Self {
        Self {
            id,
            display_name: display_name.into(),
        }
    }
}

/// A role held within one household membership.
///
/// **Hard constraint (unchanged by this re-root):** this is per-membership
/// context, never a grant. It must never be fed into
/// [`crate::authz::ServicePrincipal`]'s capabilities — see `src/authz.rs`'s
/// "no tier/circle/role-as-trust" hard constraint and its conformance-locked
/// `NoTierInvariant` case. A household `Owner` is not thereby a
/// `ServicePrincipal` with elevated capabilities; capability grants are a
/// wholly separate axis, owned by the enforcing application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyRole {
    Owner,
    Adult,
    Child,
    Guest,
}

/// Lifecycle state of a [`Membership`] row.
///
/// `Active` is a real membership; `Pending` is an owner-sent invite the
/// invitee hasn't accepted yet (joining a household is
/// invite-then-accept, not a direct add — see `crate::family::FamilyClient::invite`/`accept_invite`). A
/// pending row carries no Keycloak authority at all until accepted.
/// `#[non_exhaustive]` — the identity service's own `state` is an
/// intentionally open string (its README calls out a future
/// declined/expired state as a real, not-yet-built extension point), so
/// this client shouldn't need a breaking change to add the next one
/// either.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Active,
    Pending,
}

/// A person × household membership. Its own record — **not** a field on
/// `Account` — because a person may hold several.
///
/// Invariants (enforced server-side by the identity service; the
/// client-expressible half lives in
/// [`crate::family::guard_last_owner_leave`]):
/// - A role is per membership, not per account.
/// - A household keeps at least one `Owner` membership; a last-owner leave
///   is refused (`IdentityError::LastOwner`).
/// - Leaving deletes this row. It never deletes the account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub person: Uuid,
    pub household: Uuid,
    pub role: FamilyRole,
    pub joined_at: DateTime<Utc>,
    pub state: MembershipState,
}

/// A person-to-person guardian edge from a created child to the guardian
/// who created them.
///
/// **Only valid for `origin = CreatedInHousehold` children** — construct
/// through [`GuardianEdge::new`], which enforces that, rather than a
/// struct literal. Emancipation ends these edges and keeps the child's
/// `account_id`; it does not delete the account.
///
/// **Status:**
/// the identity service removed the endpoint that used to mint these —
/// the original `create_child` trusted a client-supplied
/// `child_account_id`, which let any household adult capture an
/// *existing* identity as their "child." That endpoint now parses no
/// request body and always `501`s; there is no server response shape
/// producing a `GuardianEdge` today. This type and its `::new` guard
/// stay: the invariant they enforce is unchanged, and they're what a
/// future safe (server-minted) implementation will build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianEdge {
    pub child: Uuid,
    pub guardian: Uuid,
    pub household_of_creation: Uuid,
    pub created_at: DateTime<Utc>,
    /// Whether the guardian holds an escrowed key for the child. Visible
    /// to the child — never a hidden grant.
    pub escrow: bool,
}

impl GuardianEdge {
    /// Construct a guardian edge for `child`.
    ///
    /// Returns `IdentityError::InvalidGuardianEdge` unless
    /// `child.origin == AccountOrigin::CreatedInHousehold` — a standalone
    /// account never carries a guardian edge; the one exception to
    /// standalone-first is the created-child path and nothing else.
    pub fn new(
        child: &Account,
        guardian: Uuid,
        household_of_creation: Uuid,
        created_at: DateTime<Utc>,
        escrow: bool,
    ) -> Result<Self, IdentityError> {
        if child.origin != AccountOrigin::CreatedInHousehold {
            return Err(IdentityError::InvalidGuardianEdge { child: child.id });
        }
        Ok(Self {
            child: child.id,
            guardian,
            household_of_creation,
            created_at,
            escrow,
        })
    }
}

/// A member of a household, bundled with its role.
///
/// **Deprecated** by the standalone-first re-root (0.2.0): a
/// person can hold memberships in more than one household, so a role is
/// no longer a property of the account — it's per [`Membership`]. Use
/// [`Membership`] (joined with an [`Account`] fetched separately) via
/// `crate::family::FamilyClient::list_memberships` instead. Kept, still
/// compiling, for source compatibility with any existing caller of the
/// now-deprecated `FamilyClient::fetch_members`.
#[deprecated(
    since = "0.2.0",
    note = "role is per-membership, not per-account; use `Membership` via `FamilyClient::list_memberships`"
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyMember {
    pub account: Account,
    pub role: FamilyRole,
}
