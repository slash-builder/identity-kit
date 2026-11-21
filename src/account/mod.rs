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
    /// The account id (`account_id`). The data model says it is never reissued; this crate does not enforce that. For
    /// Keycloak sign-in it is the userinfo `sub`, which must be a UUID or sign-in fails with [`IdentityError::Auth`].
    pub id: Uuid,
    /// The name shown for the person. For an account resolved by Keycloak sign-in it is the first of the userinfo `name`,
    /// `preferred_username`, `email` and `sub` claims that is present (a present but empty value counts as present).
    pub display_name: String,
    /// The person's email address, if known. Keycloak sign-in takes it from the userinfo `email` claim. This crate does
    /// not check whether the address is verified.
    pub email: Option<String>,
    /// How the account came to exist; see [`AccountOrigin`]. Keycloak sign-in always sets [`AccountOrigin::Standalone`].
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
    /// The device id.
    pub id: Uuid,
    /// The `id` of the [`Account`] that claims the device.
    pub account_id: Uuid,
    /// The device's name.
    pub name: String,
    /// The kind of device; see [`DeviceKind`].
    pub kind: DeviceKind,
}

/// The kind of a [`Device`].
///
/// Serialised as the variant name in snake case (`"desktop"`, `"cumulus"`, and so on). This crate attaches no behaviour
/// to any kind; it is carried with the [`Device`] as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// A desktop device.
    Desktop,
    /// A mobile device.
    Mobile,
    /// The `Cumulus` kind.
    Cumulus,
    /// The `Anvil` kind.
    Anvil,
    /// The `Wisp` kind.
    Wisp,
    /// The `Squall` kind.
    Squall,
    /// The `Halcyon` kind.
    Halcyon,
    /// A device that fits none of the other kinds.
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
    /// The household id (`hid`). The data model says a retired id is never reused; this crate does not enforce that.
    pub id: Uuid,
    /// The name shown for the household.
    pub display_name: String,
}

impl Household {
    /// Construct a `Household` from its id and display name.
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
    /// An owner of the household. A household must keep at least one `Owner` membership (see [`Membership`]), and the
    /// identity service accepts [`FamilyClient::invite`](crate::family::FamilyClient::invite) only from an owner.
    Owner,
    /// An adult member. This crate attaches no behaviour to the role beyond carrying it.
    Adult,
    /// A child member. This crate attaches no behaviour to the role beyond carrying it.
    Child,
    /// A guest member. This crate attaches no behaviour to the role beyond carrying it.
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
    /// A real membership.
    Active,
    /// An owner-sent invite the invitee has not accepted yet; see
    /// [`FamilyClient::accept_invite`](crate::family::FamilyClient::accept_invite).
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
    /// The `id` of the [`Account`] that holds the membership.
    pub person: Uuid,
    /// The `id` of the [`Household`] the membership is in.
    pub household: Uuid,
    /// The person's role in this household. Per membership, not per account.
    pub role: FamilyRole,
    /// The `joined_at` timestamp (UTC) the identity service reports for the row. This crate does not interpret it.
    pub joined_at: DateTime<Utc>,
    /// Whether the membership is active or still a pending invite.
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
    /// The `id` of the created child's [`Account`].
    pub child: Uuid,
    /// The guardian's id, as given to [`GuardianEdge::new`], which does not check it.
    pub guardian: Uuid,
    /// The id of the household the child was created in, as given to [`GuardianEdge::new`], which does not check it.
    pub household_of_creation: Uuid,
    /// When the edge was created (UTC), as given to [`GuardianEdge::new`].
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
    /// The member's account.
    pub account: Account,
    /// The member's role.
    pub role: FamilyRole,
}
