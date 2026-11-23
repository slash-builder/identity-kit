//! Family-graph client — rooted on the person ("standalone-first
//! identity").
//!
//! Every operation here takes or returns a *person's* memberships, never a
//! household's member list keyed off an account-level role — there isn't
//! one. This client implements the wire-shape half of that data model.
//!
//! Aligned against a real identity service; every deviation from this
//! client's earlier best-guess shapes is called out inline below rather
//! than silently absorbed. Two security findings reached this client
//! directly:
//!
//! - **Child creation:** the original `create_child` design let any
//!   household adult capture an *existing* identity as their "child" by
//!   naming its `account_id`. The identity service removed the whole
//!   client-supplied-account-id path — `create_child` now parses no
//!   request body and always `501`s. This client follows: there is no
//!   `CreateChildRequest`/`CreateChildResponse` anymore, and
//!   `FamilyClient::create_child` takes no request, same posture as
//!   `emancipate`. [`crate::account::GuardianEdge`] and its `::new` guard
//!   stay — they're a client-side invariant independent of that removed
//!   endpoint, kept for whenever a safe, server-minted implementation
//!   replaces it.
//! - **Invitations:** joining a household is now invite-then-accept, not a
//!   direct add, so a person's own act of consent is what creates real
//!   membership. `invite`/`accept_invite` below replace the old `join`.
//!
//! [`guard_last_owner_leave`] and [`crate::account::GuardianEdge::new`]
//! are the invariants from the shared data model that are fully
//! expressible client-side, and are unit-tested as such below —
//! everything server-authoritative is covered by `error_from_parts`'s
//! tests instead.

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use chrono::{DateTime, Utc};

#[allow(deprecated)]
use crate::account::FamilyMember;
use crate::account::{Account, FamilyRole, Membership, MembershipState};
use crate::IdentityError;

/// Talks to an identity service's membership/roster endpoints.
pub struct FamilyClient {
    http: reqwest::Client,
    base_url: String,
    access_token: String,
}

/// Request body for [`FamilyClient::invite`].
///
/// `household` is **not** a field here — identity-service takes it from
/// the path (`POST /households/{household_id}/memberships`), and having
/// it in both places invites a mismatch. `person` is renamed
/// `account_id` and `display_name` is added to match that service's own
/// `InviteMemberRequest` exactly (see its README's alignment table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    /// The `id` of the account being invited.
    pub account_id: Uuid,
    /// A display name for the invitee, sent as given in the request body. This crate does not interpret it.
    pub display_name: String,
    /// The role the invitee will hold. It is fixed at invite time; [`FamilyClient::accept_invite`] sends no body. This
    /// crate sends the role as given and does not check it.
    pub role: FamilyRole,
}

/// The wire shape identity-service actually returns for a single
/// membership row (`MemberRecord` in that service's `src/models.rs`) —
/// used by [`FamilyClient::invite`], [`FamilyClient::accept_invite`], and
/// [`FamilyClient::list_memberships`]'s responses. Every row carries its
/// own `household_id` (fixed server-side after an earlier gap where
/// `GET /people/{id}/memberships` omitted it — see that service's commit
/// history — this client no longer needs to be handed a household id
/// separately to build a full [`Membership`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipRecord {
    /// The `id` of the member's account. Becomes [`Membership::person`] in [`MembershipRecord::into_membership`].
    pub account_id: Uuid,
    /// The `id` of the household. Becomes [`Membership::household`] in [`MembershipRecord::into_membership`].
    /// [`FamilyClient::invite`] and [`FamilyClient::accept_invite`] fail if it differs from the household they targeted.
    pub household_id: Uuid,
    /// The household's own `display_name`, when cheaply available
    /// server-side. `None` on endpoints that don't fetch it (e.g. the
    /// household-scoped roster read, where the caller already supplied
    /// the household) or when the lookup missed.
    pub household_display_name: Option<String>,
    /// The member's display name as the identity service reports it. [`MembershipRecord::into_membership`] does not
    /// carry it into the [`Membership`].
    pub display_name: String,
    /// The member's role. Becomes [`Membership::role`] in [`MembershipRecord::into_membership`].
    pub role: FamilyRole,
    /// When the member joined (UTC), as the identity service reports it. Becomes [`Membership::joined_at`] in
    /// [`MembershipRecord::into_membership`].
    pub joined_at: DateTime<Utc>,
    /// Left as an open string, matching the identity service's own
    /// member-record `state` — currently `"active"` or `"pending"` (an
    /// owner-sent invite the invitee hasn't accepted yet), with more
    /// states a documented future extension point. See
    /// [`MembershipRecord::into_membership`] for what happens if the
    /// server ever sends a value this client's `MembershipState` doesn't
    /// know yet.
    pub state: String,
}

impl MembershipRecord {
    /// Convert this wire row into a full [`Membership`].
    ///
    /// Fails rather than guesses if `state` isn't a value this client's
    /// `MembershipState` recognizes yet — `MembershipState` is
    /// `#[non_exhaustive]` precisely so identity-service can add a new
    /// state without breaking this client at compile time, but a client
    /// build that predates that addition still needs to say so instead
    /// of silently mislabeling it.
    pub fn into_membership(self) -> Result<Membership, IdentityError> {
        let state = match self.state.as_str() {
            "active" => MembershipState::Active,
            "pending" => MembershipState::Pending,
            other => {
                return Err(IdentityError::Transport(format!(
                    "identity-service returned membership state {other:?}, which this \
                     identity-kit build's MembershipState doesn't recognize yet"
                )))
            }
        };
        Ok(Membership {
            person: self.account_id,
            household: self.household_id,
            role: self.role,
            joined_at: self.joined_at,
            state,
        })
    }
}

impl FamilyClient {
    /// Construct a client against a running identity-service instance.
    ///
    /// `access_token` is an access token the caller has
    /// already obtained; it is forwarded verbatim, and not inspected, as `Authorization: Bearer` on
    /// every call — identity-service is an OAuth2 resource server (see
    /// its README's "API contract"); this Kit never collects or mints
    /// credentials itself.
    ///
    /// **Refuses a non-`https` `base_url`** (security finding): a bearer token must never cross the network
    /// in the clear. `http` is allowed only for `localhost`/`127.0.0.1`/
    /// `::1`, so local tests (and a mocked server bound to loopback) keep
    /// working — see `validate_base_url`.
    pub fn new(
        base_url: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        let base_url = base_url.into();
        validate_base_url(&base_url)?;

        let http = crate::transport::http_client_builder()
            .build()
            .map_err(|e| IdentityError::Transport(format!("building HTTP client: {e}")))?;
        Ok(Self {
            http,
            base_url,
            access_token: access_token.into(),
        })
    }

    fn url(&self, path: &str) -> Result<reqwest::Url, IdentityError> {
        let trimmed = self.base_url.trim_end_matches('/');
        let raw = format!("{trimmed}/{path}");
        reqwest::Url::parse(&raw)
            .map_err(|e| IdentityError::Transport(format!("building request URL {raw:?}: {e}")))
    }

    /// `GET /people/{account_id}/memberships` — every household
    /// membership `person` currently holds, active or pending. **Not
    /// filtered** — unlike the household-scoped roster read, this is
    /// currently the only way a caller discovers their own pending
    /// invites (identity-service has no separate "list my invites"
    /// endpoint yet).
    pub async fn list_memberships(
        &self,
        person: Uuid,
    ) -> Result<Vec<MembershipRecord>, IdentityError> {
        let url = self.url(&format!("people/{person}/memberships"))?;
        let response = self
            .http
            .get(url.clone())
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("GET {url} failed: {e}")))?;
        if !response.status().is_success() {
            return Err(map_error_response(response).await);
        }
        response.json().await.map_err(|e| {
            IdentityError::Transport(format!("GET {url} response was not valid JSON: {e}"))
        })
    }

    /// `POST /households/{household_id}/memberships` — **invite**, owner
    /// only (this used to add directly; a person joining a
    /// household is supposed to be their own act). Creates a
    /// `state: "pending"` row; performs no Keycloak write, so the invitee
    /// gains no real authority until they accept — see
    /// [`FamilyClient::accept_invite`].
    pub async fn invite(
        &self,
        household: Uuid,
        request: InviteMemberRequest,
    ) -> Result<Membership, IdentityError> {
        let url = self.url(&format!("households/{household}/memberships"))?;
        let response = self
            .http
            .post(url.clone())
            .bearer_auth(&self.access_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("POST {url} failed: {e}")))?;
        if !response.status().is_success() {
            return Err(map_error_response(response).await);
        }
        let record: MembershipRecord = response.json().await.map_err(|e| {
            IdentityError::Transport(format!("POST {url} response was not valid JSON: {e}"))
        })?;
        check_household_matches(&record, household)?;
        record.into_membership()
    }

    /// `POST /households/{household_id}/memberships/{account_id}/accept`
    /// — accept a pending invite. Only the invitee, with their own token
    /// (identity-service returns `403` for anyone else, including the
    /// inviting owner). No request body: the role was fixed at invite
    /// time. This is the only call that turns a pending invite into a
    /// real membership — the Keycloak write happens here.
    pub async fn accept_invite(
        &self,
        household: Uuid,
        person: Uuid,
    ) -> Result<Membership, IdentityError> {
        let url = self.url(&format!(
            "households/{household}/memberships/{person}/accept"
        ))?;
        let response = self
            .http
            .post(url.clone())
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("POST {url} failed: {e}")))?;
        if !response.status().is_success() {
            return Err(map_error_response(response).await);
        }
        let record: MembershipRecord = response.json().await.map_err(|e| {
            IdentityError::Transport(format!("POST {url} response was not valid JSON: {e}"))
        })?;
        check_household_matches(&record, household)?;
        record.into_membership()
    }

    /// `DELETE /households/{household_id}/memberships/{account_id}` — no
    /// request body (identity-service's `DELETE` endpoints never take
    /// one; `household`/`person` are already in the path). Deletes the
    /// membership row (active or still-pending); never the account.
    /// Idempotent server-side: removing an account that isn't currently a
    /// member isn't an error.
    ///
    /// A household must keep at least one `Owner` membership — see
    /// [`guard_last_owner_leave`] for the client-expressible half of that
    /// invariant, callable ahead of this round trip against a cached
    /// roster. identity-service re-checks authoritatively regardless
    /// (`409 last_owner`, surfaced here as `IdentityError::LastOwner`).
    pub async fn leave(&self, household: Uuid, person: Uuid) -> Result<(), IdentityError> {
        let url = self.url(&format!("households/{household}/memberships/{person}"))?;
        let response = self
            .http
            .delete(url.clone())
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("DELETE {url} failed: {e}")))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(map_error_response(response).await)
        }
    }

    /// `POST /households/{household_id}/children` — **stub, always
    /// `501`.**
    ///
    /// Security finding (blocking): the
    /// original design took a client-supplied `child_account_id` and
    /// trusted it, which let any household adult capture an *existing*
    /// identity as their "child." identity-service removed that path
    /// entirely rather than patching it — this endpoint now parses no
    /// request body server-side and always `501`s, so there is no
    /// request type here either. The only safe implementation mints a
    /// new Keycloak user server-side, inside the call; until that lands,
    /// this is a real HTTP call against a real (owner-only) route that
    /// can't succeed, same posture as [`FamilyClient::emancipate`].
    pub async fn create_child(&self, household: Uuid) -> Result<(), IdentityError> {
        let url = self.url(&format!("households/{household}/children"))?;
        let response = self
            .http
            .post(url.clone())
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("POST {url} failed: {e}")))?;
        if response.status().is_success() {
            // No success response shape exists — identity-service always
            // 501s this route today. Fail loudly rather than silently
            // succeed if that ever changes underfoot.
            return Err(IdentityError::Transport(format!(
                "POST {url} returned {} but create_child has no defined success response shape yet",
                response.status()
            )));
        }
        Err(map_error_response(response).await)
    }

    /// `POST /people/{account_id}/emancipate`.
    ///
    /// This is a real HTTP call against a real route — but
    /// identity-service's handler unconditionally answers `501` today
    /// (see its `handlers::children::emancipate` doc comment: emancipation
    /// needs a device-side re-key/escrow-destruction attestation that
    /// service has no way to obtain or verify yet). Surfaces as
    /// `IdentityError::NotYetSupported`, not a fabricated success.
    pub async fn emancipate(&self, child: Uuid) -> Result<Account, IdentityError> {
        let url = self.url(&format!("people/{child}/emancipate"))?;
        let response = self
            .http
            .post(url.clone())
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("POST {url} failed: {e}")))?;
        if response.status().is_success() {
            // No success response shape is documented — identity-service
            // always 501s this route today. Fail loudly rather than
            // return a fabricated Account if that ever changes underfoot.
            return Err(IdentityError::Transport(format!(
                "POST {url} returned {} but emancipate has no defined success response shape yet",
                response.status()
            )));
        }
        Err(map_error_response(response).await)
    }

    /// **Deprecated.** See [`FamilyMember`]'s doc comment: a role is
    /// per-membership now, not per-account. Use
    /// [`FamilyClient::list_memberships`]. No equivalent endpoint exists
    /// server-side to align this against — kept as a client-only stub that returns
    /// [`IdentityError::NotImplemented`].
    #[deprecated(
        since = "0.2.0",
        note = "role is per-membership, not per-account; use `FamilyClient::list_memberships`"
    )]
    #[allow(deprecated)]
    pub async fn fetch_members(
        &self,
        _owner: &Account,
    ) -> Result<Vec<FamilyMember>, IdentityError> {
        Err(IdentityError::NotImplemented(
            "superseded by FamilyClient::list_memberships; kept for source compat",
        ))
    }
}

/// Refuses to build a client that would send a bearer token to a
/// non-`https` origin. `http` is allowed only when the host is
/// `localhost`, `127.0.0.1`, or `::1` — wiremock (and any other loopback
/// test server) binds there, so tests don't need a self-signed TLS setup,
/// but a real deployment target always needs `https`.
fn validate_base_url(base_url: &str) -> Result<(), IdentityError> {
    let url = reqwest::Url::parse(base_url).map_err(|e| {
        IdentityError::Transport(format!(
            "FamilyClient base_url {base_url:?} is not a valid URL: {e}"
        ))
    })?;
    crate::transport::ensure_secure_url(&url, "FamilyClient base_url")
}

/// Defensive integrity check: [`MembershipRecord::household_id`] should
/// always equal the `household` the call was made against. A mismatch
/// means either a server bug or a mixed-up response, not something to
/// silently trust.
fn check_household_matches(
    record: &MembershipRecord,
    household: Uuid,
) -> Result<(), IdentityError> {
    if record.household_id != household {
        Err(IdentityError::Transport(format!(
            "response household_id ({}) does not match the household the call targeted ({household})",
            record.household_id
        )))
    } else {
        Ok(())
    }
}

/// Client-side pre-flight guard for the last-owner invariant: a
/// household must keep at least one `Owner` membership, so leaving the
/// last owner is refused.
///
/// This is optimistic and local — it only ever sees the roster the caller
/// hands it, typically from a prior [`FamilyClient::list_memberships`]
/// call, so it can go stale before the real `leave()` round trip lands.
/// identity-service is the authority and re-checks server-side
/// regardless; this exists so a caller (e.g. a UI) can fail fast with the
/// same typed error the server would eventually return, and so that
/// invariant is unit-testable here without a network call.
pub fn guard_last_owner_leave(
    household_roster: &[Membership],
    leaving: Uuid,
) -> Result<(), IdentityError> {
    let Some(leaving_membership) = household_roster.iter().find(|m| m.person == leaving) else {
        // Not present in the roster handed in — nothing to refuse locally;
        // let the round trip surface whatever the server thinks is true.
        return Ok(());
    };

    if leaving_membership.role != FamilyRole::Owner {
        return Ok(());
    }

    let remaining_owners = household_roster
        .iter()
        .filter(|m| m.household == leaving_membership.household)
        .filter(|m| m.person != leaving && m.role == FamilyRole::Owner)
        .count();

    if remaining_owners == 0 {
        return Err(IdentityError::LastOwner {
            household: leaving_membership.household,
        });
    }

    Ok(())
}

/// Maps identity-service's error envelope
/// (`{"error": "<code>", "message"?: ..., ...}` — see its README's "API
/// contract") to a typed [`IdentityError`], reconstructing `LastOwner`
/// from the `409` payload's `household_id` field rather than
/// string-matching a message, per that service's own documented intent.
/// There is no `invalid_guardian_edge` mapping any more — identity-service
/// stopped returning it when it removed the endpoint that used
/// to produce it (see `crate::error::IdentityError::InvalidGuardianEdge`'s
/// doc comment).
///
/// A free function over `(StatusCode, &Value)` rather than a
/// `reqwest::Response` directly, so it's unit-testable without a live or
/// mocked HTTP round trip.
fn error_from_parts(status: StatusCode, body: &Value) -> IdentityError {
    let code = body.get("error").and_then(Value::as_str).unwrap_or("");
    let message = body.get("message").and_then(Value::as_str);

    match (status.as_u16(), code) {
        (409, "last_owner") => match body
            .get("household_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            Some(household) => IdentityError::LastOwner { household },
            None => IdentityError::Transport(format!(
                "identity-service returned 409 last_owner without a parseable household_id: {body}"
            )),
        },
        (501, _) => {
            IdentityError::NotYetSupported(message.map(str::to_string).unwrap_or_else(|| {
                "identity-service has not implemented this endpoint yet".to_string()
            }))
        }
        (401, _) | (403, _) => IdentityError::Auth(
            message
                .map(str::to_string)
                .unwrap_or_else(|| format!("identity-service returned {status}")),
        ),
        _ => IdentityError::Transport(match message {
            Some(m) => format!("identity-service returned {status}: {m}"),
            None => format!("identity-service returned {status}: {body}"),
        }),
    }
}

async fn map_error_response(response: reqwest::Response) -> IdentityError {
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    error_from_parts(status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::account::{AccountOrigin, GuardianEdge};

    fn membership(person: Uuid, household: Uuid, role: FamilyRole) -> Membership {
        Membership {
            person,
            household,
            role,
            joined_at: Utc::now(),
            state: MembershipState::Active,
        }
    }

    #[test]
    fn guard_refuses_the_last_owner_leaving() {
        let household = Uuid::new_v4();
        let only_owner = Uuid::new_v4();
        let roster = vec![membership(only_owner, household, FamilyRole::Owner)];

        let result = guard_last_owner_leave(&roster, only_owner);
        assert!(
            matches!(result, Err(IdentityError::LastOwner { household: h }) if h == household),
            "expected IdentityError::LastOwner({household}), got {result:?}"
        );
    }

    #[test]
    fn guard_allows_an_owner_leaving_when_another_owner_remains() {
        let household = Uuid::new_v4();
        let leaving = Uuid::new_v4();
        let staying = Uuid::new_v4();
        let roster = vec![
            membership(leaving, household, FamilyRole::Owner),
            membership(staying, household, FamilyRole::Owner),
        ];

        assert!(guard_last_owner_leave(&roster, leaving).is_ok());
    }

    #[test]
    fn guard_allows_a_non_owner_leaving_regardless_of_roster() {
        let household = Uuid::new_v4();
        let leaving = Uuid::new_v4();
        let roster = vec![membership(leaving, household, FamilyRole::Adult)];

        assert!(guard_last_owner_leave(&roster, leaving).is_ok());
    }

    #[test]
    fn guard_ignores_owners_in_a_different_household() {
        // A person's other-household ownerships must never count as a
        // spare owner for *this* household's last-owner check.
        let household = Uuid::new_v4();
        let other_household = Uuid::new_v4();
        let leaving = Uuid::new_v4();
        let same_person_elsewhere = Uuid::new_v4();
        let roster = vec![
            membership(leaving, household, FamilyRole::Owner),
            membership(same_person_elsewhere, other_household, FamilyRole::Owner),
        ];

        let result = guard_last_owner_leave(&roster, leaving);
        assert!(matches!(result, Err(IdentityError::LastOwner { household: h }) if h == household));
    }

    #[test]
    fn guardian_edge_rejects_a_standalone_child() {
        let child = Account::new(Uuid::new_v4(), "Kid", None, AccountOrigin::Standalone);

        let result = GuardianEdge::new(&child, Uuid::new_v4(), Uuid::new_v4(), Utc::now(), true);

        assert!(
            matches!(result, Err(IdentityError::InvalidGuardianEdge { child: c }) if c == child.id),
            "a standalone-origin child must never accept a guardian edge, got {result:?}"
        );
    }

    #[test]
    fn guardian_edge_accepts_a_created_in_household_child() {
        let child = Account::new(
            Uuid::new_v4(),
            "Kid",
            None,
            AccountOrigin::CreatedInHousehold,
        );
        let guardian = Uuid::new_v4();
        let household = Uuid::new_v4();

        let edge = GuardianEdge::new(&child, guardian, household, Utc::now(), true)
            .expect("a created-in-household child accepts a guardian edge");

        assert_eq!(edge.child, child.id);
        assert_eq!(edge.guardian, guardian);
        assert_eq!(edge.household_of_creation, household);
        assert!(edge.escrow);
    }

    fn wire_record(household: Uuid, state: &str) -> MembershipRecord {
        MembershipRecord {
            account_id: Uuid::new_v4(),
            household_id: household,
            household_display_name: None,
            display_name: "Ada".to_string(),
            role: FamilyRole::Adult,
            joined_at: Utc::now(),
            state: state.to_string(),
        }
    }

    #[test]
    fn membership_record_into_membership_maps_the_active_state() {
        let household = Uuid::new_v4();
        let record = wire_record(household, "active");

        let membership = record
            .clone()
            .into_membership()
            .expect("\"active\" is a recognized state");
        assert_eq!(membership.person, record.account_id);
        assert_eq!(membership.household, household);
        assert_eq!(membership.role, record.role);
        assert_eq!(membership.state, MembershipState::Active);
    }

    #[test]
    fn membership_record_into_membership_maps_the_pending_state() {
        let household = Uuid::new_v4();
        let record = wire_record(household, "pending");

        let membership = record
            .into_membership()
            .expect("\"pending\" is a recognized state (invite/accept)");
        assert_eq!(membership.state, MembershipState::Pending);
    }

    #[test]
    fn membership_record_into_membership_rejects_an_unrecognized_state() {
        let record = wire_record(Uuid::new_v4(), "suspended");

        let result = record.into_membership();
        assert!(matches!(result, Err(IdentityError::Transport(_))));
    }

    #[test]
    fn error_from_parts_maps_409_last_owner_by_field_not_message() {
        let household = Uuid::new_v4();
        let body = json!({ "error": "last_owner", "household_id": household.to_string() });

        let err = error_from_parts(StatusCode::CONFLICT, &body);
        assert!(matches!(err, IdentityError::LastOwner { household: h } if h == household));
    }

    #[test]
    fn error_from_parts_no_longer_special_cases_invalid_guardian_edge() {
        // The identity service never sends this anymore — any
        // 409 that isn't last_owner (including this now-dead code) falls
        // through to the generic Transport mapping.
        let child = Uuid::new_v4();
        let body =
            json!({ "error": "invalid_guardian_edge", "child_account_id": child.to_string() });

        let err = error_from_parts(StatusCode::CONFLICT, &body);
        assert!(matches!(err, IdentityError::Transport(_)));
    }

    #[test]
    fn error_from_parts_maps_501_to_not_yet_supported() {
        let body = json!({ "error": "not_implemented", "message": "emancipation needs a device attestation" });

        let err = error_from_parts(StatusCode::NOT_IMPLEMENTED, &body);
        match err {
            IdentityError::NotYetSupported(msg) => {
                assert!(msg.contains("device attestation"))
            }
            other => panic!("expected NotYetSupported, got {other:?}"),
        }
    }

    #[test]
    fn error_from_parts_maps_401_and_403_to_auth() {
        let body = json!({ "error": "unauthorized" });
        assert!(matches!(
            error_from_parts(StatusCode::UNAUTHORIZED, &body),
            IdentityError::Auth(_)
        ));
        assert!(matches!(
            error_from_parts(StatusCode::FORBIDDEN, &body),
            IdentityError::Auth(_)
        ));
    }

    #[test]
    fn error_from_parts_falls_back_to_transport_for_anything_else() {
        let body = json!({ "error": "internal_error" });
        assert!(matches!(
            error_from_parts(StatusCode::INTERNAL_SERVER_ERROR, &body),
            IdentityError::Transport(_)
        ));
    }

    #[test]
    fn validate_base_url_accepts_https() {
        assert!(validate_base_url("https://identity.example.com").is_ok());
    }

    #[test]
    fn validate_base_url_accepts_http_on_loopback_hosts() {
        assert!(validate_base_url("http://localhost:8080").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_base_url("http://[::1]:8080").is_ok());
    }

    #[test]
    fn validate_base_url_refuses_http_on_a_non_loopback_host() {
        let result = validate_base_url("http://identity.example.com");
        assert!(matches!(result, Err(IdentityError::InsecureTransport(_))));
    }

    #[test]
    fn family_client_new_refuses_a_non_https_non_loopback_base_url() {
        let result = FamilyClient::new("http://identity.example.com", "test-token");
        assert!(matches!(result, Err(IdentityError::InsecureTransport(_))));
    }

    // ---- real HTTP round trips against a local mock identity-service
    // (wiremock, no live network) — proves the URL/method/header/body
    // wiring, not just the pure mapping functions above. ------------------
    mod http {
        use super::*;
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        #[tokio::test]
        async fn list_memberships_sends_bearer_auth_and_parses_the_wire_array() {
            let server = MockServer::start().await;
            let client = FamilyClient::new(server.uri(), "test-token").unwrap();
            let person = Uuid::new_v4();
            let account_id = Uuid::new_v4();
            let household = Uuid::new_v4();

            Mock::given(method("GET"))
                .and(path(format!("/people/{person}/memberships")))
                .and(header("authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                    "account_id": account_id.to_string(),
                    "household_id": household.to_string(),
                    "household_display_name": "Example Family",
                    "display_name": "Ada",
                    "role": "adult",
                    "joined_at": Utc::now().to_rfc3339(),
                    "state": "active",
                }])))
                .mount(&server)
                .await;

            let records = client.list_memberships(person).await.unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].account_id, account_id);
            assert_eq!(records[0].household_id, household);
            assert_eq!(records[0].role, FamilyRole::Adult);
        }

        #[tokio::test]
        async fn invite_posts_to_the_household_scoped_path_and_builds_a_pending_membership() {
            let server = MockServer::start().await;
            let client = FamilyClient::new(server.uri(), "test-token").unwrap();
            let household = Uuid::new_v4();
            let account_id = Uuid::new_v4();

            Mock::given(method("POST"))
                .and(path(format!("/households/{household}/memberships")))
                .and(header("authorization", "Bearer test-token"))
                .and(body_string_contains("\"account_id\""))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "account_id": account_id.to_string(),
                    "household_id": household.to_string(),
                    "household_display_name": null,
                    "display_name": "Jane",
                    "role": "adult",
                    "joined_at": Utc::now().to_rfc3339(),
                    "state": "pending",
                })))
                .mount(&server)
                .await;

            let membership = client
                .invite(
                    household,
                    InviteMemberRequest {
                        account_id,
                        display_name: "Jane".to_string(),
                        role: FamilyRole::Adult,
                    },
                )
                .await
                .unwrap();

            assert_eq!(membership.person, account_id);
            assert_eq!(membership.household, household);
            assert_eq!(membership.role, FamilyRole::Adult);
            assert_eq!(membership.state, MembershipState::Pending);
        }

        #[tokio::test]
        async fn accept_invite_posts_to_the_accept_path_with_no_body_and_builds_an_active_membership(
        ) {
            let server = MockServer::start().await;
            let client = FamilyClient::new(server.uri(), "test-token").unwrap();
            let household = Uuid::new_v4();
            let person = Uuid::new_v4();

            Mock::given(method("POST"))
                .and(path(format!(
                    "/households/{household}/memberships/{person}/accept"
                )))
                .and(header("authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "account_id": person.to_string(),
                    "household_id": household.to_string(),
                    "household_display_name": null,
                    "display_name": "Jane",
                    "role": "adult",
                    "joined_at": Utc::now().to_rfc3339(),
                    "state": "active",
                })))
                .mount(&server)
                .await;

            let membership = client.accept_invite(household, person).await.unwrap();
            assert_eq!(membership.person, person);
            assert_eq!(membership.household, household);
            assert_eq!(membership.state, MembershipState::Active);
        }

        #[tokio::test]
        async fn leave_sends_no_body_and_succeeds_on_204() {
            let server = MockServer::start().await;
            let client = FamilyClient::new(server.uri(), "test-token").unwrap();
            let household = Uuid::new_v4();
            let person = Uuid::new_v4();

            Mock::given(method("DELETE"))
                .and(path(format!(
                    "/households/{household}/memberships/{person}"
                )))
                .and(header("authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;

            client.leave(household, person).await.unwrap();
        }

        #[tokio::test]
        async fn leave_maps_a_409_last_owner_response_to_a_typed_error() {
            let server = MockServer::start().await;
            let client = FamilyClient::new(server.uri(), "test-token").unwrap();
            let household = Uuid::new_v4();
            let person = Uuid::new_v4();

            Mock::given(method("DELETE"))
                .and(path(format!(
                    "/households/{household}/memberships/{person}"
                )))
                .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                    "error": "last_owner",
                    "household_id": household.to_string(),
                })))
                .mount(&server)
                .await;

            let result = client.leave(household, person).await;
            assert!(
                matches!(result, Err(IdentityError::LastOwner { household: h }) if h == household)
            );
        }

        #[tokio::test]
        async fn create_child_takes_no_body_and_maps_the_servers_501_to_not_yet_supported() {
            let server = MockServer::start().await;
            let client = FamilyClient::new(server.uri(), "test-token").unwrap();
            let household = Uuid::new_v4();

            Mock::given(method("POST"))
                .and(path(format!("/households/{household}/children")))
                .and(header("authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(501).set_body_json(json!({
                    "error": "not_implemented",
                    "message": "child creation requires this service to mint a new Keycloak user",
                })))
                .mount(&server)
                .await;

            let result = client.create_child(household).await;
            match result {
                Err(IdentityError::NotYetSupported(msg)) => {
                    assert!(msg.contains("mint a new Keycloak user"))
                }
                other => panic!("expected NotYetSupported, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn emancipate_maps_the_servers_501_to_not_yet_supported() {
            let server = MockServer::start().await;
            let client = FamilyClient::new(server.uri(), "test-token").unwrap();
            let child = Uuid::new_v4();

            Mock::given(method("POST"))
                .and(path(format!("/people/{child}/emancipate")))
                .respond_with(ResponseTemplate::new(501).set_body_json(json!({
                    "error": "not_implemented",
                    "message": "emancipation requires a device-side re-key attestation",
                })))
                .mount(&server)
                .await;

            let result = client.emancipate(child).await;
            match result {
                Err(IdentityError::NotYetSupported(msg)) => {
                    assert!(msg.contains("device-side re-key"))
                }
                other => panic!("expected NotYetSupported, got {other:?}"),
            }
        }
    }
}
