//! `AccountClient` — a stateless, token-scoped client against Keycloak's
//! real Account REST API (`{base_url}/realms/{realm}/account/*`), for
//! self-service account maintenance: profile read/update, password
//! change, and session/device listing + revocation.
//!
//! ## Why this is a separate type from `AuthN`, not an extension of it
//!
//! `authn::AuthN` (`src/authn/mod.rs`) owns exactly one thing: standing up
//! and refreshing an interactive, session-owning sign-in. It holds a
//! `TokenCache`, mints/verifies PKCE state, and persists a `Session` across
//! calls. `AccountClient` fits none of that shape. Its typical caller,
//! a backend API, never runs a sign-in flow of its own — it receives an
//! already-validated caller bearer token on every incoming request (minted
//! upstream, by a client app's own PKCE flow through `AuthN`) and needs
//! to relay that same token straight through to Keycloak's `/account/*`
//! endpoints for the lifetime of that one request. There is no session to
//! own, no refresh to schedule, and no PKCE verifier to hold — forcing this
//! through `AuthN` would mean bolting a stateless, per-request bearer-relay
//! shape onto a type whose entire contract is "I own your session."
//! `AccountClient` is deliberately stateless instead: every method takes
//! the caller's bearer token as a parameter, and the client itself holds
//! nothing but an HTTP client and the resolved Account REST API base URL —
//! safe to construct once (e.g. in a web framework's shared application state)
//! and reuse across every request it handles, each with a different
//! caller's token.
//!
//! This also keeps the client on the *self-scoped* side of the trust
//! boundary: Keycloak's `/account/*` endpoints
//! take no user-id parameter — the subject is always resolved from
//! whichever bearer token is presented — so this client can never be
//! pointed at a household member other than whoever the token belongs to.
//! An Admin API credential (which *can* touch any user in
//! the realm) must never be substituted in here as a shortcut; a consumer
//! that genuinely needs to act on someone else's account needs a different,
//! admin-scoped client, not this one.
//!
//! ## A real Keycloak API-shape finding, not a guess
//!
//! `change_password`'s existence was the one endpoint in this module's
//! brief that didn't hold up under verification. Keycloak's Account REST
//! API has never shipped a `/account/credentials/password` endpoint —
//! confirmed by reading `AccountCredentialResource.java` at every tagged
//! `keycloak/keycloak` release from `15.0.0` through the pinned `26.0.0`
//! inclusive; the class only ever exposes credential-type listing, a
//! single-credential delete, and a credential-label update. Real
//! self-service password change on this Keycloak version is an
//! application-initiated-action browser redirect (`kc_action=
//! UPDATE_PASSWORD`), not a bearer-token REST call.
//! [`AccountClient::change_password`] returns
//! `IdentityError::NotImplemented` without making any network call, rather
//! than hitting a URL that would 404 in production; see its doc comment.
//!
//! Everything else in this module's brief is real and confirmed live:
//! `GET`/`POST /account` (profile — see [`AccountClient::get_profile`] and
//! [`AccountClient::update_profile`] for a second, real profile-update
//! finding), `GET /account/sessions/devices` (device list with nested
//! per-session client data — no separate "linked services" endpoint,
//! confirmed from `SessionResource.java`), `DELETE /account/sessions/{id}`
//! (single session), and `DELETE /account/sessions` (bulk revoke of every
//! *other* session — also confirmed real from source; it takes an optional
//! `current` query parameter that defaults to `false`, which this module
//! always sends explicitly rather than relying on the server default).

use serde::{Deserialize, Serialize};
use url::Url;

use crate::IdentityError;

/// Build the Account REST API base URL for a given base URL + realm:
/// `{base_url}/realms/{realm}/account`.
///
/// A free function rather than a method, same reasoning as
/// `authn::keycloak::discovery_url` — directly unit-testable without a
/// constructed client, and it's the seam that has to keep working
/// identically across every realm on the shared Keycloak instance.
fn account_base_url(base_url: &str, realm: &str) -> Result<Url, IdentityError> {
    let trimmed = base_url.trim_end_matches('/');
    let raw = format!("{trimmed}/realms/{realm}/account");
    Url::parse(&raw)
        .map_err(|e| IdentityError::Auth(format!("invalid Account REST API base URL: {e}")))
}

/// The caller's own profile, as returned by
/// `GET /realms/{realm}/account`.
///
/// A subset of Keycloak's `UserRepresentation` (which extends
/// `AbstractUserRepresentation`) — only the fields Account Maintenance
/// needs. Extra server-side fields (e.g. `userProfileMetadata`) are
/// silently ignored, same discipline as
/// `authn::keycloak::OidcDiscoveryDocument`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountProfile {
    /// The user's id (`id`), if Keycloak sends it.
    #[serde(default)]
    pub id: Option<String>,
    /// The username (`username`). Required in the response.
    pub username: String,
    /// The first name (`firstName`), if Keycloak sends it.
    #[serde(default)]
    pub first_name: Option<String>,
    /// The last name (`lastName`), if Keycloak sends it.
    #[serde(default)]
    pub last_name: Option<String>,
    /// The email address (`email`), if Keycloak sends it.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether Keycloak reports the email address as verified (`emailVerified`), if it sends the field.
    #[serde(default)]
    pub email_verified: Option<bool>,
}

/// The request body for [`AccountClient::update_profile`].
///
/// **Deliberately not a sparse patch.** Verified from Keycloak's own
/// `AbstractUserRepresentation::getRawAttributes()` merge logic (the method
/// `updateAccount()` server-side calls to build the attribute set it
/// validates and writes): an included `username` or `email` always
/// replaces the stored value, but an *omitted* one is treated as "clear
/// this field" — there is no partial-update semantics for those two
/// fields. `firstName`/`lastName` are the opposite: omitting them leaves
/// the stored value untouched. That asymmetry is exactly why `username`
/// and `email` are required `String`s here rather than `Option<String>` —
/// making them optional would silently reproduce a real account-data-loss
/// footgun. Callers should [`AccountClient::get_profile`] first, mutate
/// what they actually want to change, and submit the full result — never
/// construct one of these from scratch with fields guessed at.
///
/// Also carries a forward security coupling: changing `email` here is inert
/// only while `reset_password_allowed` is unset on the realm (email isn't
/// yet a recovery factor). The moment that flips, an email change through
/// this type must require re-authentication upstream, or the Account
/// Maintenance screen must stop exposing the email field — this Kit has no
/// way to enforce that from here; it's a caller-side obligation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountProfileUpdate {
    /// The username to store. Always sent; see the type doc for why it is not optional.
    pub username: String,
    /// The email address to store. Always sent; see the type doc for why it is not optional.
    pub email: String,
    /// The first name to store (`firstName`). Left out of the request when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// The last name to store (`lastName`). Left out of the request when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

/// One physical/browser device with at least one active session, as
/// returned by `GET /realms/{realm}/account/sessions/devices`. Mirrors
/// Keycloak's `DeviceRepresentation` (verified against
/// `services/.../account/SessionResource.java` in `keycloak/keycloak`, at
/// the pinned `26.0.0` tag).
///
/// **`id` is essentially never populated.** The server groups sessions by
/// OS + OS version to build this list and never calls `setId` on the
/// result — confirmed by reading `SessionResource::devices()` directly, not
/// assumed from the field's mere presence on the Java class. The real,
/// revocable identifier lives one level down, on each entry in
/// [`Self::sessions`] — that per-session id is what
/// [`AccountClient::revoke_session`] actually takes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDevice {
    /// The device id (`id`). Essentially never populated; see the type doc.
    #[serde(default)]
    pub id: Option<String>,
    /// The IP address (`ipAddress`), as a string, if Keycloak sends it.
    #[serde(default)]
    pub ip_address: Option<String>,
    /// The operating system (`os`), if Keycloak sends it.
    #[serde(default)]
    pub os: Option<String>,
    /// The operating system version (`osVersion`), if Keycloak sends it.
    #[serde(default)]
    pub os_version: Option<String>,
    /// The browser (`browser`), if Keycloak sends it.
    #[serde(default)]
    pub browser: Option<String>,
    /// The `device` field of Keycloak's `DeviceRepresentation`, if Keycloak sends it.
    #[serde(default)]
    pub device: Option<String>,
    /// The `lastAccess` value as Keycloak sends it, passed through unconverted; `0` if absent. This crate does not state
    /// its unit.
    #[serde(default)]
    pub last_access: i64,
    /// The `current` flag as Keycloak sends it; `None` if absent.
    #[serde(default)]
    pub current: Option<bool>,
    /// The `mobile` flag as Keycloak sends it; `false` if absent.
    #[serde(default)]
    pub mobile: bool,
    /// The device's active sessions; empty if absent. Their ids are what [`AccountClient::revoke_session`] takes.
    #[serde(default)]
    pub sessions: Vec<AccountSession>,
}

/// One active session nested under an [`AccountDevice`].
///
/// `id` here — not `AccountDevice::id` — is the real, revocable session
/// identifier `DELETE /realms/{realm}/account/sessions/{id}` expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSession {
    /// The session id. This is what [`AccountClient::revoke_session`] takes.
    pub id: String,
    /// The IP address (`ipAddress`), as a string, if Keycloak sends it.
    #[serde(default)]
    pub ip_address: Option<String>,
    /// The `started` value as Keycloak sends it, passed through unconverted; `0` if absent. This crate does not
    /// state its unit.
    #[serde(default)]
    pub started: i64,
    /// The `lastAccess` value as Keycloak sends it, passed through unconverted; `0` if absent. This crate does not state
    /// its unit.
    #[serde(default)]
    pub last_access: i64,
    /// The `expires` value as Keycloak sends it, passed through unconverted; `0` if absent. This crate does not
    /// state its unit.
    #[serde(default)]
    pub expires: i64,
    /// The browser (`browser`), if Keycloak sends it.
    #[serde(default)]
    pub browser: Option<String>,
    /// The `current` flag as Keycloak sends it; `None` if absent.
    #[serde(default)]
    pub current: Option<bool>,
    /// The "linked services" data — no separate endpoint is needed for it;
    /// this is where it already lives.
    #[serde(default)]
    pub clients: Vec<AccountSessionClient>,
}

/// A client authorized against one session, nested under
/// [`AccountSession::clients`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSessionClient {
    /// The client's id (`clientId`).
    pub client_id: String,
    /// The client's display name (`clientName`), if Keycloak sends it.
    #[serde(default)]
    pub client_name: Option<String>,
}

/// A stateless, token-scoped client against one realm's Keycloak Account
/// REST API.
///
/// Construct once (e.g. behind a web framework's shared application state) and
/// reuse across every request — nothing here is per-caller except the
/// bearer token each method takes as a parameter. See this module's header
/// comment for why that shape, not `AuthN`, is the right fit.
#[derive(Debug)]
pub struct AccountClient {
    http: reqwest::Client,
    account_url: Url,
}

impl AccountClient {
    /// Build a client for one realm's Account REST API.
    ///
    /// `base_url` is the shared Keycloak instance root (e.g.
    /// `https://id.example.com`); `realm` is the per-tenant knob
    /// (`household`, `staff`, or any future realm on that instance) — never
    /// hardcode it, same rule as `KeycloakConfig`.
    pub fn new(base_url: impl AsRef<str>, realm: impl AsRef<str>) -> Result<Self, IdentityError> {
        let base_url = base_url.as_ref();
        let realm = realm.as_ref();
        if base_url.trim().is_empty() {
            return Err(IdentityError::Auth(
                "AccountClient base_url is empty".to_string(),
            ));
        }
        if realm.trim().is_empty() {
            return Err(IdentityError::Auth(
                "AccountClient realm is empty".to_string(),
            ));
        }
        let account_url = account_base_url(base_url, realm)?;
        crate::transport::ensure_secure_url(&account_url, "AccountClient base_url")?;
        let http = crate::transport::http_client_builder()
            .build()
            .map_err(|e| IdentityError::Transport(format!("building HTTP client: {e}")))?;
        Ok(Self { http, account_url })
    }

    fn endpoint(&self, suffix: &str) -> Result<Url, IdentityError> {
        let raw = format!("{}{}", self.account_url, suffix);
        Url::parse(&raw).map_err(|e| {
            IdentityError::Transport(format!("invalid Account REST API URL ({raw}): {e}"))
        })
    }

    /// `GET /realms/{realm}/account` — the caller's own profile.
    pub async fn get_profile(&self, access_token: &str) -> Result<AccountProfile, IdentityError> {
        let response = self
            .http
            .get(self.account_url.clone())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("GET {} failed: {e}", self.account_url)))?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!(
                    "GET {} returned an error status: {e}",
                    self.account_url
                ))
            })?;
        response.json().await.map_err(|e| {
            IdentityError::Transport(format!("account profile response was not valid JSON: {e}"))
        })
    }

    /// `POST /realms/{realm}/account` — update the caller's own profile.
    ///
    /// See [`AccountProfileUpdate`]'s doc comment before calling this —
    /// the request body is the whole editable profile, not a sparse patch.
    pub async fn update_profile(
        &self,
        access_token: &str,
        update: &AccountProfileUpdate,
    ) -> Result<(), IdentityError> {
        self.http
            .post(self.account_url.clone())
            .bearer_auth(access_token)
            .json(update)
            .send()
            .await
            .map_err(|e| {
                IdentityError::Transport(format!("POST {} failed: {e}", self.account_url))
            })?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!(
                    "POST {} returned an error status: {e}",
                    self.account_url
                ))
            })?;
        Ok(())
    }

    /// Change the caller's own password.
    ///
    /// **Not implemented — deliberately, not for lack of time.** Keycloak's
    /// Account REST API has no `POST /account/credentials/password`
    /// endpoint on any version through the pinned `26.0.0` (verified from
    /// `AccountCredentialResource.java` source, every tagged release
    /// `15.0.0`–`26.0.0`). Calling that URL would 404 in production, so
    /// this method returns `IdentityError::NotImplemented` immediately and
    /// makes no network call. Real self-service password change on this
    /// Keycloak version is the `kc_action=UPDATE_PASSWORD`
    /// application-initiated-action browser redirect — a full redirect
    /// cycle through the login theme, not a fetch a stateless bearer-token
    /// client can perform. See this module's header comment.
    /// `current_password`/`new_password` are accepted
    /// here so the method signature is ready the moment a real mechanism
    /// exists — nothing here reads them yet.
    pub async fn change_password(
        &self,
        _access_token: &str,
        _current_password: &str,
        _new_password: &str,
    ) -> Result<(), IdentityError> {
        Err(IdentityError::NotImplemented(
            "Keycloak's Account REST API has no POST /account/credentials/password endpoint \
             (verified against every tagged release 15.0.0-26.0.0, including the pinned 26.0.0) \
             -- self-service password change on this Keycloak version is the \
             kc_action=UPDATE_PASSWORD browser redirect, not a bearer-token REST call. See \
             src/account/keycloak.rs's header comment.",
        ))
    }

    /// `GET /realms/{realm}/account/sessions/devices` — every device with
    /// an active session, each carrying its nested sessions and (per
    /// session) the authorized clients — the "linked services" data,
    /// already present here.
    pub async fn list_sessions(
        &self,
        access_token: &str,
    ) -> Result<Vec<AccountDevice>, IdentityError> {
        let url = self.endpoint("/sessions/devices")?;
        let response = self
            .http
            .get(url.clone())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("GET {url} failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!("GET {url} returned an error status: {e}"))
            })?;
        response.json().await.map_err(|e| {
            IdentityError::Transport(format!("account sessions response was not valid JSON: {e}"))
        })
    }

    /// `DELETE /realms/{realm}/account/sessions/{id}` — revoke one session.
    ///
    /// `session_id` is an [`AccountSession::id`] (from a device's nested
    /// `sessions` list) — not an [`AccountDevice::id`], which Keycloak's
    /// own `/sessions/devices` response essentially never populates. See
    /// [`AccountDevice`]'s doc comment.
    pub async fn revoke_session(
        &self,
        access_token: &str,
        session_id: &str,
    ) -> Result<(), IdentityError> {
        if session_id.trim().is_empty() {
            return Err(IdentityError::Auth(
                "revoke_session: session_id is empty".to_string(),
            ));
        }
        let url = self.endpoint(&format!("/sessions/{session_id}"))?;
        self.http
            .delete(url.clone())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("DELETE {url} failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!("DELETE {url} returned an error status: {e}"))
            })?;
        Ok(())
    }

    /// `DELETE /realms/{realm}/account/sessions` — revoke every session
    /// *except* the one the presented bearer token belongs to.
    ///
    /// This bulk endpoint is real, not a guess — confirmed from
    /// `SessionResource.logout(boolean removeCurrent)` in `keycloak/
    /// keycloak` source (pinned `26.0.0` tag): a bare `DELETE` on this
    /// resource's root path, filtering out the current session unless
    /// `?current=true` is passed. This method always sends
    /// `?current=false` explicitly rather than relying on that default, so
    /// behavior can't silently change out from under callers if a future
    /// Keycloak version flips it. No `revoke_session`-over-`list_sessions`
    /// fallback loop was needed.
    pub async fn revoke_other_sessions(&self, access_token: &str) -> Result<(), IdentityError> {
        let url = self.endpoint("/sessions?current=false")?;
        self.http
            .delete(url.clone())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("DELETE {url} failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!("DELETE {url} returned an error status: {e}"))
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ---- account_base_url construction -----------------------------------

    #[test]
    fn account_base_url_joins_base_url_and_realm() {
        let url = account_base_url("https://id.example.com", "household").unwrap();
        assert_eq!(
            url.as_str(),
            "https://id.example.com/realms/household/account"
        );
    }

    #[test]
    fn account_base_url_strips_a_trailing_slash_on_base_url() {
        let url = account_base_url("https://id.example.com/", "household").unwrap();
        assert_eq!(
            url.as_str(),
            "https://id.example.com/realms/household/account"
        );
    }

    #[test]
    fn account_base_url_is_realm_parameterized_not_hardcoded() {
        let household = account_base_url("https://id.example.com", "household").unwrap();
        let staff = account_base_url("https://id.example.com", "staff").unwrap();
        assert_ne!(household, staff);
        assert!(household.as_str().ends_with("/realms/household/account"));
        assert!(staff.as_str().ends_with("/realms/staff/account"));
    }

    // ---- AccountClient::new validation ------------------------------------

    #[test]
    fn new_rejects_empty_base_url() {
        let err = AccountClient::new("", "household").unwrap_err();
        assert!(matches!(err, IdentityError::Auth(_)));
    }

    #[test]
    fn new_rejects_empty_realm() {
        let err = AccountClient::new("https://id.example.com", "").unwrap_err();
        assert!(matches!(err, IdentityError::Auth(_)));
    }

    #[test]
    fn new_accepts_a_well_formed_config() {
        assert!(AccountClient::new("https://id.example.com", "household").is_ok());
    }

    // ---- get_profile --------------------------------------------------

    #[tokio::test]
    async fn get_profile_sends_bearer_token_and_parses_the_response() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        Mock::given(method("GET"))
            .and(path("/realms/household/account"))
            .and(header("authorization", "Bearer test-access-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "username": "alice",
                "firstName": "Alice",
                "lastName": "Example",
                "email": "alice@example.com",
                "emailVerified": true,
                "userProfileMetadata": {"attributes": []},
            })))
            .mount(&server)
            .await;

        let profile = client.get_profile("test-access-token").await.unwrap();

        assert_eq!(profile.username, "alice");
        assert_eq!(profile.first_name.as_deref(), Some("Alice"));
        assert_eq!(profile.email.as_deref(), Some("alice@example.com"));
        assert_eq!(profile.email_verified, Some(true));
    }

    #[tokio::test]
    async fn get_profile_surfaces_an_unauthorized_response_as_an_error() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        Mock::given(method("GET"))
            .and(path("/realms/household/account"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let result = client.get_profile("stale-token").await;
        assert!(matches!(result, Err(IdentityError::Transport(_))));
    }

    // ---- update_profile -------------------------------------------------

    #[tokio::test]
    async fn update_profile_posts_the_full_representation_with_bearer_auth() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        Mock::given(method("POST"))
            .and(path("/realms/household/account"))
            .and(header("authorization", "Bearer test-access-token"))
            .and(body_json(serde_json::json!({
                "username": "alice",
                "email": "alice@example.com",
                "firstName": "Alice",
            })))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let update = AccountProfileUpdate {
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            first_name: Some("Alice".to_string()),
            last_name: None,
        };

        client
            .update_profile("test-access-token", &update)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_profile_surfaces_a_validation_error_status() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        Mock::given(method("POST"))
            .and(path("/realms/household/account"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let update = AccountProfileUpdate {
            username: "alice".to_string(),
            email: "not-an-email".to_string(),
            first_name: None,
            last_name: None,
        };

        let result = client.update_profile("test-access-token", &update).await;
        assert!(matches!(result, Err(IdentityError::Transport(_))));
    }

    // ---- change_password: verified not implemented on this Keycloak version

    #[tokio::test]
    async fn change_password_returns_not_implemented_without_any_network_call() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();
        // Deliberately no mock registered for any /credentials/password
        // path: if the implementation ever starts making this call, the
        // request would 404 against wiremock's unmocked-request behavior
        // rather than this test's own assertion catching it, but the
        // `received_requests` check below is the real guard.

        let result = client
            .change_password("test-access-token", "old-pw", "new-pw")
            .await;

        assert!(matches!(result, Err(IdentityError::NotImplemented(_))));
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests.is_empty(),
            "change_password must not make any network call on this Keycloak version"
        );
    }

    // ---- list_sessions ----------------------------------------------------

    #[tokio::test]
    async fn list_sessions_parses_device_and_nested_session_client_shape() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        Mock::given(method("GET"))
            .and(path("/realms/household/account/sessions/devices"))
            .and(header("authorization", "Bearer test-access-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "os": "Mac OS X",
                    "osVersion": "10.15",
                    "device": "Other",
                    "lastAccess": 1_758_000_000i64,
                    "current": true,
                    "mobile": false,
                    "sessions": [
                        {
                            "id": "session-abc",
                            "ipAddress": "203.0.113.5",
                            "started": 1_757_990_000i64,
                            "lastAccess": 1_758_000_000i64,
                            "expires": 1_758_600_000i64,
                            "browser": "Chrome/128.0",
                            "current": true,
                            "clients": [
                                {"clientId": "example-app", "clientName": "Example App"}
                            ]
                        }
                    ]
                }
            ])))
            .mount(&server)
            .await;

        let devices = client.list_sessions("test-access-token").await.unwrap();

        assert_eq!(devices.len(), 1);
        let device = &devices[0];
        assert_eq!(device.id, None, "devices() never sets an id server-side");
        assert_eq!(device.os.as_deref(), Some("Mac OS X"));
        assert_eq!(device.sessions.len(), 1);

        let session = &device.sessions[0];
        assert_eq!(session.id, "session-abc");
        assert_eq!(session.current, Some(true));
        assert_eq!(session.clients.len(), 1);
        assert_eq!(session.clients[0].client_id, "example-app");
        assert_eq!(
            session.clients[0].client_name.as_deref(),
            Some("Example App")
        );
    }

    // ---- revoke_session -----------------------------------------------

    #[tokio::test]
    async fn revoke_session_sends_delete_to_sessions_slash_id() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        Mock::given(method("DELETE"))
            .and(path("/realms/household/account/sessions/session-abc"))
            .and(header("authorization", "Bearer test-access-token"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        client
            .revoke_session("test-access-token", "session-abc")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoke_session_rejects_an_empty_session_id_without_a_network_call() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        let result = client.revoke_session("test-access-token", "").await;
        assert!(matches!(result, Err(IdentityError::Auth(_))));

        let requests = server.received_requests().await.unwrap();
        assert!(requests.is_empty());
    }

    // ---- revoke_other_sessions --------------------------------------------

    #[tokio::test]
    async fn revoke_other_sessions_sends_delete_with_current_false_query_param() {
        let server = MockServer::start().await;
        let client = AccountClient::new(server.uri(), "household").unwrap();

        Mock::given(method("DELETE"))
            .and(path("/realms/household/account/sessions"))
            .and(query_param("current", "false"))
            .and(header("authorization", "Bearer test-access-token"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        client
            .revoke_other_sessions("test-access-token")
            .await
            .unwrap();
    }
}
