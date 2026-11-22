//! Keycloak AuthN.
//!
//! Real OIDC discovery + Authorization Code + PKCE against a Keycloak
//! realm, using `oauth2` v4 for the token-endpoint mechanics and `reqwest`
//! for discovery/userinfo. Deliberately provider-shaped so the same client
//! works unmodified against every realm of a Keycloak instance —
//! `base_url` and `realm` are the only per-tenant inputs, and every endpoint is resolved from the realm's own
//! `.well-known/openid-configuration` document rather than assumed.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{DecodingKey, Validation};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, Scope as OauthScope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::account::{Account, AccountOrigin};
use crate::authz::{Capabilities, Scope as CapabilityScope, ServicePrincipal};
use crate::token::TokenCache;
use crate::transport::{ensure_secure_url, http_client_builder};
use crate::IdentityError;

/// HTTP error for the OAuth2 token-endpoint adapter below.
#[derive(Debug, thiserror::Error)]
enum OauthHttpError {
    #[error("token endpoint request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid HTTP value in token endpoint exchange: {0}")]
    Invalid(String),
}

/// Runs an `oauth2` token-endpoint request over this crate's own `reqwest` client, so the older `reqwest` (and its old
/// TLS stack) that `oauth2` 4 would otherwise bundle is not pulled in. Certificate verification stays on, timeouts apply,
/// and redirects are refused, as the OAuth2 specification requires for token requests.
async fn oauth2_http_client(
    req: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, OauthHttpError> {
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes())
        .map_err(|e| OauthHttpError::Invalid(e.to_string()))?;
    let mut builder = client.request(method, req.url.as_str());
    for (name, value) in req.headers.iter() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    let resp = builder.body(req.body).send().await?;
    let status_code = oauth2::http::StatusCode::from_u16(resp.status().as_u16())
        .map_err(|e| OauthHttpError::Invalid(e.to_string()))?;
    let mut headers = oauth2::http::HeaderMap::new();
    for (name, value) in resp.headers().iter() {
        let n = oauth2::http::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| OauthHttpError::Invalid(e.to_string()))?;
        let v = oauth2::http::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| OauthHttpError::Invalid(e.to_string()))?;
        headers.append(n, v);
    }
    let body = resp.bytes().await?.to_vec();
    Ok(oauth2::HttpResponse {
        status_code,
        headers,
        body,
    })
}

/// Configuration for the Keycloak provider.
///
/// `base_url` + `realm` are resolved dynamically via OIDC discovery
/// (`{base_url}/realms/{realm}/.well-known/openid-configuration`) rather
/// than a hardcoded endpoint shape, so the same config type works against
/// every realm on the shared Keycloak instance — `staff`, `household`, or any
/// future tenant. Never assume a single-realm shape when constructing one
/// of these.
#[derive(Clone)]
pub struct KeycloakConfig {
    /// e.g. `https://id.example.com`. Trailing slash optional.
    pub base_url: String,
    /// e.g. `staff`, `household`. This is the per-product knob — never
    /// hardcode it.
    pub realm: String,
    pub client_id: String,
    /// Confidential clients only. Native/mobile/SPA clients doing
    /// Authorization Code + PKCE should leave this `None`.
    pub client_secret: Option<String>,
    /// Must match a redirect URI registered on the Keycloak client.
    pub redirect_url: String,
    /// OIDC scopes to request. `"openid"` is always included even if
    /// omitted here — it's required for the claims this Kit relies on to
    /// build an [`Account`].
    pub scopes: Vec<String>,
}

/// Manual, redacting `Debug` impl — `client_secret` (a confidential
/// client's real secret, when set) must never appear in a log line or
/// panic message via an incidental `{:?}`. See
/// `KeycloakServicePrincipalConfig`'s identical discipline below, which
/// this mirrors.
impl fmt::Debug for KeycloakConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeycloakConfig")
            .field("base_url", &self.base_url)
            .field("realm", &self.realm)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl KeycloakConfig {
    /// Build a config with the default scopes (`openid profile
    /// email`) and no client secret — the PKCE-public-client shape almost
    /// every consumer surface here needs. Override `client_secret` or
    /// `scopes` directly afterwards if a given deployment needs to.
    pub fn new(
        base_url: impl Into<String>,
        realm: impl Into<String>,
        client_id: impl Into<String>,
        redirect_url: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            realm: realm.into(),
            client_id: client_id.into(),
            client_secret: None,
            redirect_url: redirect_url.into(),
            scopes: default_scopes(),
        }
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.base_url.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakConfig.base_url is empty".to_string(),
            ));
        }
        if self.realm.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakConfig.realm is empty".to_string(),
            ));
        }
        if self.client_id.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakConfig.client_id is empty".to_string(),
            ));
        }
        if self.redirect_url.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakConfig.redirect_url is empty".to_string(),
            ));
        }
        let base = Url::parse(&self.base_url).map_err(|e| {
            IdentityError::Auth(format!("KeycloakConfig.base_url is not a valid URL: {e}"))
        })?;
        ensure_secure_url(&base, "KeycloakConfig.base_url")?;
        Url::parse(&self.redirect_url).map_err(|e| {
            IdentityError::Auth(format!(
                "KeycloakConfig.redirect_url is not a valid URL: {e}"
            ))
        })?;
        Ok(())
    }

    /// Scopes to actually request: always includes `"openid"`, deduped.
    fn effective_scopes(&self) -> Vec<String> {
        let mut scopes = self.scopes.clone();
        if !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".to_string());
        }
        scopes.dedup();
        scopes
    }
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

/// Configuration for a non-interactive `ServicePrincipal` authenticating
/// via the OAuth2 **Client Credentials** grant (`grant_type=
/// client_credentials`, RFC 6749 §4.4) — see
/// `KeycloakAuthN::service_principal`'s doc comment for why this is not
/// the ROPC flow this module's own doc comment refuses.
///
/// **What this type does not cover, on purpose:**
/// - Provisioning the underlying confidential Keycloak client (a
///   `division-ci-*`-style client with `full_scope_allowed = false`) is
///   the deployer's infrastructure-as-code, and the naming/scope
///   convention is the deployer's call. This type only describes what an
///   already-provisioned client's config looks like from the caller's
///   side.
/// - The capability-scope taxonomy — which client roles should exist and
///   what they mean — is the deployer's call. This Kit only
///   provides the mapping mechanism (see `client_role_capabilities`),
///   generically.
/// - Secret custody/rotation: treat the secret as a crown jewel — a
///   secrets manager only, never in code, logs or argv. This crate never persists
///   `client_secret` anywhere.
#[derive(Clone)]
pub struct KeycloakServicePrincipalConfig {
    /// e.g. `https://id.example.com`. Trailing slash optional.
    pub base_url: String,
    /// e.g. `staff`, `household`. Never hardcode — same discipline as
    /// [`KeycloakConfig::realm`].
    pub realm: String,
    pub client_id: String,
    /// The confidential client's secret. Never logged, never
    /// `Debug`/`Display`-printed (see the manual [`fmt::Debug`] impl just
    /// below), and never persisted by this crate.
    pub client_secret: String,
    /// Which client's `resource_access.{roles_client_id}.roles` claim on
    /// the issued access token becomes this principal's [`Capabilities`].
    /// Defaults to the authenticating client itself
    /// ([`KeycloakServicePrincipalConfig::new`]) — override only if the
    /// realm's role-mapping convention grants roles on a different
    /// resource-server client.
    pub roles_client_id: String,
    /// OAuth2 scopes to request alongside the grant. Empty by default —
    /// unlike [`KeycloakConfig`]'s interactive flow, `"openid"` is not
    /// implied here: a Client Credentials token is not an ID token, and
    /// this path never calls the userinfo endpoint.
    pub scopes: Vec<String>,
}

/// Manual, redacting `Debug` impl — `client_secret` must never appear in
/// a log line or panic message via an incidental `{:?}`.
impl fmt::Debug for KeycloakServicePrincipalConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeycloakServicePrincipalConfig")
            .field("base_url", &self.base_url)
            .field("realm", &self.realm)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("roles_client_id", &self.roles_client_id)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl KeycloakServicePrincipalConfig {
    /// `roles_client_id` defaults to `client_id` — override the field
    /// directly afterwards if a given deployment's role-mapping
    /// convention needs a different resource-server client.
    pub fn new(
        base_url: impl Into<String>,
        realm: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        let client_id = client_id.into();
        Self {
            base_url: base_url.into(),
            realm: realm.into(),
            roles_client_id: client_id.clone(),
            client_id,
            client_secret: client_secret.into(),
            scopes: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.base_url.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakServicePrincipalConfig.base_url is empty".to_string(),
            ));
        }
        if self.realm.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakServicePrincipalConfig.realm is empty".to_string(),
            ));
        }
        if self.client_id.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakServicePrincipalConfig.client_id is empty".to_string(),
            ));
        }
        if self.client_secret.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakServicePrincipalConfig.client_secret is empty".to_string(),
            ));
        }
        if self.roles_client_id.trim().is_empty() {
            return Err(IdentityError::Auth(
                "KeycloakServicePrincipalConfig.roles_client_id is empty".to_string(),
            ));
        }
        let base = Url::parse(&self.base_url).map_err(|e| {
            IdentityError::Auth(format!(
                "KeycloakServicePrincipalConfig.base_url is not a valid URL: {e}"
            ))
        })?;
        ensure_secure_url(&base, "KeycloakServicePrincipalConfig.base_url")?;
        Ok(())
    }
}

/// The claims subset needed to build a [`ServicePrincipal`]'s
/// [`Capabilities`] from a Client Credentials access token.
///
/// Deliberately reads only `resource_access` — never `groups` or any
/// household-group claim. Per `account.rs`'s `FamilyRole` doc comment
/// ("must never be fed into `ServicePrincipal`'s capabilities"), a
/// service principal's capabilities come only from its own client's
/// roles; there is no field here for `groups` to land in even by
/// accident.
#[derive(Debug, Default, Deserialize)]
struct ServicePrincipalClaims {
    #[serde(default)]
    resource_access: HashMap<String, ResourceAccessEntry>,
}

#[derive(Debug, Default, Deserialize)]
struct ResourceAccessEntry {
    #[serde(default)]
    roles: Vec<String>,
}

/// Maps a Client Credentials access token's `resource_access.
/// {roles_client_id}.roles` claim into a [`Capabilities`] bundle — one
/// [`CapabilityScope`] per role, in claim order — for **client
/// roles** rather than household groups (operator access is expressed as
/// client roles, never groups).
///
/// This is local, unverified claim extraction — it does not check the
/// token's signature (no JWKS fetch happens in this Kit) or its
/// audience. That mirrors this crate's existing posture toward tokens it
/// handles (the interactive flow never independently verifies the ID
/// token either; it trusts whatever the discovered token endpoint
/// returns over TLS): a `ServicePrincipal`'s capabilities are a *data
/// model*, not an enforcement decision (see `src/authz.rs`'s module doc
/// comment) — the enforcement point is responsible for
/// independently verifying any token it's handed before acting on it.
///
/// Errors only if `access_token` isn't a well-formed JWT at all (three
/// dot-separated, base64url-decodable, JSON segments) — a genuine
/// transport-level surprise. A well-formed token with no
/// `resource_access` entry for `roles_client_id`, or an empty `roles`
/// list, is not an error: it's a principal that authenticated
/// successfully but holds no capabilities yet, same as
/// `parse_memberships`'s "ignore what doesn't match, never error on it"
/// discipline for the interactive path's `groups` claim.
pub(crate) fn client_role_capabilities(
    access_token: &str,
    roles_client_id: &str,
) -> Result<Capabilities, IdentityError> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;

    let token_data = jsonwebtoken::decode::<ServicePrincipalClaims>(
        access_token,
        &DecodingKey::from_secret(&[]),
        &validation,
    )
    .map_err(|e| {
        IdentityError::Auth(format!(
            "client-credentials access token was not a well-formed JWT: {e}"
        ))
    })?;

    let scopes = token_data
        .claims
        .resource_access
        .get(roles_client_id)
        .map(|entry| entry.roles.iter().cloned().map(CapabilityScope).collect())
        .unwrap_or_default();

    Ok(Capabilities::new(scopes))
}

/// Assembles a JWT-shaped string from a raw header, a raw payload and a
/// verbatim signature segment: the first two are base64url-encoded (no
/// padding) and joined with the third by dots.
///
/// Test-only. `client_role_capabilities` never reads the signature, so test
/// tokens are not signed; building them by hand also means the tests need no
/// `jsonwebtoken` crypto backend (see the note on that dependency in
/// `Cargo.toml`).
#[cfg(test)]
pub(crate) fn jwt_from_parts(header: &str, payload: &str, signature: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    format!(
        "{}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload),
    )
}

/// The JOSE header of a token Keycloak signs with its default realm key:
/// `RS256`, with the `kid` naming the realm key. Test tokens use it so the
/// tests exercise the shape the Kit really receives (an asymmetric
/// algorithm and a `kid`), not an HMAC token with no `kid`. Test-only.
#[cfg(test)]
pub(crate) const KEYCLOAK_JWT_HEADER: &str =
    r#"{"alg":"RS256","typ":"JWT","kid":"Vt9kYwPqL3mZ1cXn7sUeB0dHfA5oRiTg"}"#;

/// A structurally well-formed JWT with Keycloak's header
/// ([`KEYCLOAK_JWT_HEADER`]) carrying `claims`, with a placeholder
/// signature. Test-only; see [`jwt_from_parts`].
#[cfg(test)]
pub(crate) fn unsigned_test_jwt(claims: &serde_json::Value) -> String {
    jwt_from_parts(
        KEYCLOAK_JWT_HEADER,
        &claims.to_string(),
        "placeholder-signature",
    )
}

/// The subset of a realm's `.well-known/openid-configuration` document this
/// client needs. Keycloak's real response has many more fields; those are
/// silently ignored (no `deny_unknown_fields`) rather than causing a parse
/// failure on IdP-side additions.
#[derive(Debug, Clone, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    #[serde(default)]
    end_session_endpoint: Option<String>,
}

/// Build the discovery-document URL for a given base URL + realm.
///
/// A free function rather than a method so it's directly unit-testable
/// without a live network call or a constructed client — this is exactly
/// the seam that has to keep working identically for the `staff` and
/// `household` realms on the same Keycloak instance.
fn discovery_url(base_url: &str, realm: &str) -> Result<Url, IdentityError> {
    let trimmed = base_url.trim_end_matches('/');
    let raw = format!("{trimmed}/realms/{realm}/.well-known/openid-configuration");
    Url::parse(&raw).map_err(|e| IdentityError::Auth(format!("invalid discovery URL: {e}")))
}

fn cache_key(realm: &str, client_id: &str) -> String {
    format!("identity-kit:keycloak:{realm}:{client_id}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A pending interactive sign-in.
///
/// The caller must open [`Self::authorize_url`] in a real browser/webview,
/// then hand this struct back — together with the `code` and `state` the
/// IdP's redirect delivers — to
/// [`crate::authn::AuthN::complete_sign_in`].
///
/// Holds the PKCE verifier. Never serialize this or hand it to anything
/// except the completing call; it's the secret half of the PKCE pair the
/// authorize URL's `code_challenge` commits to.
#[derive(Debug)]
pub struct PendingAuthorization {
    pub authorize_url: Url,
    pub csrf_state: String,
    pkce_verifier: PkceCodeVerifier,
}

/// An authenticated session: the [`Account`] resolved from the IdP's
/// userinfo claims, plus the tokens backing it.
///
/// Serializable so it round-trips through [`TokenCache`] as-is — this is
/// the only token-storage format this flow uses; there's no parallel seam.
/// `Debug` is **not** derived — see the manual impl below.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    account: Account,
    access_token: String,
    refresh_token: Option<String>,
    expires_at_unix: Option<u64>,
}

/// Manual, redacting `Debug` impl — `access_token` is a live bearer token
/// and `refresh_token`, when present, is long-lived; either must never
/// appear in a log line or panic message via an incidental `{:?}`. Same
/// discipline as `KeycloakConfig`/`KeycloakServicePrincipalConfig` above,
/// mirrored here — the credential this protects is a person's live
/// session, not a client secret, so getting it wrong is worse, not just
/// the same class of bug. `refresh_token` is `Option<String>`, so it gets
/// the same both-arms treatment as `KeycloakConfig::client_secret`: a
/// `None` must render as `None`, never as `"<redacted>"`, or the log line
/// falsely implies a refresh token exists.
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("account", &self.account)
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl Session {
    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Best-effort: `false` if the token response didn't report an expiry
    /// (rather than assuming it's already expired).
    pub fn is_expired(&self) -> bool {
        match self.expires_at_unix {
            Some(exp) => now_unix() >= exp,
            None => false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct UserInfoClaims {
    sub: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

/// The real Keycloak AuthN implementation. Not exposed directly — reached
/// only through [`crate::authn::AuthN`].
pub(crate) struct KeycloakAuthN {
    oauth_client: BasicClient,
    http: reqwest::Client,
    userinfo_endpoint: Url,
    end_session_endpoint: Option<Url>,
    scopes: Vec<String>,
    client_id: String,
    cache_key: String,
    token_cache: Arc<dyn TokenCache>,
}

impl KeycloakAuthN {
    pub(crate) async fn connect(
        config: KeycloakConfig,
        token_cache: Arc<dyn TokenCache>,
    ) -> Result<Self, IdentityError> {
        config.validate()?;

        let http = http_client_builder()
            .build()
            .map_err(|e| IdentityError::Transport(format!("building HTTP client: {e}")))?;

        let discovery_url = discovery_url(&config.base_url, &config.realm)?;
        let response = http
            .get(discovery_url.clone())
            .send()
            .await
            .map_err(|e| {
                IdentityError::Transport(format!(
                    "OIDC discovery request to {discovery_url} failed: {e}"
                ))
            })?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!("OIDC discovery returned an error status: {e}"))
            })?;
        let discovery: OidcDiscoveryDocument = response.json().await.map_err(|e| {
            IdentityError::Transport(format!("OIDC discovery response was not valid JSON: {e}"))
        })?;

        let auth_url = AuthUrl::new(discovery.authorization_endpoint.clone())
            .map_err(|e| IdentityError::Auth(format!("invalid authorization_endpoint: {e}")))?;
        let token_url = TokenUrl::new(discovery.token_endpoint.clone())
            .map_err(|e| IdentityError::Auth(format!("invalid token_endpoint: {e}")))?;
        let userinfo_endpoint = Url::parse(&discovery.userinfo_endpoint)
            .map_err(|e| IdentityError::Auth(format!("invalid userinfo_endpoint: {e}")))?;
        let end_session_endpoint = discovery
            .end_session_endpoint
            .as_deref()
            .map(Url::parse)
            .transpose()
            .map_err(|e| IdentityError::Auth(format!("invalid end_session_endpoint: {e}")))?;
        // The IdP's own document must not be able to move a credential-carrying call to plain http.
        ensure_secure_url(auth_url.url(), "authorization_endpoint")?;
        ensure_secure_url(token_url.url(), "token_endpoint")?;
        ensure_secure_url(&userinfo_endpoint, "userinfo_endpoint")?;
        if let Some(end_session) = &end_session_endpoint {
            ensure_secure_url(end_session, "end_session_endpoint")?;
        }
        let redirect_url = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|e| IdentityError::Auth(format!("invalid redirect_url: {e}")))?;

        let oauth_client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            config.client_secret.clone().map(ClientSecret::new),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(redirect_url);

        Ok(Self {
            oauth_client,
            http,
            userinfo_endpoint,
            end_session_endpoint,
            scopes: config.effective_scopes(),
            cache_key: cache_key(&config.realm, &config.client_id),
            client_id: config.client_id.clone(),
            token_cache,
        })
    }

    /// Non-interactive AuthN for a headless `ServicePrincipal` — the
    /// OAuth2 **Client Credentials** grant (`grant_type=
    /// client_credentials`, RFC 6749 §4.4) against the same realm-scoped
    /// token endpoint [`Self::connect`] resolves via OIDC discovery.
    ///
    /// ## Why this is not the ROPC flow this module refuses
    ///
    /// See this module's doc comment ("Security architecture"): ROPC is
    /// refused because it lets *a human's* plaintext password cross this
    /// library on behalf of *a person* — it forecloses WebAuthn/passkeys
    /// and puts a password through a code path it should never touch.
    /// Client Credentials carries no password and authenticates no
    /// person at all: it authenticates *the client application itself* —
    /// a confidential Keycloak client provisioned out-of-band for a
    /// specific non-interactive caller (e.g. a division's CI), using a
    /// secret that never represents a human's own credential and is
    /// never entered by a human at sign-in time. This is a standard
    /// OAuth2 grant for service-to-service calls — not a new security
    /// posture, and not a loosening of the ROPC refusal above.
    ///
    /// Unlike [`Self::connect`]/[`Self::begin_sign_in`]/
    /// [`Self::complete_sign_in`], this is a standalone associated
    /// function: there is no interactive session to hold open
    /// afterwards, no `TokenCache` to persist through (a division-CI
    /// caller re-acquires a fresh grant per run rather than caching a
    /// long-lived session), and the result is a [`ServicePrincipal`]
    /// directly rather than a [`Session`] wrapping an [`Account`] — a
    /// service principal has no human account behind it.
    pub(crate) async fn service_principal(
        config: KeycloakServicePrincipalConfig,
    ) -> Result<ServicePrincipal, IdentityError> {
        config.validate()?;

        let http = http_client_builder()
            .build()
            .map_err(|e| IdentityError::Transport(format!("building HTTP client: {e}")))?;

        let discovery_url = discovery_url(&config.base_url, &config.realm)?;
        let response = http
            .get(discovery_url.clone())
            .send()
            .await
            .map_err(|e| {
                IdentityError::Transport(format!(
                    "OIDC discovery request to {discovery_url} failed: {e}"
                ))
            })?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!("OIDC discovery returned an error status: {e}"))
            })?;
        let discovery: OidcDiscoveryDocument = response.json().await.map_err(|e| {
            IdentityError::Transport(format!("OIDC discovery response was not valid JSON: {e}"))
        })?;

        let auth_url = AuthUrl::new(discovery.authorization_endpoint.clone())
            .map_err(|e| IdentityError::Auth(format!("invalid authorization_endpoint: {e}")))?;
        let token_url = TokenUrl::new(discovery.token_endpoint.clone())
            .map_err(|e| IdentityError::Auth(format!("invalid token_endpoint: {e}")))?;

        ensure_secure_url(auth_url.url(), "authorization_endpoint")?;
        ensure_secure_url(token_url.url(), "token_endpoint")?;

        let oauth_client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            auth_url,
            Some(token_url),
        );

        let mut request = oauth_client.exchange_client_credentials();
        for scope in &config.scopes {
            request = request.add_scope(OauthScope::new(scope.clone()));
        }
        let token_response = request
            .request_async(oauth2_http_client)
            .await
            .map_err(|e| IdentityError::Auth(format!("client-credentials exchange failed: {e}")))?;

        let capabilities = client_role_capabilities(
            token_response.access_token().secret(),
            &config.roles_client_id,
        )?;

        Ok(ServicePrincipal::new(None, capabilities))
    }

    pub(crate) fn begin_sign_in(&self) -> PendingAuthorization {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut request = self
            .oauth_client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);
        for scope in &self.scopes {
            request = request.add_scope(OauthScope::new(scope.clone()));
        }
        let (authorize_url, csrf_token) = request.url();

        PendingAuthorization {
            authorize_url,
            csrf_state: csrf_token.secret().clone(),
            pkce_verifier,
        }
    }

    pub(crate) async fn complete_sign_in(
        &self,
        pending: PendingAuthorization,
        code: String,
        returned_state: String,
    ) -> Result<Session, IdentityError> {
        if returned_state != pending.csrf_state {
            return Err(IdentityError::Auth(
                "OIDC callback state did not match the pending authorization's CSRF state"
                    .to_string(),
            ));
        }

        let token_response = self
            .oauth_client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pending.pkce_verifier)
            .request_async(oauth2_http_client)
            .await
            .map_err(|e| IdentityError::Auth(format!("authorization code exchange failed: {e}")))?;

        let account = self
            .fetch_account(token_response.access_token().secret())
            .await?;
        let session = self.to_session(&token_response, account);
        self.persist(&session)?;
        Ok(session)
    }

    pub(crate) async fn refresh(&self) -> Result<Session, IdentityError> {
        let cached = self
            .load_cached_session()?
            .ok_or_else(|| IdentityError::Auth("no cached Keycloak session to refresh".into()))?;
        let refresh_token = cached.refresh_token.clone().ok_or_else(|| {
            IdentityError::Auth("cached Keycloak session has no refresh token".into())
        })?;

        let token_response = self
            .oauth_client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.clone()))
            .request_async(oauth2_http_client)
            .await
            .map_err(|e| IdentityError::Auth(format!("token refresh failed: {e}")))?;

        // Keycloak doesn't always rotate the refresh token on a refresh
        // grant; keep the previous one if this response omits a new one.
        let mut session = self.to_session(&token_response, cached.account);
        if session.refresh_token.is_none() {
            session.refresh_token = Some(refresh_token);
        }
        self.persist(&session)?;
        Ok(session)
    }

    pub(crate) fn sign_out(
        &self,
        post_logout_redirect_uri: Option<&str>,
    ) -> Result<Option<Url>, IdentityError> {
        self.token_cache.delete(&self.cache_key)?;

        let Some(end_session) = &self.end_session_endpoint else {
            return Ok(None);
        };
        let mut url = end_session.clone();
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("client_id", &self.client_id);
            if let Some(redirect) = post_logout_redirect_uri {
                pairs.append_pair("post_logout_redirect_uri", redirect);
            }
        }
        Ok(Some(url))
    }

    async fn fetch_account(&self, access_token: &str) -> Result<Account, IdentityError> {
        let response = self
            .http
            .get(self.userinfo_endpoint.clone())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| IdentityError::Transport(format!("userinfo request failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                IdentityError::Transport(format!("userinfo returned an error status: {e}"))
            })?;
        let claims: UserInfoClaims = response.json().await.map_err(|e| {
            IdentityError::Transport(format!("userinfo response was not valid JSON: {e}"))
        })?;

        // Keycloak's default user store issues a UUID `sub`; a federated
        // or legacy store might not. `Account::id` requires a `Uuid`, so a
        // non-UUID `sub` surfaces as a clear auth error rather than a
        // silently fabricated id.
        let id = Uuid::parse_str(&claims.sub).map_err(|e| {
            IdentityError::Auth(format!(
                "Keycloak userinfo `sub` claim ({}) is not a UUID, which Account::id requires: {e}",
                claims.sub
            ))
        })?;

        let display_name = claims
            .name
            .or(claims.preferred_username)
            .or_else(|| claims.email.clone())
            .unwrap_or(claims.sub);

        Ok(Account {
            id,
            display_name,
            email: claims.email,
            // Every account resolved through Keycloak sign-in is a
            // standalone adult signing in on their own — a created-child
            // account is provisioned by a guardian via
            // `FamilyClient::create_child`, never by an interactive
            // Keycloak sign-in flow.
            origin: AccountOrigin::Standalone,
        })
    }

    fn to_session(&self, token_response: &BasicTokenResponse, account: Account) -> Session {
        Session {
            account,
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response.refresh_token().map(|t| t.secret().clone()),
            expires_at_unix: token_response
                .expires_in()
                .map(|d| now_unix() + d.as_secs()),
        }
    }

    fn load_cached_session(&self) -> Result<Option<Session>, IdentityError> {
        let Some(raw) = self.token_cache.get(&self.cache_key)? else {
            return Ok(None);
        };
        let session = serde_json::from_str(&raw).map_err(|e| {
            IdentityError::Cache(format!("cached Keycloak session was corrupt: {e}"))
        })?;
        Ok(Some(session))
    }

    fn persist(&self, session: &Session) -> Result<(), IdentityError> {
        let raw = serde_json::to_string(session)
            .map_err(|e| IdentityError::Cache(format!("failed to serialize session: {e}")))?;
        self.token_cache.set(&self.cache_key, &raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A trivial in-process `TokenCache` — exactly the kind of implementer
    /// a CLI or test suite would pass in ahead of the still-open
    /// `keyring`-backed default.
    #[derive(Default)]
    struct InMemoryTokenCache {
        entries: Mutex<HashMap<String, String>>,
    }

    impl TokenCache for InMemoryTokenCache {
        fn get(&self, key: &str) -> Result<Option<String>, IdentityError> {
            Ok(self.entries.lock().unwrap().get(key).cloned())
        }

        fn set(&self, key: &str, value: &str) -> Result<(), IdentityError> {
            self.entries
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<(), IdentityError> {
            self.entries.lock().unwrap().remove(key);
            Ok(())
        }
    }

    // ---- discovery-URL construction -----------------------------------

    #[test]
    fn discovery_url_joins_base_url_and_realm() {
        let url = discovery_url("https://id.example.com", "staff").unwrap();
        assert_eq!(
            url.as_str(),
            "https://id.example.com/realms/staff/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_strips_a_trailing_slash_on_base_url() {
        let url = discovery_url("https://id.example.com/", "staff").unwrap();
        assert_eq!(
            url.as_str(),
            "https://id.example.com/realms/staff/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_is_realm_parameterized_not_hardcoded() {
        // The same base URL, two different realms on the shared instance —
        // this is the "build once, not twice" constraint: nothing here may
        // assume a single-realm shape.
        let staff = discovery_url("https://id.example.com", "staff").unwrap();
        let household = discovery_url("https://id.example.com", "household").unwrap();
        assert_ne!(staff, household);
        assert!(staff
            .as_str()
            .ends_with("/realms/staff/.well-known/openid-configuration"));
        assert!(household
            .as_str()
            .ends_with("/realms/household/.well-known/openid-configuration"));
    }

    #[test]
    fn discovery_url_rejects_an_unparseable_base_url() {
        let err = discovery_url("not a url", "staff").unwrap_err();
        assert!(matches!(err, IdentityError::Auth(_)));
    }

    // ---- config validation ---------------------------------------------

    fn valid_config() -> KeycloakConfig {
        KeycloakConfig::new(
            "https://id.example.com",
            "staff",
            "app-desktop",
            "app://auth/callback",
        )
    }

    #[test]
    fn config_new_always_includes_openid_scope() {
        let config = valid_config();
        assert!(config.scopes.iter().any(|s| s == "openid"));
    }

    #[test]
    fn effective_scopes_adds_openid_even_if_caller_omitted_it() {
        let mut config = valid_config();
        config.scopes = vec!["profile".to_string()];
        let scopes = config.effective_scopes();
        assert!(scopes.iter().any(|s| s == "openid"));
        assert!(scopes.iter().any(|s| s == "profile"));
    }

    #[test]
    fn effective_scopes_does_not_duplicate_openid() {
        let mut config = valid_config();
        config.scopes = vec!["openid".to_string(), "openid".to_string()];
        let scopes = config.effective_scopes();
        assert_eq!(scopes.iter().filter(|s| s.as_str() == "openid").count(), 1);
    }

    #[test]
    fn validate_accepts_a_well_formed_config() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_realm() {
        let mut config = valid_config();
        config.realm = String::new();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, IdentityError::Auth(_)));
    }

    #[test]
    fn validate_rejects_empty_client_id() {
        let mut config = valid_config();
        config.client_id = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_base_url() {
        let mut config = valid_config();
        config.base_url = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_redirect_url() {
        let mut config = valid_config();
        config.redirect_url = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_a_malformed_base_url() {
        let mut config = valid_config();
        config.base_url = "not a url".to_string();
        assert!(config.validate().is_err());
    }

    // ---- PKCE challenge/verifier generation -----------------------------

    #[test]
    fn pkce_challenge_uses_s256() {
        let (challenge, _verifier) = PkceCodeChallenge::new_random_sha256();
        assert_eq!(challenge.method().as_str(), "S256");
    }

    #[test]
    fn pkce_challenge_is_the_sha256_of_the_verifier() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let recomputed = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        assert_eq!(challenge.as_str(), recomputed.as_str());
    }

    #[test]
    fn pkce_verifier_and_challenge_are_not_the_same_string() {
        // Guards against an accidental plain/no-op "challenge".
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        assert_ne!(challenge.as_str(), verifier.secret().as_str());
    }

    // ---- begin_sign_in() authorize-URL shape ----------------------------

    async fn keycloak_authn_against(server: &MockServer) -> KeycloakAuthN {
        Mock::given(method("GET"))
            .and(path("/realms/staff/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": format!("{}/realms/staff", server.uri()),
                "authorization_endpoint": format!("{}/realms/staff/protocol/openid-connect/auth", server.uri()),
                "token_endpoint": format!("{}/realms/staff/protocol/openid-connect/token", server.uri()),
                "userinfo_endpoint": format!("{}/realms/staff/protocol/openid-connect/userinfo", server.uri()),
                "end_session_endpoint": format!("{}/realms/staff/protocol/openid-connect/logout", server.uri()),
            })))
            .mount(server)
            .await;

        let config =
            KeycloakConfig::new(server.uri(), "staff", "app-desktop", "app://auth/callback");
        let cache: Arc<dyn TokenCache> = Arc::new(InMemoryTokenCache::default());
        KeycloakAuthN::connect(config, cache).await.unwrap()
    }

    #[test]
    fn config_refuses_a_plain_http_base_url_on_a_non_loopback_host() {
        let mut config = valid_config();
        config.base_url = "http://id.example.com".to_string();
        assert!(matches!(
            config.validate(),
            Err(IdentityError::InsecureTransport(_))
        ));
    }

    #[test]
    fn service_principal_config_refuses_a_plain_http_base_url_on_a_non_loopback_host() {
        let mut config = valid_service_principal_config();
        config.base_url = "http://id.example.com".to_string();
        assert!(matches!(
            config.validate(),
            Err(IdentityError::InsecureTransport(_))
        ));
    }

    #[tokio::test]
    async fn connect_refuses_a_discovery_document_that_advertises_a_plain_http_token_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realms/staff/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": format!("{}/realms/staff", server.uri()),
                "authorization_endpoint": format!("{}/realms/staff/protocol/openid-connect/auth", server.uri()),
                "token_endpoint": "http://idp.example.com/realms/staff/protocol/openid-connect/token",
                "userinfo_endpoint": format!("{}/realms/staff/protocol/openid-connect/userinfo", server.uri()),
            })))
            .mount(&server)
            .await;

        let config =
            KeycloakConfig::new(server.uri(), "staff", "app-desktop", "app://auth/callback");
        let cache: Arc<dyn TokenCache> = Arc::new(InMemoryTokenCache::default());
        match KeycloakAuthN::connect(config, cache).await {
            Err(IdentityError::InsecureTransport(_)) => {}
            Ok(_) => panic!("a plain-http token endpoint must be refused"),
            Err(other) => panic!("expected InsecureTransport, got {other}"),
        }
    }

    #[tokio::test]
    async fn connect_resolves_endpoints_via_discovery_not_hardcoded_paths() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;

        assert_eq!(
            kc.userinfo_endpoint.as_str(),
            format!(
                "{}/realms/staff/protocol/openid-connect/userinfo",
                server.uri()
            )
        );
        assert_eq!(
            kc.end_session_endpoint.as_ref().unwrap().as_str(),
            format!(
                "{}/realms/staff/protocol/openid-connect/logout",
                server.uri()
            )
        );
    }

    #[tokio::test]
    async fn begin_sign_in_authorize_url_carries_pkce_s256_and_state() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;

        let pending = kc.begin_sign_in();
        let query: HashMap<_, _> = pending.authorize_url.query_pairs().into_owned().collect();

        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("app-desktop")
        );
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(query.contains_key("code_challenge"));
        assert_eq!(
            query.get("state").map(String::as_str),
            Some(pending.csrf_state.as_str())
        );
        assert!(!pending.csrf_state.is_empty());

        // The verifier held on the pending authorization must actually
        // correspond to the challenge sent in the URL.
        let expected_challenge =
            PkceCodeChallenge::from_code_verifier_sha256(&pending.pkce_verifier);
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some(expected_challenge.as_str())
        );
    }

    #[tokio::test]
    async fn begin_sign_in_requests_openid_scope_by_default() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;

        let pending = kc.begin_sign_in();
        let query: HashMap<_, _> = pending.authorize_url.query_pairs().into_owned().collect();
        let scope = query.get("scope").cloned().unwrap_or_default();
        assert!(scope.split(' ').any(|s| s == "openid"));
    }

    // ---- complete_sign_in(): full code-exchange happy path against a
    // local mock server (no live network / no real Keycloak needed) -------

    #[tokio::test]
    async fn complete_sign_in_rejects_a_state_mismatch_without_calling_the_token_endpoint() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;
        // Deliberately no token-endpoint mock registered: if the
        // implementation called it despite the state mismatch, wiremock
        // would 404 rather than silently succeed, but asserting the error
        // variant directly is the real behavioural contract.
        let pending = kc.begin_sign_in();

        let result = kc
            .complete_sign_in(pending, "some-code".to_string(), "wrong-state".to_string())
            .await;

        assert!(matches!(result, Err(IdentityError::Auth(_))));
    }

    #[tokio::test]
    async fn complete_sign_in_exchanges_code_and_builds_account_from_userinfo() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;
        let pending = kc.begin_sign_in();
        let state = pending.csrf_state.clone();

        Mock::given(method("POST"))
            .and(path("/realms/staff/protocol/openid-connect/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=test-auth-code"))
            .and(body_string_contains("code_verifier="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token",
                "token_type": "bearer",
                "expires_in": 300,
            })))
            .mount(&server)
            .await;

        let sub = Uuid::new_v4();
        Mock::given(method("GET"))
            .and(path("/realms/staff/protocol/openid-connect/userinfo"))
            .and(header("authorization", "Bearer test-access-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": sub.to_string(),
                "name": "Ada Lovelace",
                "email": "ada@example.com",
            })))
            .mount(&server)
            .await;

        let session = kc
            .complete_sign_in(pending, "test-auth-code".to_string(), state)
            .await
            .unwrap();

        assert_eq!(session.access_token(), "test-access-token");
        assert_eq!(session.account().id, sub);
        assert_eq!(session.account().display_name, "Ada Lovelace");
        assert_eq!(session.account().email.as_deref(), Some("ada@example.com"));
        assert!(!session.is_expired());

        // And it was persisted through the TokenCache seam, not a parallel
        // store.
        let cached = kc.load_cached_session().unwrap().unwrap();
        assert_eq!(cached.access_token(), "test-access-token");
    }

    // ---- refresh(): request shape + refresh-token retention -------------

    #[tokio::test]
    async fn refresh_sends_the_standard_refresh_token_grant_shape() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;

        let account = Account {
            id: Uuid::new_v4(),
            display_name: "Ada Lovelace".to_string(),
            email: Some("ada@example.com".to_string()),
            origin: AccountOrigin::Standalone,
        };
        let seeded = Session {
            account: account.clone(),
            access_token: "stale-access-token".to_string(),
            refresh_token: Some("known-refresh-token".to_string()),
            expires_at_unix: Some(0),
        };
        kc.persist(&seeded).unwrap();

        Mock::given(method("POST"))
            .and(path("/realms/staff/protocol/openid-connect/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=known-refresh-token"))
            .and(body_string_contains(format!("client_id={}", "app-desktop")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fresh-access-token",
                "token_type": "bearer",
                "expires_in": 300,
            })))
            .mount(&server)
            .await;

        let refreshed = kc.refresh().await.unwrap();

        assert_eq!(refreshed.access_token(), "fresh-access-token");
        assert_eq!(refreshed.account().id, account.id);
        // The refresh response omitted a new refresh_token — Keycloak
        // doesn't always rotate it — so the prior one must be retained.
        assert_eq!(
            refreshed.refresh_token.as_deref(),
            Some("known-refresh-token")
        );
    }

    #[tokio::test]
    async fn refresh_fails_cleanly_with_no_cached_session() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;

        let result = kc.refresh().await;
        assert!(matches!(result, Err(IdentityError::Auth(_))));
    }

    // ---- sign_out() ------------------------------------------------------

    #[tokio::test]
    async fn sign_out_clears_the_cache_and_builds_the_end_session_url() {
        let server = MockServer::start().await;
        let kc = keycloak_authn_against(&server).await;
        let seeded = Session {
            account: Account {
                id: Uuid::new_v4(),
                display_name: "Ada Lovelace".to_string(),
                email: None,
                origin: AccountOrigin::Standalone,
            },
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at_unix: None,
        };
        kc.persist(&seeded).unwrap();

        let url = kc.sign_out(Some("app://auth/logged-out")).unwrap().unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("app-desktop")
        );
        assert_eq!(
            query.get("post_logout_redirect_uri").map(String::as_str),
            Some("app://auth/logged-out")
        );

        assert!(kc.load_cached_session().unwrap().is_none());
    }

    // ---- KeycloakServicePrincipalConfig: validation + secret redaction --

    fn valid_service_principal_config() -> KeycloakServicePrincipalConfig {
        KeycloakServicePrincipalConfig::new(
            "https://id.example.com",
            "household",
            "division-ci-example",
            "super-secret-value",
        )
    }

    #[test]
    fn service_principal_config_new_defaults_roles_client_id_to_client_id() {
        let config = valid_service_principal_config();
        assert_eq!(config.roles_client_id, config.client_id);
    }

    #[test]
    fn service_principal_config_validate_accepts_a_well_formed_config() {
        assert!(valid_service_principal_config().validate().is_ok());
    }

    #[test]
    fn service_principal_config_validate_rejects_empty_client_secret() {
        let mut config = valid_service_principal_config();
        config.client_secret = String::new();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, IdentityError::Auth(_)));
    }

    #[test]
    fn service_principal_config_validate_rejects_empty_realm() {
        let mut config = valid_service_principal_config();
        config.realm = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn service_principal_config_validate_rejects_empty_client_id() {
        let mut config = valid_service_principal_config();
        config.client_id = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn service_principal_config_validate_rejects_a_malformed_base_url() {
        let mut config = valid_service_principal_config();
        config.base_url = "not a url".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn service_principal_config_debug_redacts_the_client_secret() {
        let config = valid_service_principal_config();
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("super-secret-value"));
        assert!(debug_output.contains("<redacted>"));
    }

    #[test]
    fn keycloak_config_debug_redacts_the_client_secret() {
        let mut config = valid_config();
        config.client_secret = Some("super-secret-pkce-value".to_string());
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("super-secret-pkce-value"));
        assert!(debug_output.contains("<redacted>"));
    }

    #[test]
    fn keycloak_config_debug_reports_no_secret_when_none_is_set() {
        // A `None` client secret (the public-client/PKCE-only shape) must
        // not be misreported as "redacted" — that would falsely imply a
        // secret is present.
        let config = valid_config();
        assert!(config.client_secret.is_none());
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("<redacted>"));
        assert!(debug_output.contains("client_secret: None"));
    }

    // ---- Session: access_token / refresh_token redaction -----------------

    fn session_with_refresh_token() -> Session {
        Session {
            account: Account {
                id: Uuid::new_v4(),
                display_name: "Ada Lovelace".to_string(),
                email: Some("ada@example.com".to_string()),
                origin: AccountOrigin::Standalone,
            },
            access_token: "super-secret-access-token".to_string(),
            refresh_token: Some("super-secret-refresh-token".to_string()),
            expires_at_unix: Some(0),
        }
    }

    #[test]
    fn session_debug_redacts_the_access_token_and_refresh_token() {
        let session = session_with_refresh_token();
        let debug_output = format!("{session:?}");
        assert!(!debug_output.contains("super-secret-access-token"));
        assert!(!debug_output.contains("super-secret-refresh-token"));
        // Both fields redact independently — this isn't satisfied by a
        // single "<redacted>" that happens to appear once.
        assert_eq!(debug_output.matches("<redacted>").count(), 2);
    }

    #[test]
    fn session_debug_reports_no_refresh_token_when_none_is_set() {
        // A `None` refresh_token (e.g. a session Keycloak never issued one
        // for) must not be misreported as "redacted" — that would falsely
        // imply a refresh token is present.
        let mut session = session_with_refresh_token();
        session.refresh_token = None;
        let debug_output = format!("{session:?}");
        assert!(!debug_output.contains("super-secret-access-token"));
        assert!(debug_output.contains("access_token: \"<redacted>\""));
        assert!(debug_output.contains("refresh_token: None"));
    }

    // ---- client_role_capabilities(): the resource_access.{client}.roles
    // -> Capabilities mapping --------------------------------------

    /// Builds a structurally well-formed (but unverified-by-design; see
    /// `client_role_capabilities`'s doc comment) test JWT carrying the
    /// given claims, plus a default `exp` a real Keycloak token would
    /// always carry (unless the caller's claims already set one) — an
    /// `exp` claim is the one thing `client_role_capabilities` still
    /// requires present and unexpired, signature checking aside.
    /// The token is not signed — `client_role_capabilities` never
    /// checks the signature.
    fn test_jwt(mut claims: serde_json::Value) -> String {
        if let serde_json::Value::Object(map) = &mut claims {
            map.entry("exp")
                .or_insert_with(|| serde_json::json!(now_unix() + 300));
        }
        unsigned_test_jwt(&claims)
    }

    #[test]
    fn client_role_capabilities_maps_a_well_formed_role() {
        let token = test_jwt(serde_json::json!({
            "resource_access": { "division-ci": { "roles": ["read:builds"] } },
        }));
        let caps = client_role_capabilities(&token, "division-ci").unwrap();
        assert!(caps.includes(&CapabilityScope("read:builds".to_string())));
    }

    #[test]
    fn client_role_capabilities_maps_multiple_roles() {
        let token = test_jwt(serde_json::json!({
            "resource_access": {
                "division-ci": { "roles": ["read:builds", "write:artifacts"] },
            },
        }));
        let caps = client_role_capabilities(&token, "division-ci").unwrap();
        assert!(caps.includes(&CapabilityScope("read:builds".to_string())));
        assert!(caps.includes(&CapabilityScope("write:artifacts".to_string())));
    }

    #[test]
    fn client_role_capabilities_ignores_roles_under_a_different_client() {
        // A role scoped to some other resource-server client in
        // `resource_access` — not the one this principal is
        // authenticating as/reading roles for — is silently skipped,
        // never surfaced, same "ignore what doesn't match" discipline as
        // `parse_household_group`.
        let token = test_jwt(serde_json::json!({
            "resource_access": { "some-other-client": { "roles": ["admin:everything"] } },
        }));
        let caps = client_role_capabilities(&token, "division-ci").unwrap();
        assert!(caps.scopes.is_empty());
    }

    #[test]
    fn client_role_capabilities_handles_an_empty_roles_list() {
        let token = test_jwt(serde_json::json!({
            "resource_access": { "division-ci": { "roles": [] } },
        }));
        let caps = client_role_capabilities(&token, "division-ci").unwrap();
        assert!(caps.scopes.is_empty());
    }

    #[test]
    fn client_role_capabilities_handles_a_missing_resource_access_claim() {
        let token = test_jwt(serde_json::json!({ "sub": "some-service-account" }));
        let caps = client_role_capabilities(&token, "division-ci").unwrap();
        assert!(caps.scopes.is_empty());
    }

    #[test]
    fn client_role_capabilities_errors_on_a_malformed_token() {
        let err = client_role_capabilities("not.a-jwt", "division-ci").unwrap_err();
        assert!(matches!(err, IdentityError::Auth(_)));
    }

    // ---- client_role_capabilities(): what it checks about a token and
    // what it does not. These pin the `exp` check as it was on jsonwebtoken 9
    // (`Validation::default()` with the signature check switched off and
    // `validate_aud = false`), so a change of jsonwebtoken major cannot
    // silently loosen it. See jsonwebtoken's "type confusion with exp/nbf"
    // advisory: the token's `exp` must be present, a number, and not
    // expired, and a wrong-typed `exp` must never read as "valid". The
    // tokens carry Keycloak's real header shape (RS256 with a `kid`). ------

    /// Claims that would give `division-ci` the `read:builds` role, with the
    /// given raw JSON `exp` value (or none) spliced in.
    fn claims_with_exp(exp: Option<serde_json::Value>) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "resource_access": { "division-ci": { "roles": ["read:builds"] } },
        });
        if let Some(exp) = exp {
            claims["exp"] = exp;
        }
        claims
    }

    /// `true` when `client_role_capabilities` accepted the token and mapped
    /// the role, i.e. the token was treated as valid.
    fn treated_as_valid(token: &str) -> bool {
        match client_role_capabilities(token, "division-ci") {
            Ok(caps) => {
                assert!(caps.includes(&CapabilityScope("read:builds".to_string())));
                true
            }
            Err(err) => {
                assert!(matches!(err, IdentityError::Auth(_)), "{err:?}");
                false
            }
        }
    }

    #[test]
    fn client_role_capabilities_refuses_a_token_with_no_exp() {
        let token = unsigned_test_jwt(&claims_with_exp(None));
        assert!(!treated_as_valid(&token));
    }

    #[test]
    fn client_role_capabilities_refuses_an_exp_of_the_wrong_type() {
        let future = now_unix() + 300;
        // Every one of these would, if it were read as "no expiry to check"
        // or as "not expired", let an unusable token through.
        let wrong_types = [
            ("a string of digits", serde_json::json!(future.to_string())),
            ("a string of text", serde_json::json!("never")),
            ("an empty string", serde_json::json!("")),
            ("true", serde_json::json!(true)),
            ("false", serde_json::json!(false)),
            ("null", serde_json::Value::Null),
            ("an array", serde_json::json!([future])),
            ("an object", serde_json::json!({ "exp": future })),
            ("a negative integer", serde_json::json!(-1)),
            ("a negative float", serde_json::json!(-1.5)),
            ("an integer beyond u64", serde_json::json!(1e30)),
        ];
        for (what, exp) in wrong_types {
            let token = unsigned_test_jwt(&claims_with_exp(Some(exp)));
            assert!(!treated_as_valid(&token), "exp as {what} was accepted");
        }
    }

    #[test]
    fn client_role_capabilities_refuses_an_expired_token() {
        let token = unsigned_test_jwt(&claims_with_exp(Some(serde_json::json!(now_unix() - 3600))));
        assert!(!treated_as_valid(&token));
        // The extreme: expired since the epoch.
        let token = unsigned_test_jwt(&claims_with_exp(Some(serde_json::json!(0))));
        assert!(!treated_as_valid(&token));
    }

    #[test]
    fn client_role_capabilities_allows_the_default_60_second_clock_skew() {
        // `jsonwebtoken`'s default leeway is 60 s. Against the real clock,
        // a token that expired 58 s ago still reads as current and one that
        // expired 62 s ago does not (so the test tolerates up to 2 s between
        // building the token and checking it). The exact edge, 60 against 61,
        // is pinned with a fixed clock in
        // `require_current_exp_boundary_is_exp_equal_to_now_minus_60`.
        let just_expired =
            unsigned_test_jwt(&claims_with_exp(Some(serde_json::json!(now_unix() - 58))));
        assert!(treated_as_valid(&just_expired));
        let long_expired =
            unsigned_test_jwt(&claims_with_exp(Some(serde_json::json!(now_unix() - 62))));
        assert!(!treated_as_valid(&long_expired));
    }

    #[test]
    fn client_role_capabilities_accepts_a_numeric_exp_in_any_json_number_form() {
        // RFC 7519 NumericDate is "a JSON numeric value", fractions allowed;
        // jsonwebtoken 9 accepted a non-negative finite float (rounded).
        let future = now_unix() + 300;
        for exp in [
            serde_json::json!(future),
            serde_json::json!(future as f64),
            serde_json::json!(future as f64 + 0.4),
            serde_json::json!(9_999_999_999_u64),
        ] {
            let token = unsigned_test_jwt(&claims_with_exp(Some(exp.clone())));
            assert!(treated_as_valid(&token), "exp {exp} was refused");
        }
    }

    #[test]
    fn client_role_capabilities_does_not_check_nbf() {
        // `Validation::validate_nbf` was never switched on: scalar `nbf`
        // values (a number, a string, a bool, null) are accepted whatever
        // they say. Pinned so a change here is deliberate. (Array and object
        // values are covered by
        // `client_role_capabilities_does_not_parse_claims_it_does_not_read`.)
        let future = now_unix() + 300;
        for nbf in [
            serde_json::json!(future + 100_000),
            serde_json::json!("not-a-number"),
            serde_json::json!(true),
            serde_json::Value::Null,
        ] {
            let mut claims = claims_with_exp(Some(serde_json::json!(future)));
            claims["nbf"] = nbf.clone();
            let token = unsigned_test_jwt(&claims);
            assert!(treated_as_valid(&token), "nbf {nbf} was refused");
        }
    }

    #[test]
    fn client_role_capabilities_never_looks_at_the_signature() {
        // By design (see the function's doc comment): a token whose signature
        // is another key's, garbage, or empty is read all the same.
        let claims = claims_with_exp(Some(serde_json::json!(now_unix() + 300)));
        let header = KEYCLOAK_JWT_HEADER;
        for signature in [
            "",
            "!!not base64url!!",
            "AAAA",
            "c2lnbmVkLWJ5LXNvbWVib2R5LWVsc2U",
        ] {
            let token = jwt_from_parts(header, &claims.to_string(), signature);
            assert!(
                treated_as_valid(&token),
                "signature {signature:?} was refused"
            );
        }
    }

    #[test]
    fn client_role_capabilities_does_not_check_audience_issuer_or_subject() {
        let mut claims = claims_with_exp(Some(serde_json::json!(now_unix() + 300)));
        claims["aud"] = serde_json::json!("some-other-service");
        claims["iss"] = serde_json::json!("https://not-the-realm.example");
        claims["sub"] = serde_json::json!("anyone");
        assert!(treated_as_valid(&unsigned_test_jwt(&claims)));
    }

    /// Claims shaped like a real Keycloak access token for a confidential
    /// client's service account (the Client Credentials grant): realm and
    /// resource roles side by side, an `aud` list, `azp`, and the usual
    /// extras this Kit never reads.
    fn keycloak_service_account_claims() -> serde_json::Value {
        serde_json::json!({
            "exp": now_unix() + 300,
            "iat": now_unix(),
            "jti": "6f1c2b0e-9d63-4a38-8a57-1f0f3c2f9a11",
            "iss": "https://id.example.com/realms/household",
            "aud": ["account", "some-resource-server"],
            "sub": "2d0b6a4c-5e1f-4f6e-9a77-0c1d2e3f4a5b",
            "typ": "Bearer",
            "azp": "division-ci",
            "scope": "profile email",
            "clientHost": "10.0.0.7",
            "email_verified": false,
            "preferred_username": "service-account-division-ci",
            "clientAddress": "10.0.0.7",
            "client_id": "division-ci",
            "realm_access": {
                "roles": ["default-roles-household", "offline_access", "uma_authorization"],
            },
            "resource_access": {
                "division-ci": { "roles": ["read:builds", "write:artifacts"] },
                "account": { "roles": ["manage-account", "view-profile"] },
            },
        })
    }

    #[test]
    fn client_role_capabilities_reads_a_keycloak_shaped_service_account_token() {
        let token = unsigned_test_jwt(&keycloak_service_account_claims());
        let caps = client_role_capabilities(&token, "division-ci").unwrap();
        assert_eq!(caps.scopes.len(), 2, "{:?}", caps.scopes);
        assert!(caps.includes(&CapabilityScope("read:builds".to_string())));
        assert!(caps.includes(&CapabilityScope("write:artifacts".to_string())));
        // Only this client's own roles: neither the realm roles nor another
        // client's roles in the same token become capabilities.
        for other in [
            "offline_access",
            "manage-account",
            "default-roles-household",
        ] {
            assert!(
                !caps.includes(&CapabilityScope(other.to_string())),
                "{other} leaked into the capabilities"
            );
        }
    }

    #[test]
    fn client_role_capabilities_reads_tokens_whatever_the_signing_algorithm() {
        // Keycloak signs with RS256 by default (the header every other test
        // uses), but a realm can use others, and the Kit never looks at the
        // signature: an HMAC token without a `kid` and an ES256 one with a
        // `kid` read the same.
        let payload = keycloak_service_account_claims().to_string();
        for header in [
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"alg":"ES256","typ":"JWT","kid":"ec-realm-key-1"}"#,
        ] {
            let token = jwt_from_parts(header, &payload, "placeholder-signature");
            let caps = client_role_capabilities(&token, "division-ci")
                .unwrap_or_else(|e| panic!("{header}: {e:?}"));
            assert!(
                caps.includes(&CapabilityScope("read:builds".to_string())),
                "{header}"
            );
        }
    }

    #[test]
    fn client_role_capabilities_refuses_a_token_that_is_not_a_jwt() {
        let claims = claims_with_exp(Some(serde_json::json!(now_unix() + 300)));
        let good_header = KEYCLOAK_JWT_HEADER;
        let good_payload = claims.to_string();
        let cases = [
            ("empty", String::new()),
            ("one segment", "abc".to_string()),
            ("two segments", {
                let t = jwt_from_parts(good_header, &good_payload, "x");
                t.rsplit_once('.').unwrap().0.to_string()
            }),
            (
                "payload not JSON",
                jwt_from_parts(good_header, "not json", "x"),
            ),
            (
                "payload a JSON array",
                jwt_from_parts(good_header, "[1,2]", "x"),
            ),
            (
                "header not JSON",
                jwt_from_parts("not json", &good_payload, "x"),
            ),
            (
                "no alg",
                jwt_from_parts(r#"{"typ":"JWT"}"#, &good_payload, "x"),
            ),
            // An unsigned `alg: none` token is not a token this Kit reads.
            (
                "alg none",
                jwt_from_parts(r#"{"alg":"none"}"#, &good_payload, ""),
            ),
            (
                "unknown alg",
                jwt_from_parts(r#"{"alg":"XX999"}"#, &good_payload, "x"),
            ),
            (
                "resource_access of the wrong shape",
                unsigned_test_jwt(&serde_json::json!({
                    "resource_access": "everything",
                    "exp": now_unix() + 300,
                })),
            ),
        ];
        for (what, token) in cases {
            assert!(!treated_as_valid(&token), "{what} was accepted");
        }
    }

    // ---- service_principal(): full client-credentials exchange against a
    // local mock server ----------------------------------------------------

    #[tokio::test]
    async fn service_principal_exchanges_client_credentials_and_maps_capabilities() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realms/household/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": format!("{}/realms/household", server.uri()),
                "authorization_endpoint": format!("{}/realms/household/protocol/openid-connect/auth", server.uri()),
                "token_endpoint": format!("{}/realms/household/protocol/openid-connect/token", server.uri()),
                "userinfo_endpoint": format!("{}/realms/household/protocol/openid-connect/userinfo", server.uri()),
            })))
            .mount(&server)
            .await;

        let access_token = test_jwt(serde_json::json!({
            "resource_access": { "division-ci-example": { "roles": ["read:builds"] } },
        }));

        Mock::given(method("POST"))
            .and(path("/realms/household/protocol/openid-connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            // Per RFC 6749 §2.3.1, `oauth2`'s default `AuthType::BasicAuth`
            // sends both `client_id` and `client_secret` only via the
            // `Authorization: Basic` header when a secret is present —
            // neither rides in the request body on this path. Asserting
            // the exact header value below proves that, rather than just
            // asserting the body's absence.
            .and(header(
                "authorization",
                format!(
                    "Basic {}",
                    base64_basic_auth("division-ci-example", "super-secret-value")
                )
                .as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": 300,
            })))
            .mount(&server)
            .await;

        let mut config = KeycloakServicePrincipalConfig::new(
            server.uri(),
            "household",
            "division-ci-example",
            "super-secret-value",
        );
        config.roles_client_id = "division-ci-example".to_string();

        let principal = KeycloakAuthN::service_principal(config).await.unwrap();

        assert_eq!(principal.device(), None);
        assert!(principal.has(&CapabilityScope("read:builds".to_string())));
    }

    #[tokio::test]
    async fn service_principal_rejects_an_empty_client_secret_without_a_network_call() {
        // Deliberately no mocks registered: if validation didn't run
        // first, wiremock would 404 rather than this returning a typed
        // config error.
        let server = MockServer::start().await;
        let mut config = KeycloakServicePrincipalConfig::new(
            server.uri(),
            "household",
            "division-ci-example",
            "super-secret-value",
        );
        config.client_secret = String::new();

        let result = KeycloakAuthN::service_principal(config).await;
        assert!(matches!(result, Err(IdentityError::Auth(_))));
    }

    /// Minimal, dependency-free base64 (RFC 4648 standard alphabet, with
    /// padding) encoder — only needed here to independently compute the
    /// `Authorization: Basic` header value `oauth2`'s default `AuthType`
    /// sends the client secret through, so the test below doesn't take on
    /// a new crate dependency just to assert a header value.
    fn base64_basic_auth(client_id: &str, client_secret: &str) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let input = format!("{client_id}:{client_secret}");
        let bytes = input.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
            out.push(if chunk.len() > 1 {
                CHARS[((n >> 6) & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                CHARS[(n & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    // ---- live-IdP integration test ---------------------------------------
    //
    // Everything above runs against a local `wiremock` server and needs no
    // network access. This one genuinely needs a live Keycloak realm — it
    // exists to catch drift between our discovery-document assumptions and
    // what a real Keycloak instance actually serves. It's `#[ignore]`d so
    // `cargo test` stays hermetic; run it explicitly against a real
    // instance:
    //
    //   IDENTITY_KIT_KC_BASE_URL=https://id.example.com \
    //   IDENTITY_KIT_KC_REALM=staff \
    //     cargo test --test '*' -- --ignored discovery_against_a_live_keycloak_realm
    //
    // (or run it as a unit test target — it lives here since it exercises
    // this module's `discovery_url`/`OidcDiscoveryDocument` directly.)
    #[tokio::test]
    #[ignore = "requires a live Keycloak instance; see the doc comment above this test"]
    async fn discovery_against_a_live_keycloak_realm() {
        let base_url = std::env::var("IDENTITY_KIT_KC_BASE_URL")
            .unwrap_or_else(|_| "https://id.example.com".to_string());
        let realm = std::env::var("IDENTITY_KIT_KC_REALM").unwrap_or_else(|_| "staff".to_string());

        let http = reqwest::Client::new();
        let url = discovery_url(&base_url, &realm).unwrap();
        let doc: OidcDiscoveryDocument = http.get(url).send().await.unwrap().json().await.unwrap();

        assert!(doc.authorization_endpoint.contains(&realm));
        assert!(doc.token_endpoint.contains(&realm));
        assert!(doc.userinfo_endpoint.contains(&realm));
    }
}
