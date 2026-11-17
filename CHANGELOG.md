# Changelog

All notable changes to **identity-kit** will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First public release, as `slashbuilder-identity-kit` 0.2.0 on crates.io.
The library is still imported as `identity_kit`. Earlier 0.1.x builds were
internal only and were never published to crates.io; this file records
their history so the 0.2.0 changes read in order.

### Changed

- **Package renamed to `slashbuilder-identity-kit`** (the plain
  `identity-kit` name on crates.io belongs to another crate). The library
  name is unchanged (`[lib] name = "identity_kit"`), so `use identity_kit::...`
  keeps working.
- The conformance test now resolves its harness from crates.io
  (`slashbuilder-spec-kit` 0.1, imported as `spec_kit`) instead of a private
  registry. The harness shape is the same.

### Security

- **Credentials never travel over plain `http`.** Every URL that carries a
  secret or token is refused unless it is `https`, or `http` to a loopback host
  (`localhost`, `127.0.0.1`, `::1`, for local tests): the Keycloak and service
  principal base URLs, the endpoints an identity provider advertises in its
  discovery document, and the Account and Family clients. A URL that embeds
  `user:password@` is refused. The check fails with
  `IdentityError::InsecureTransport`.
- A redirect is followed only to a target that passes the same check, so a
  redirect cannot downgrade a request to plain `http`. Token requests still
  refuse every redirect.
- All HTTP clients now have timeouts (30 s per request, 10 s to connect).
- The OAuth2 token calls (client credentials, authorization code, refresh) go
  through this crate's own `reqwest` 0.12 client, so the older HTTP and TLS
  stack that `oauth2` 4 bundles (with known advisories) is no longer built.
- `AuthN::auth0` and the deprecated `FamilyClient::fetch_members` now return
  `IdentityError::NotImplemented` instead of panicking.
- The unused `keyring` and `tracing` dependencies were removed.
- `cargo-deny` carries one dated exception: `chrono` is flagged unmaintained
  (RUSTSEC-2026-0543, a notice, no vulnerability); re-review by 2027-02-16.
- The minimum supported Rust version is now stated and tested: 1.88.

### Added

- **Account self-service client.** `account::AccountClient` is a stateless,
  token-scoped client against Keycloak's Account REST API: profile
  read/update, session/device listing and revocation. `change_password`
  returns `IdentityError::NotImplemented`, because Keycloak's Account REST
  API has no password endpoint (self-service password change is a
  `kc_action=UPDATE_PASSWORD` browser redirect).
- **Service-principal AuthN.** `AuthN::service_principal_keycloak` performs
  the OAuth2 Client Credentials grant for a non-interactive caller and maps
  the token's client roles into a `ServicePrincipal`'s `Capabilities`
  (`KeycloakServicePrincipalConfig`). This is not the Resource Owner
  Password Credentials grant, which remains unsupported.
- `authz::ServicePrincipal` and `PrincipalId`, exported at the crate root,
  plus a conformance test that pins the capability and principal invariants
  (`tests/conformance.rs` in the repository).
- **Person-rooted account model.**
  - `Account` gained `pub origin: AccountOrigin` (`Standalone` |
    `CreatedInHousehold`). It still carries no scalar household id.
  - New types: `AccountOrigin`, `Household`, `Membership` (person x
    household, with `role`, `joined_at` and `state`), `MembershipState`
    (`#[non_exhaustive]`: `Active` and `Pending`) and `GuardianEdge` (child
    to guardian, only constructible through `GuardianEdge::new` for a
    `CreatedInHousehold` child).
  - New `IdentityError` variants: `LastOwner`, `InvalidGuardianEdge`,
    `NotYetSupported(String)` (an identity-service route that exists but
    answers `501`) and `InsecureTransport`.
  - `family::FamilyClient` is rooted on the person and implemented for real
    over `reqwest`: `list_memberships`, `invite`, `accept_invite`, `leave`,
    `create_child` and `emancipate`. `FamilyClient::new(base_url,
    access_token)` forwards the caller's own access token as
    `Authorization: Bearer` on every call. `create_child` and `emancipate`
    surface the server's `501` as `IdentityError::NotYetSupported`.
  - `MembershipRecord` mirrors the identity service's member wire shape and
    carries `household_id` and `household_display_name`.
  - `family::guard_last_owner_leave`: the client-expressible half of the
    "a household keeps at least one `Owner`" invariant, usable as a local
    pre-flight check.
  - New dependency: `chrono` (with `serde`), for `joined_at` and
    `created_at`.
- **Keycloak AuthN.** `AuthN::keycloak` performs real OIDC discovery
  (`{base_url}/realms/{realm}/.well-known/openid-configuration`) and drives
  Authorization Code + PKCE (`S256`) via `oauth2` v4 and `reqwest`, with
  silent refresh through the standard `refresh_token` grant. Nothing
  hardcodes a realm name or endpoint path. Sessions persist through the
  `TokenCache` trait seam. New public types:
  `authn::keycloak::{KeycloakConfig, PendingAuthorization, Session}`, plus
  `AuthN::{begin_sign_in, complete_sign_in, refresh, sign_out}`. It does not
  implement Resource Owner Password Credentials or any other
  credential-collecting flow.
- Initial scaffold: the public module surface (`account`, `authn`, `authz`,
  `family`, `token`, `error`), the `Account`, `Device`, `DeviceKind`,
  `FamilyMember` and `FamilyRole` data model, the `AuthN` handle with
  `Auth0Config` / `KeycloakConfig`, `Scope` and `Capabilities`, the
  `TokenCache` trait and `IdentityError`.

### Changed (breaking, 0.2.0)

- Any external struct-literal construction of `Account` needs the new
  `origin` field, or the new `Account::new(id, display_name, email, origin)`
  constructor. This is why the version moved from 0.1 to 0.2.0.
- `AuthN::keycloak` takes a second argument, `token_cache: Arc<dyn
  TokenCache>`. (It was `unimplemented!()` before.)
- `KeycloakConfig` gained `client_secret: Option<String>`, `redirect_url:
  String` and `scopes: Vec<String>`. Use `KeycloakConfig::new(base_url,
  realm, client_id, redirect_url)` for the usual public-client shape.
- `FamilyClient` follows the identity service's real routes: path-carried
  ids are no longer repeated in request bodies, `leave(household, person)`
  takes no body, and `list_memberships` returns `MembershipRecord`s.
- Joining a household is invite-then-accept: `FamilyClient::join` and
  `JoinHouseholdRequest` are replaced by `FamilyClient::invite` /
  `InviteMemberRequest` (creates a `pending` row) and
  `FamilyClient::accept_invite(household, person)`.
- `CreateChildRequest` and `CreateChildResponse` are removed. A
  client-supplied child account id let a household adult capture an existing
  identity; `FamilyClient::create_child(household)` now takes no request.
  The `409 invalid_guardian_edge` mapping is dropped from
  `family::error_from_parts`.

### Deprecated

- `FamilyMember` and `FamilyClient::fetch_members` (since 0.2.0): a role is
  per-membership, not per-account. Both still compile, and
  `fetch_members` is still `unimplemented!()`. Use `Membership` and
  `FamilyClient::list_memberships`.

### Security

- `FamilyClient::new` refuses a non-`https` `base_url`, so a bearer token
  can never cross the network in the clear. `http` is allowed only for
  `localhost`, `127.0.0.1` and `::1`. Failure is `IdentityError::InsecureTransport`.
- `Session`'s `Debug` output redacts the access and refresh tokens, and the
  same holds for `KeycloakServicePrincipalConfig`'s client secret.

### Notes

- The authorization *engine* is intentionally not included; Identity Kit is
  the client side only.
- `AuthN::auth0` is a stub (`unimplemented!()`); the identity-provider
  decision landed on Keycloak.

[Unreleased]: https://github.com/slash-builder/identity-kit/commits/main
