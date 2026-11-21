# Identity Kit

> Rust client library for OIDC sign-in, household / family-graph identity,
> and capability-based authorization.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange.svg)

Identity Kit is the *client* side of identity for Rust applications. It
talks to an OIDC provider (Keycloak today), exposes an
account / device / household-membership data model, provides a
stateless client for Keycloak's self-service Account REST API, and
provides the capability primitives that authorization checks consume.
Tokens are persisted through a small `TokenCache` trait that you
implement (an OS-keychain default is planned, not shipped).

It does **not** ship an identity service of its own — it's a client
library that integrates with whatever IdP you bring.

## Status

Pre-1.0: the API can change in any minor release; changes are listed in
[`CHANGELOG.md`](CHANGELOG.md). The data model and trait surfaces are in
place. **Keycloak AuthN is implemented** — real OIDC discovery +
Authorization Code + PKCE, silent refresh, the Client Credentials grant
for non-interactive service principals, all wired to the `TokenCache`
seam. Auth0 (`AuthN::auth0`) is a stub that returns
`IdentityError::NotImplemented`. `FamilyClient` is a real HTTP client for an identity
service's household/membership REST routes, but those routes belong to a
server that is not part of this crate. The deprecated
`FamilyClient::fetch_members` is also still a stub, and returns the same error.

## Install

```toml
[dependencies]
slashbuilder-identity-kit = "0.2"
```

The package is named `slashbuilder-identity-kit` (the plain `identity-kit`
name on crates.io belongs to an unrelated crate), but the library is
still imported as **`identity_kit`**, so `use identity_kit::...` is what
you write. If you prefer the short name in `Cargo.toml` as well:

```toml
identity-kit = { package = "slashbuilder-identity-kit", version = "0.2" }
```

## Quick start

```rust
use std::sync::Arc;
use identity_kit::authn::{AuthN, KeycloakConfig};

let config = KeycloakConfig::new(
    "https://id.example.com",   // your Keycloak instance
    "my-realm",                 // the realm is a per-product knob, never hardcoded
    "my-desktop-app",           // client id
    "myapp://auth/callback",    // redirect URL
);
let client = AuthN::keycloak(config, token_cache).await?; // Arc<dyn TokenCache>

// 1. Open `pending.authorize_url` in a real browser/webview.
let pending = client.begin_sign_in();

// 2. After the IdP redirects back with `code` + `state`:
let session = client.complete_sign_in(pending, code, state).await?;
let me = session.account().clone();

// Later, silently:
let session = client.refresh().await?;
```

This flow never collects a password inside the library — only
Authorization Code + PKCE via the IdP's own hosted login page. The
Resource Owner Password Credentials grant is deliberately not
implemented.

Self-service account maintenance is a separate, stateless,
token-scoped client — not part of `AuthN`, since it has no session to own:

```rust
use identity_kit::account::AccountClient;

let account = AccountClient::new("https://id.example.com", "my-realm")?;
let profile = account.get_profile(bearer_token).await?; // caller-supplied, per call
let devices = account.list_sessions(bearer_token).await?;
account.revoke_other_sessions(bearer_token).await?;
```

See the header comment of `src/account/keycloak.rs` for why it's a
separate type from `AuthN`, and for a real Keycloak API-shape finding:
`change_password` returns `IdentityError::NotImplemented` because
Keycloak's Account REST API has never shipped a
`/account/credentials/password` endpoint (verified from source across
every tagged release through Keycloak `26.0.0`) — self-service password
change on that version is a `kc_action=UPDATE_PASSWORD` browser
redirect, not a REST call.

## Data model

A small, deliberately conservative shape:

- **`Account`** — a person (id, display name, optional email) with an
  `AccountOrigin` (`Standalone` or `CreatedInHousehold`). It carries no
  household id.
- **`Household`** and **`Membership`** — a person × household record with
  a `FamilyRole` (`Owner` / `Adult` / `Child` / `Guest`) and a
  `MembershipState`. A person may hold several memberships.
- **`GuardianEdge`** — child → guardian, only constructible for a
  `CreatedInHousehold` child.
- **`Device`** — a device claimed by an account, tagged with a
  `DeviceKind`.
- **`Scope`**, **`Capabilities`** and **`ServicePrincipal`** — opaque
  scope strings, a bag that authorization checks evaluate against, and a
  grant-holding subject that other Kits embody rather than redefine.

`FamilyMember` is deprecated since 0.2.0 (a role is per-membership, not
per-account); use `Membership`.

## Scope

**In scope.** Account, device, and household-membership types. OIDC
sign-in against Keycloak (Authorization Code + PKCE, refresh, and the
Client Credentials grant for service principals). A token-cache seam.
Capability evaluation primitives. A stateless client for Keycloak's
Account REST API.

**Out of scope.** The IdP itself (Keycloak is deployed separately; Auth0
is a stub). The identity service that stores households and memberships.
The authorization *engine* — Identity Kit is the client; the engine
decides grants and is intentionally not in this crate. Federation IN
(accepting an upstream SSO) — that's a service-side concern.

## How it fits

Identity Kit is consumed by other Kits in the SlashBuilder Kit ecosystem
(for example the substrate and fabric Kits use its `ServicePrincipal`).
Outside that ecosystem it's a serviceable OIDC client library with an
opinionated household account model layered on top.

## Building from source

```bash
git clone https://github.com/slash-builder/identity-kit.git
cd identity-kit
cargo test
```

Requires Rust 1.89 or newer (the minimum supported Rust version, checked
in CI) and no system libraries. The tests are hermetic: they run against
a local mock server and never touch a real IdP or keychain. One
`#[ignore]`d test talks to a live Keycloak realm you point it at; see its
doc comment in `src/authn/keycloak.rs`.

## Contributing

Contributions welcome under Apache-2.0; see
[`CONTRIBUTING.md`](CONTRIBUTING.md). Sign your commits with
`git commit -s` to attest under the Developer Certificate of Origin.

Auth code lives at a particularly load-bearing seam — changes to the
public API surface should start as an issue, since downstream Kits
inherit the shape. To report a vulnerability, see
[`SECURITY.md`](SECURITY.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).

## About

Identity Kit is part of the **SlashBuilder Kit ecosystem** — a set of
reusable Rust and Dart libraries built around the BeOS-style "Kit"
pattern. Each Kit owns a self-contained domain (storage, messaging,
identity, fabric, devices, app store, design); products are composed
from Kits.

Maintained by [SlashBuilder](https://slashbuilder.com) / Douglas Lockamy.
