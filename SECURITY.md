# Security policy

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Report it privately, by either of these:

1. **GitHub private vulnerability reporting:** use the "Report a vulnerability" button on the [Security tab of this repository](https://github.com/slash-builder/identity-kit/security/advisories/new). Only the maintainer and you see the report.
2. **Email:** security@slashbuilder.com, for when GitHub's form is not an option for you.

Please include:

* what you found and where (file, command or page);
* the commit of `main` you looked at (`git rev-parse HEAD`) and your operating system;
* steps to reproduce it, or a short proof of concept;
* what you think the impact is, and whether anyone else knows.

## What to expect

You get an **acknowledgement within 7 days**, from a person. Nothing else is promised: this project has one maintainer, no paid support and no fixed fix time. If the report is valid, the reply says what happens next; if it is not, it says why.

## Supported versions

This project is pre-1.0. **Only the latest release and the latest commit of `main` are supported.** Older versions get no fixes; update to the latest release.

## Scope

In scope: the code and the documentation in **this repository**: the Rust crate (`slashbuilder-identity-kit`), including how it handles access tokens, refresh tokens, client secrets, PKCE state and redirect URLs, and how it validates the URLs it is given.

Out of scope: third-party services and software (GitHub, Keycloak, other identity providers, Rust and their packages), any identity service or server this client is pointed at, and any other software the Kit can be used with. A problem there belongs with its owners. If you are not sure where something belongs, report it here, privately.
