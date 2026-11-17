//! Shared HTTP plumbing: one rule for which URLs may carry a credential, and one client builder with timeouts.

use std::time::Duration;

use url::{Host, Url};

use crate::IdentityError;

/// Total time allowed for one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Time allowed to establish the connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most redirects a request may follow.
const MAX_REDIRECTS: usize = 10;

/// A `reqwest` client builder with timeouts, so a stalled identity provider cannot hang the caller forever, and a
/// redirect policy that never follows a redirect to a target [`ensure_secure_url`] would refuse (so a redirect cannot
/// downgrade a request from `https` to plain `http` and carry a bearer token with it).
pub(crate) fn http_client_builder() -> reqwest::ClientBuilder {
    let redirects = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        match ensure_secure_url(attempt.url(), "redirect target") {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e.to_string()),
        }
    });
    reqwest::Client::builder()
        .redirect(redirects)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
}

/// Refuses a URL that would carry a credential in the clear.
///
/// `https` always passes. `http` passes only for a loopback host (`localhost`, `127.0.0.0/8`, `::1`), so tests against a
/// mock server bound to loopback keep working. Any other scheme, and `http` to any other host, is refused with
/// [`IdentityError::InsecureTransport`]. `what` names the value in the error message (never put a secret in it).
pub(crate) fn ensure_secure_url(url: &Url, what: &str) -> Result<(), IdentityError> {
    // A credential embedded in a URL would end up in logs and error messages; never accept one.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(IdentityError::InsecureTransport(format!(
            "{what} must not embed credentials in the URL"
        )));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match url.host() {
                Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
                Some(Host::Ipv4(ip)) => ip.is_loopback(),
                Some(Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if loopback {
                Ok(())
            } else {
                Err(IdentityError::InsecureTransport(format!(
                    "{what} is http but not a loopback host; use https"
                )))
            }
        }
        other => Err(IdentityError::InsecureTransport(format!(
            "{what} has unsupported scheme {other:?}; use https"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(raw: &str) -> Result<(), IdentityError> {
        ensure_secure_url(&Url::parse(raw).unwrap(), "test url")
    }

    #[test]
    fn https_is_accepted() {
        assert!(check("https://id.example.com/realms/x").is_ok());
    }

    #[test]
    fn http_is_accepted_only_on_loopback_hosts() {
        assert!(check("http://localhost:8080").is_ok());
        assert!(check("http://127.0.0.1:8080").is_ok());
        assert!(check("http://[::1]:8080").is_ok());
    }

    #[test]
    fn http_to_any_other_host_is_refused() {
        assert!(matches!(
            check("http://id.example.com"),
            Err(IdentityError::InsecureTransport(_))
        ));
        assert!(matches!(
            check("http://10.0.0.5:8080"),
            Err(IdentityError::InsecureTransport(_))
        ));
    }

    #[test]
    fn a_hostname_that_only_looks_like_localhost_is_refused() {
        assert!(matches!(
            check("http://localhost.evil.example"),
            Err(IdentityError::InsecureTransport(_))
        ));
    }

    #[test]
    fn a_url_with_embedded_credentials_is_refused() {
        assert!(matches!(
            check("https://user:secret@id.example.com"),
            Err(IdentityError::InsecureTransport(_))
        ));
        assert!(matches!(
            check("https://user@id.example.com"),
            Err(IdentityError::InsecureTransport(_))
        ));
    }

    #[tokio::test]
    async fn a_redirect_to_plain_http_on_another_host_is_not_followed() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://idp.example.invalid/steal"),
            )
            .mount(&server)
            .await;
        let client = http_client_builder().build().unwrap();
        let result = client.get(server.uri()).send().await;
        let err = result.expect_err("a downgrade redirect must be refused");
        assert!(err.is_redirect(), "expected a redirect error, got: {err}");
    }

    #[test]
    fn other_schemes_are_refused() {
        assert!(matches!(
            check("ftp://id.example.com"),
            Err(IdentityError::InsecureTransport(_))
        ));
    }
}
