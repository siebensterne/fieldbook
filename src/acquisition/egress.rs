//! Egress policy: how collection traffic leaves the process.
//!
//! Direct networking remains the default. An explicitly configured proxy is
//! considered only for a route the account holder is, by the venue's terms,
//! eligibility rules, and applicable law, permitted to use. A proxy is a
//! network path, not an entitlement to access a venue, and this module must
//! never be used to disguise a client's location or bypass a restriction.
//!
//! Properties enforced here:
//!
//! - **Rights before routes.** No HTTP client is built until the runtime
//!   authorization source has granted a live, venue-scoped right. A proxy is a
//!   route, never an entitlement.
//! - **Fail closed.** In `explicit_proxy` mode, a proxy that cannot be
//!   reached or negotiated fails the connection. There is never a silent
//!   fallback to direct egress.
//! - **Direct stays direct.** Direct mode never inherits unrelated shell
//!   proxy variables; the explicit route is the only route that is added,
//!   and the HTTP client is built with `no_proxy` before the explicit route
//!   is applied.
//! - **Secrets stay in the environment.** Proxy endpoints and credentials are
//!   read from environment variables named by `[network]` in configuration,
//!   never from the TOML document itself. They are never serialized, hashed
//!   into fingerprints, written to logs, or embedded in error messages.
//! - **Venue authentication is end-to-end.** Adapter signatures and venue TLS
//!   credentials are only ever sent through the venue's TLS connection. A
//!   proxy observes destination metadata; it is not a trust anchor.
//!
//! Egress is fail-closed: an unqualified destination is refused before any
//! socket is opened, and the proxy's observation is metadata, not authority.
//! A successful connection never grants source rights.

use std::fmt;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    config::NetworkSettings,
    egress_intent::{EgressIntent, EndpointIdentity, MAX_REDIRECTS},
    governance::operation_plan::{
        OperationClass, OperationPlan, PlanRequest, class_for, require_plan_step,
    },
    rights::{AuthorizationGate, require_provider_egress},
    util::sha256_hex,
};

/// The actual HTTP request being authorized, supplied by the caller at dispatch.
///
/// The intent carries the provider, source product, operation and full scope.
/// The URL, method and resource class are the *actual* request, never values
/// reconstructed from a plan step, a client or an installed proof.
#[derive(Debug, Clone)]
pub struct HttpEgressRequest<'a> {
    pub intent: &'a EgressIntent,
    pub url: &'a str,
    pub method: &'a str,
    pub resource_class: &'a str,
    pub approved_resource_class: &'a str,
    pub approved_method: &'a str,
    pub gate: &'a AuthorizationGate,
    pub at_us: i64,
}

/// Authorize one actual HTTP request before any client, DNS, TCP or TLS work.
///
/// Checks that the operation is a provider-egress step, that the URL's
/// authority and scheme are exactly the ones in the caller's intent, that the
/// method and endpoint resource class are the approved ones, and finally that
/// the full intent is covered by a live authorization. A denial is always a
/// denial: no network layer is reached.
///
/// # Errors
/// Returns the fail-closed denial before dispatch is allowed to run.
pub fn authorize_http_request(binding: &HttpEgressRequest<'_>) -> anyhow::Result<()> {
    anyhow::ensure!(
        class_for(binding.intent.operation) == OperationClass::ProviderEgress,
        "HTTP egress operation `{}` is not a provider-egress operation",
        binding.intent.operation.as_str()
    );
    anyhow::ensure!(
        !binding.resource_class.trim().is_empty()
            && binding.resource_class == binding.approved_resource_class,
        "HTTP endpoint resource class `{}` is not the approved class `{}`",
        binding.resource_class,
        binding.approved_resource_class
    );
    anyhow::ensure!(
        !binding.method.trim().is_empty() && binding.method == binding.approved_method,
        "HTTP method `{}` is not the approved method `{}`",
        binding.method,
        binding.approved_method
    );
    let actual = EndpointIdentity::from_url(binding.url)
        .map_err(|error| anyhow::anyhow!("HTTP target has no usable endpoint: {error}"))?;
    anyhow::ensure!(
        actual == binding.intent.endpoint_identity,
        "HTTP target `{}` is not the authorized endpoint `{}`",
        actual.authority(),
        binding.intent.endpoint_identity.authority()
    );
    binding.intent.validate()?;
    binding.gate.require_egress(binding.intent, binding.at_us)
}

/// Authorize, then run one HTTP dispatch. The `send` closure is the only place
/// a socket can be opened; injected transports make denial tests fail if it
/// is reached. On denial it is never called.
///
/// # Errors
/// Returns the authorization denial without calling `send`, or the dispatch
/// error when authorization succeeded.
pub fn dispatch_http_request<T>(
    binding: &HttpEgressRequest<'_>,
    send: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    authorize_http_request(binding)?;
    send()
}

/// Derive an HTTP binding from an authorized plan step. The approved resource
/// class and method come from the declaration, not from the dispatch caller,
/// and the step is reauthorized before the binding is returned.
///
/// # Errors
/// Returns the fail-closed denial when the step is missing, unauthorized or
/// not an egress step.
pub fn http_request_for_plan_step<'a>(
    plan: &'a OperationPlan,
    operation: crate::rights::Operation,
    url: &'a str,
    method: &'a str,
    resource_class: &'a str,
    gate: &'a AuthorizationGate,
    at_us: i64,
) -> anyhow::Result<HttpEgressRequest<'a>> {
    require_plan_step(plan, operation, gate, at_us)?;
    let step = plan
        .step_for_operation(operation)
        .ok_or_else(|| anyhow::anyhow!("no plan step for operation {operation:?}"))?;
    let PlanRequest::Egress(intent) = &step.request else {
        anyhow::bail!("plan step `{operation:?}` is not a provider-egress step");
    };
    let approved = step.approved_resource_class.as_deref().ok_or_else(|| {
        anyhow::anyhow!("plan step `{operation:?}` has no approved resource class")
    })?;
    let approved_method = step
        .approved_http_method
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("plan step `{operation:?}` has no approved HTTP method"))?;
    Ok(HttpEgressRequest {
        intent,
        url,
        method,
        resource_class,
        approved_resource_class: approved,
        approved_method,
        gate,
        at_us,
    })
}

/// Proxy protocol the venue must be reached through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    /// HTTP `CONNECT` tunnel; venue TLS is established end-to-end after the
    /// tunnel is up.
    HttpConnect,
    /// SOCKS5; the venue TLS handshake runs inside the stream the proxy
    /// provides.
    Socks5,
}

impl ProxyScheme {
    fn evidence_name(self) -> &'static str {
        match self {
            Self::HttpConnect => "http_connect",
            Self::Socks5 => "socks5",
        }
    }
}

/// Proxy credentials read exclusively from the environment.
///
/// `Debug` and `Display` are not implemented because instances carry proxy
/// credentials and are passed only to the client library.
#[derive(Clone)]
struct ProxyAuth {
    username: String,
    password: String,
}

/// A validated, non-secret view plus the redactable credential domain of a
/// configured proxy.
#[derive(Clone)]
pub struct ProxyEndpoint {
    /// Tunnel protocol.
    pub scheme: ProxyScheme,
    /// Proxy host (no brackets).
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// When true (SOCKS5 only), the proxy resolves the venue hostname. For
    /// `socks5h://` this is forced on; for `socks5://` it comes from
    /// `[network] proxy_remote_dns`.
    pub remote_dns: bool,
    auth: Option<ProxyAuth>,
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyEndpoint")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("remote_dns", &self.remote_dns)
            .field("authenticated", &self.auth.is_some())
            .finish()
    }
}

impl ProxyEndpoint {
    pub(crate) fn authentication(&self) -> Option<(&str, &str)> {
        self.auth
            .as_ref()
            .map(|auth| (auth.username.as_str(), auth.password.as_str()))
    }
}

/// How collection traffic leaves the process.
#[derive(Clone)]
pub enum EgressRoute {
    /// Direct connections to the venue. The default.
    Direct,
    /// A single, explicitly configured proxy. Connections either use this
    /// route or fail; they never fall back to direct networking.
    ExplicitProxy(ProxyEndpoint),
}

impl fmt::Debug for EgressRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("Direct"),
            Self::ExplicitProxy(endpoint) => formatter
                .debug_tuple("ExplicitProxy")
                .field(endpoint)
                .finish(),
        }
    }
}

/// Non-secret provenance recorded in evidence artifacts and the journal
/// manifest. Hosts and ports are recorded because they determine route
/// reachability; credentials and TLS material never appear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteProvenance {
    /// `direct` or `explicit_proxy`.
    pub mode: String,
    /// `direct`, `http_connect`, or `socks5`.
    pub kind: String,
    /// Proxy host, or absent for direct mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Proxy port, or absent for direct mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SOCKS5 DNS mode; absent for direct and HTTP CONNECT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_dns: Option<bool>,
    /// Operator-chosen, non-secret route label from `[network] proxy_label`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// SHA-256 of the non-secret route identity; stable across runs on the
    /// same configuration.
    pub fingerprint_sha256: String,
}

impl EgressRoute {
    /// Resolve the effective route from validated transport settings,
    /// reading the process environment.
    ///
    /// # Errors
    ///
    /// In `explicit_proxy` mode any ambiguity — a missing or malformed proxy
    /// URL, an unsupported scheme, a missing component, or a partially
    /// specified credential pair — is an error, not a best effort.
    pub fn from_network(network: &NetworkSettings) -> anyhow::Result<Self> {
        Self::from_network_with(network, |name| std::env::var(name).ok())
    }

    /// Resolve the effective route with an injected environment lookup.
    ///
    /// The lookup mirrors `std::env::var`, including values. This keeps the
    /// resolution path unit-testable without touching process-global state;
    /// production code always uses [`Self::from_network`].
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::from_network`].
    pub fn from_network_with(
        network: &NetworkSettings,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        Self::from_network_inner(network, &lookup)
    }

    fn from_network_inner(
        network: &NetworkSettings,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        if network.egress_mode.eq_ignore_ascii_case("direct") {
            return Ok(Self::Direct);
        }
        if !network.egress_mode.eq_ignore_ascii_case("explicit_proxy") {
            bail!(
                "network.egress_mode must be `direct` or `explicit_proxy`, got `{}`",
                network.egress_mode
            );
        }

        let non_empty = |name: &str| {
            lookup(name).and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            })
        };

        let proxy_url_env = non_empty(&network.proxy_url_env).with_context(|| {
            format!(
                "network.egress_mode = explicit_proxy requires environment variable {} to be set to a valid proxy URL",
                network.proxy_url_env
            )
        })?;

        let parsed = Url::parse(&proxy_url_env).with_context(|| {
            format!(
                "environment variable {} does not hold a valid URL",
                network.proxy_url_env
            )
        })?;

        let scheme_lower = parsed.scheme().to_ascii_lowercase();
        let remote_dns_forced = match scheme_lower.as_str() {
            "socks5h" => true,
            _ => network.proxy_remote_dns,
        };
        let scheme = match scheme_lower.as_str() {
            "http" => ProxyScheme::HttpConnect,
            "socks5" | "socks5h" => ProxyScheme::Socks5,
            "https" => bail!(
                "environment variable {} uses `https://` proxies, which are not supported; an HTTP CONNECT proxy must be plain `http://`, or use `socks5://` / `socks5h://`",
                network.proxy_url_env
            ),
            other => bail!(
                "environment variable {} uses unsupported proxy scheme `{other}`; supported: http, socks5, socks5h",
                network.proxy_url_env
            ),
        };
        if scheme != ProxyScheme::Socks5 && network.proxy_remote_dns {
            // A typed choice that does not apply is not silently honoured.
            bail!("network.proxy_remote_dns is only meaningful for socks5 proxies");
        }

        let raw_host = parsed.host_str().with_context(|| {
            format!(
                "environment variable {} must name a proxy host",
                network.proxy_url_env
            )
        })?;
        let host = strip_brackets(raw_host).to_owned();
        let default_port = match scheme {
            ProxyScheme::HttpConnect => 8080,
            ProxyScheme::Socks5 => 1080,
        };
        let port = parsed.port().unwrap_or(default_port);

        // Credential domain: an explicit user/password env pair wins; otherwise
        // URL userinfo is used. Both must be fully specified or fully absent.
        let (username, password) = match (
            non_empty(&network.proxy_auth_user_env),
            non_empty(&network.proxy_auth_password_env),
        ) {
            (Some(user), Some(password)) => (user, password),
            (Some(_), None) => bail!(
                "environment variable {} is set but {} is not; proxy authentication requires both",
                network.proxy_auth_user_env,
                network.proxy_auth_password_env
            ),
            (None, Some(_)) => bail!(
                "environment variable {} is set but {} is not; proxy authentication requires both",
                network.proxy_auth_password_env,
                network.proxy_auth_user_env
            ),
            (None, None) => {
                let user = parsed.username();
                match parsed.password() {
                    Some(pass) if !user.is_empty() && !pass.is_empty() => {
                        (user.to_owned(), pass.to_owned())
                    }
                    Some(pass) if user.is_empty() && !pass.is_empty() => bail!(
                        "environment variable {} carries a proxy password with no username",
                        network.proxy_url_env
                    ),
                    Some(pass) if !user.is_empty() && pass.is_empty() => bail!(
                        "environment variable {} carries a proxy username with an empty password",
                        network.proxy_url_env
                    ),
                    _ => (String::new(), String::new()),
                }
            }
        };

        let auth = if username.is_empty() {
            None
        } else {
            Some(ProxyAuth { username, password })
        };

        Ok(Self::ExplicitProxy(ProxyEndpoint {
            scheme,
            host,
            port,
            remote_dns: remote_dns_forced,
            auth,
        }))
    }

    /// The `[network]`-derived, operator-supplied non-secret route label, if any.
    fn route_label(network_label: &Option<String>) -> Option<String> {
        network_label.as_ref().and_then(|label| {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        })
    }

    /// Build the provenance record persisted in journals and probe reports.
    #[must_use]
    pub fn provenance(&self, network: &NetworkSettings) -> RouteProvenance {
        let label = Self::route_label(&network.proxy_label);
        match self {
            Self::Direct => RouteProvenance {
                mode: "direct".to_owned(),
                kind: "direct".to_owned(),
                host: None,
                port: None,
                remote_dns: None,
                label,
                fingerprint_sha256: sha256_hex(b"egress-route/v1|direct"),
            },
            Self::ExplicitProxy(endpoint) => {
                let fingerprint_input = format!(
                    "egress-route/v1|explicit_proxy|{}|{}|{}|remote_dns={}",
                    endpoint.scheme.evidence_name(),
                    endpoint.host,
                    endpoint.port,
                    endpoint.remote_dns
                );
                RouteProvenance {
                    mode: "explicit_proxy".to_owned(),
                    kind: endpoint.scheme.evidence_name().to_owned(),
                    host: Some(endpoint.host.clone()),
                    port: Some(endpoint.port),
                    remote_dns: Some(endpoint.remote_dns),
                    label,
                    fingerprint_sha256: sha256_hex(fingerprint_input.as_bytes()),
                }
            }
        }
    }
}

/// Build an HTTP client bound to the configured egress route, reading the
/// process environment. See [`http_client_with`].
///
/// # Errors
///
/// Returns an error, never a direct client, when the configured route is
/// invalid or cannot be turned into a proxy configuration.
pub fn http_client(
    user_agent: &str,
    timeout: std::time::Duration,
    network: &NetworkSettings,
    intent: Option<&EgressIntent>,
) -> anyhow::Result<reqwest::Client> {
    http_client_with(user_agent, timeout, network, intent, |name| {
        std::env::var(name).ok()
    })
}

/// Build an HTTP client bound to the configured egress route with an
/// injected environment lookup.
///
/// Direct mode builds a deterministic client: proxy environment variables
/// inherited from the shell are blocked (`no_proxy`), and no route is added.
/// Explicit proxy mode blocks the shell variables too, then attaches exactly
/// one configured proxy. Failure never falls back to direct networking.
/// Automatic redirects are disabled: a redirect target is a new authority and
/// is never followed unless the caller installs a reauthorizing policy with
/// [`http_client_with_authorized_redirects`].
///
/// # Errors
///
/// Same contract as [`http_client`].
pub fn http_client_with(
    user_agent: &str,
    timeout: std::time::Duration,
    network: &NetworkSettings,
    intent: Option<&EgressIntent>,
    lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<reqwest::Client> {
    build_http_client(
        user_agent,
        timeout,
        network,
        intent,
        reqwest::redirect::Policy::none(),
        lookup,
    )
}

/// Build a client that follows redirects only after each target has been
/// reauthorized against the supplied gate. A different authority, an
/// unparseable URL, an expired proof or a failed gate stops the redirect.
///
/// # Errors
/// Same contract as [`http_client_with`].
pub fn http_client_with_authorized_redirects(
    user_agent: &str,
    timeout: std::time::Duration,
    network: &NetworkSettings,
    intent: &EgressIntent,
    gate: &AuthorizationGate,
    lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<reqwest::Client> {
    let redirect_intent = intent.clone();
    let redirect_gate = gate.clone();
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.stop();
        }
        let Ok(at_us) = crate::time::now_us() else {
            return attempt.stop();
        };
        if !authorize_redirect_on(
            &redirect_intent,
            attempt.url().as_str(),
            &redirect_gate,
            at_us,
        ) {
            return attempt.stop();
        }
        attempt.follow()
    });
    build_http_client(user_agent, timeout, network, Some(intent), policy, lookup)
}

/// Build a client only after the actual HTTP request has been authorized.
/// The binding supplies provider, source product, operation and full scope
/// through its intent, plus the actual URL, method and approved resource class.
///
/// # Errors
/// Returns the fail-closed denial before any client or socket exists.
pub fn http_client_with_request(
    user_agent: &str,
    timeout: std::time::Duration,
    network: &NetworkSettings,
    binding: &HttpEgressRequest<'_>,
    lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<reqwest::Client> {
    authorize_http_request(binding)?;
    http_client_with(user_agent, timeout, network, Some(binding.intent), lookup)
}

fn build_http_client(
    user_agent: &str,
    timeout: std::time::Duration,
    network: &NetworkSettings,
    intent: Option<&EgressIntent>,
    redirect_policy: reqwest::redirect::Policy,
    lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<reqwest::Client> {
    // Fail closed before a client exists: no provider HTTP client is built
    // without a live authorization covering the caller's full intent. The
    // request is supplied by the caller; it is never rebuilt from a proof.
    let declared = match intent {
        Some(intent) => intent.clone(),
        None if network.venue.eq_ignore_ascii_case("loopback") => EgressIntent::loopback_test(),
        None => anyhow::bail!(
            "provider HTTP egress requires an explicit EgressIntent for venue `{}`",
            network.venue
        ),
    };
    anyhow::ensure!(
        declared.venue_id == network.venue,
        "egress intent venue `{}` does not match transport venue `{}`",
        declared.venue_id,
        network.venue
    );
    require_provider_egress(&declared)?;
    let route = EgressRoute::from_network_with(network, lookup)?;
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent.to_owned())
        .timeout(timeout)
        .redirect(redirect_policy)
        .no_proxy();
    if let EgressRoute::ExplicitProxy(endpoint) = &route {
        let proxy = proxy_url(endpoint)?;
        let http_proxy = reqwest::Proxy::all(&proxy)
            .map_err(|_| anyhow::anyhow!("building HTTP client proxy configuration"))?;
        builder = builder.proxy(http_proxy);
    }
    builder.build().context("building HTTP client")
}

/// Reauthorize one redirect destination against a specific gate.
///
/// The derived request keeps every caller-declared dimension and replaces only
/// the endpoint with the redirect target. Any mismatch, unparseable URL or
/// denial stops the redirect; no authority is followed unchecked.
#[must_use]
pub fn authorize_redirect_on(
    intent: &EgressIntent,
    url: &str,
    gate: &AuthorizationGate,
    at_us: i64,
) -> bool {
    let Ok(next) = intent.for_endpoint(url) else {
        return false;
    };
    // A redirect that changes the venue is a different authorization, not a
    // narrower form of the current one.
    if next.venue_id != intent.venue_id {
        return false;
    }
    gate.require_egress(&next, at_us).is_ok()
}

/// Render the proxy URL handed to the HTTP client crate. The value carries
/// credentials and must never be logged or reported.
fn proxy_url(endpoint: &ProxyEndpoint) -> anyhow::Result<String> {
    let scheme = match endpoint.scheme {
        ProxyScheme::HttpConnect => "http",
        ProxyScheme::Socks5 => {
            if endpoint.remote_dns {
                "socks5h"
            } else {
                "socks5"
            }
        }
    };
    let mut url = Url::parse(&format!("{scheme}://{}:{}/", endpoint.host, endpoint.port))
        .context("assembling proxy URL")?;
    if let Some((username, password)) = endpoint.authentication() {
        // `url` percent-encodes userinfo; the string is only consumed by the
        // HTTP client and is never printed.
        url.set_username(username).map_err(|_| {
            anyhow::anyhow!("proxy username is not usable in a URL userinfo component")
        })?;
        url.set_password(Some(password)).map_err(|_| {
            anyhow::anyhow!("proxy password is not usable in a URL userinfo component")
        })?;
    }
    Ok(url.into())
}

/// `Url::host_str` keeps brackets on IPv6 literals; `lookup_host` and the
/// SOCKS5 target address expect the bare address.
pub(crate) fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn network_with(overrides: impl FnOnce(&mut NetworkSettings)) -> NetworkSettings {
        let mut network = NetworkSettings::default();
        overrides(&mut network);
        network
    }

    /// Build a lookup from a fixed set of variables. Names not listed are
    /// reported as unset; empty strings are preserved so the empty-value
    /// path is exercised the same way as a set-but-empty variable.
    fn lookup<const N: usize>(pairs: [(&str, &str); N]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<&str, &str> = pairs.into_iter().collect();
        move |name| map.get(name).map(|value| (*value).to_owned())
    }

    #[test]
    fn direct_mode_never_reads_the_proxy_environment() {
        let network = network_with(|network| {
            network.egress_mode = "direct".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_IRRELEVANT_PROXY".to_owned();
        });
        let route = EgressRoute::from_network_with(
            &network,
            lookup([("MARKETDATA_TEST_IRRELEVANT_PROXY", "not a url")]),
        )
        .unwrap();
        assert!(matches!(route, EgressRoute::Direct));
        let provenance = route.provenance(&network);
        assert_eq!(provenance.mode, "direct");
        assert_eq!(provenance.kind, "direct");
        assert!(provenance.host.is_none());
        assert!(provenance.port.is_none());
    }

    #[test]
    fn explicit_proxy_requires_a_set_proxy_url() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_MISSING_PROXY".to_owned();
        });
        let error = EgressRoute::from_network_with(&network, lookup([])).unwrap_err();
        assert!(error.to_string().contains("MARKETDATA_TEST_MISSING_PROXY"));
    }

    #[test]
    fn unsupported_schemes_are_rejected() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_PROXY".to_owned();
            network.proxy_remote_dns = false;
        });
        let error = EgressRoute::from_network_with(
            &network,
            lookup([("MARKETDATA_TEST_PROXY", "ftp://proxy.internal:2121")]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unsupported proxy scheme"));
    }

    #[test]
    fn https_proxy_scheme_is_rejected_without_a_partial_handshake() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_PROXY_HTTPS".to_owned();
        });
        let error = EgressRoute::from_network_with(
            &network,
            lookup([("MARKETDATA_TEST_PROXY_HTTPS", "https://proxy.internal:8443")]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not supported"));
    }

    #[test]
    fn socks5h_forces_remote_dns() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_PROXY_SOCKS".to_owned();
            network.proxy_remote_dns = false;
        });
        let route = EgressRoute::from_network_with(
            &network,
            lookup([(
                "MARKETDATA_TEST_PROXY_SOCKS",
                "socks5h://proxy.internal:1080",
            )]),
        )
        .unwrap();
        let EgressRoute::ExplicitProxy(endpoint) = route else {
            panic!("expected explicit proxy route");
        };
        assert!(endpoint.remote_dns);
    }

    #[test]
    fn split_credential_pair_requires_both_values() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_PROXY_SPLIT_URL".to_owned();
            network.proxy_auth_user_env = "MARKETDATA_TEST_PROXY_SPLIT_USER".to_owned();
            network.proxy_auth_password_env = "MARKETDATA_TEST_PROXY_SPLIT_PASS".to_owned();
            network.proxy_remote_dns = false;
        });
        let error = EgressRoute::from_network_with(
            &network,
            lookup([
                (
                    "MARKETDATA_TEST_PROXY_SPLIT_URL",
                    "http://proxy.internal:8080",
                ),
                ("MARKETDATA_TEST_PROXY_SPLIT_USER", "operator"),
            ]),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("MARKETDATA_TEST_PROXY_SPLIT_USER")
        );
    }

    #[test]
    fn provenance_never_contains_credentials() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_PROXY_SECRET".to_owned();
            network.proxy_remote_dns = false;
            network.proxy_label = Some("approved-egress-a".to_owned());
        });
        let route = EgressRoute::from_network_with(
            &network,
            lookup([(
                "MARKETDATA_TEST_PROXY_SECRET",
                "http://operator:correct-horse-battery@proxy.internal:8080",
            )]),
        )
        .unwrap();
        let serialized = serde_json::to_string(&route.provenance(&network)).unwrap();
        assert!(!serialized.contains("correct-horse-battery"));
        assert!(!serialized.contains("operator"));
        assert!(serialized.contains("approved-egress-a"));
        assert!(serialized.contains("proxy.internal"));
        let debugged = format!("{route:?}");
        assert!(!debugged.contains("correct-horse-battery"));
        assert!(debugged.contains("authenticated: true"));
    }

    #[test]
    fn proxy_url_renders_userinfo_without_leaking() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_PROXY_URL".to_owned();
            network.proxy_remote_dns = true;
        });
        let route = EgressRoute::from_network_with(
            &network,
            lookup([(
                "MARKETDATA_TEST_PROXY_URL",
                "socks5h://operator:p%40ss@proxy.internal:1080",
            )]),
        )
        .unwrap();
        let EgressRoute::ExplicitProxy(endpoint) = &route else {
            panic!("expected explicit proxy route");
        };
        let rendered = proxy_url(endpoint).unwrap();
        assert!(rendered.starts_with("socks5h://"));
        assert!(rendered.contains("proxy.internal:1080"));
    }

    #[test]
    fn missing_proxy_port_uses_the_scheme_default() {
        let network = network_with(|network| {
            network.egress_mode = "explicit_proxy".to_owned();
            network.proxy_url_env = "MARKETDATA_TEST_PROXY_PORT".to_owned();
        });
        let route = EgressRoute::from_network_with(
            &network,
            lookup([("MARKETDATA_TEST_PROXY_PORT", "socks5://proxy.internal")]),
        )
        .unwrap();
        let EgressRoute::ExplicitProxy(endpoint) = route else {
            panic!("expected explicit proxy route");
        };
        assert_eq!(endpoint.port, 1080);
    }
}
