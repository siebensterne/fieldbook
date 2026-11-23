// SPDX-License-Identifier: Apache-2.0
//! Caller-supplied egress intent and active authorization lifecycle types.
//!
//! An [`EgressIntent`] is the *actual request* a caller wants to perform. It is
//! supplied by the caller; the authorization gate never derives one from an
//! installed proof. Every field is explicit and there is no wildcard default.
//!
//! The lifecycle types in this module implement the proposed model in
//! `NDC-SEMANTIC-MODEL-V2-PROPOSED.md` section 2.5: a rights-registry revision,
//! an immutable grant snapshot identity, a short-lived lease with a declared
//! maximum duration, an active session id, reauthorization checkpoints and
//! fail-closed refresh. Revocation is **not** instantaneous: the maximum
//! propagation time is the lease duration, because that is how long a previously
//! granted session can continue before it must refresh its authority.

use std::{
    collections::BTreeSet,
    fmt,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use anyhow::Context as _;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

use crate::{
    config::Settings,
    rights::{
        Actor, AuthorizationScope, DataObject, DeliveryMethod, Licensee, Modality, ObjectKind,
        Operation, Purpose, RecipientClass, RecipientIdentity, Retention, RightsError, ScopeSet,
        TimeWindow, UsageMode, UsageRight,
    },
    taxonomy::CountryCode,
    time::now_us,
};

/// Declared ceiling on any single authorization lease.
///
/// A request may declare a shorter lease; a longer one is rejected when the
/// grant snapshot is issued. Revocation propagation is bounded by this value
/// (15 minutes) unless a faster, tested notification channel exists. There is
/// no instantaneous-revocation claim in this module.
pub const MAX_LEASE_DURATION: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Maximum number of HTTP redirect hops followed under one intent before the
/// caller must submit a fresh intent.
pub const MAX_REDIRECTS: usize = 3;

/// The concrete network authority a request will contact.
///
/// Scheme, host and port are recorded separately so a redirect from one
/// authority to another is a different value and must be reauthorized. An IPv6
/// literal is carried without brackets; [`Self::authority`] restores them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointIdentity {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl EndpointIdentity {
    /// Parse an endpoint from a URL. A URL without a known port is rejected;
    /// no port is inferred from the scheme by this constructor.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidEndpoint`] for a URL that has no host or
    /// no explicit or well-known port.
    pub fn from_url(url: &str) -> Result<Self, RightsError> {
        let parsed = Url::parse(url).map_err(|_| RightsError::InvalidEndpoint)?;
        let host = parsed
            .host_str()
            .ok_or(RightsError::InvalidEndpoint)?
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or_else(|| parsed.host_str().unwrap_or_default())
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or(RightsError::InvalidEndpoint)?;
        Ok(Self {
            scheme: parsed.scheme().to_ascii_lowercase(),
            host,
            port,
        })
    }

    /// Render the host and port as a URI authority, restoring IPv6 brackets.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Whether the endpoint is a loopback test endpoint.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    }
}

/// The full, caller-supplied request evaluated by the authorization gate.
///
/// Every field must be supplied by the caller. In particular `endpoint_identity`
/// is the endpoint that will be contacted; the gate compares it with
/// the approved endpoint set in the matching grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressIntent {
    pub provider_id: String,
    /// Source record identity, distinct from the provider and the product.
    pub source_id: String,
    pub source_product_id: String,
    pub venue_id: String,
    pub segment_id: String,
    pub dataset_id: String,
    /// Exact actor whose request is evaluated.
    pub actor: Actor,
    pub operation: Operation,
    /// Exact object kind, identity and version the action acts upon.
    pub data_object: DataObject,
    pub purpose: Purpose,
    pub usage_mode: UsageMode,
    pub usage_right: UsageRight,
    pub licensee: Licensee,
    pub recipient_class: RecipientClass,
    pub recipient_identity: RecipientIdentity,
    pub territory: CountryCode,
    pub instruments: ScopeSet<String>,
    pub fields: ScopeSet<String>,
    pub modalities: ScopeSet<Modality>,
    pub data_time_window: TimeWindow,
    pub retention_request: Retention,
    pub delivery_method: DeliveryMethod,
    pub endpoint_identity: EndpointIdentity,
}

impl EgressIntent {
    /// Start an empty intent. No field has a default and no value is inferred.
    #[must_use]
    pub fn builder() -> EgressIntentBuilder {
        EgressIntentBuilder::default()
    }

    /// Load a declared intent from a versioned TOML file.
    ///
    /// # Errors
    /// Returns an error for a missing, malformed or wrong-version file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!("reading egress intent `{}`: {error}", path.display())
        })?;
        let file: EgressIntentFile = toml::from_str(&text).map_err(|error| {
            anyhow::anyhow!("parsing egress intent `{}`: {error}", path.display())
        })?;
        if file.schema_version != 1 {
            anyhow::bail!(
                "unsupported egress intent schema version {}",
                file.schema_version
            );
        }
        file.intent.validate()?;
        Ok(file.intent)
    }

    /// Validate the declared fields without consulting any grant.
    ///
    /// # Errors
    /// Returns the first fail-closed validation error.
    pub fn validate(&self) -> Result<(), RightsError> {
        let scope = self.to_scope();
        scope.validate()?;
        if self.endpoint_identity.host.trim().is_empty() || self.endpoint_identity.scheme.is_empty()
        {
            return Err(RightsError::InvalidEndpoint);
        }
        Ok(())
    }

    /// Build the authorization scope used for the full request-versus-grant
    /// comparison. The approved-endpoint set is empty here: it is
    /// a grant-only field and is compared separately by the gate.
    #[must_use]
    pub fn to_scope(&self) -> AuthorizationScope {
        AuthorizationScope {
            actor: self.actor,
            licensee: self.licensee.clone(),
            venue: self.venue_id.clone(),
            provider_id: self.provider_id.clone(),
            source_id: self.source_id.clone(),
            dataset_id: self.dataset_id.clone(),
            product_id: self.source_product_id.clone(),
            segment: self.segment_id.clone(),
            territory: self.territory.clone(),
            operation: self.operation,
            data_object: self.data_object.clone(),
            usage_right: self.usage_right,
            usage_mode: self.usage_mode,
            recipient_class: self.recipient_class,
            recipient_identity: self.recipient_identity.clone(),
            purpose: self.purpose,
            delivery_method: self.delivery_method,
            retention: self.retention_request,
            instruments: self.instruments.clone(),
            fields: self.fields.clone(),
            modalities: self.modalities.clone(),
            data_time_window: self.data_time_window,
            approved_endpoints: Vec::new(),
        }
    }

    /// Explicit test-only request for a loopback transport.
    ///
    /// This identity is accepted only by the loopback transport exception in
    /// `require_provider_egress`; it cannot name any provider venue and grants
    /// no right. It exists so offline transport tests can declare a request
    /// without a rights file.
    #[must_use]
    pub fn loopback_test() -> Self {
        Self {
            provider_id: "loopback".to_owned(),
            source_id: "loopback".to_owned(),
            source_product_id: "loopback".to_owned(),
            venue_id: "loopback".to_owned(),
            segment_id: "loopback-test".to_owned(),
            dataset_id: "loopback-test".to_owned(),
            actor: Actor::FieldbookProducer,
            operation: Operation::SourceContact,
            data_object: DataObject::from_declared(
                ObjectKind::RawSourceRecord,
                "loopback-object".to_owned(),
                "loopback-v1".to_owned(),
            ),
            purpose: Purpose::InternalAnalysis,
            usage_mode: UsageMode::NonDisplay,
            usage_right: UsageRight::RealTimeAccess,
            licensee: Licensee::system(),
            recipient_class: RecipientClass::Internal,
            recipient_identity: RecipientIdentity::from_declared("loopback-recipient".to_owned()),
            territory: CountryCode::new("ZZ").unwrap_or_default(),
            instruments: ScopeSet::NotApplicable,
            fields: ScopeSet::NotApplicable,
            modalities: ScopeSet::NotApplicable,
            data_time_window: TimeWindow::default(),
            retention_request: Retention::NONE,
            delivery_method: DeliveryMethod::Query,
            endpoint_identity: EndpointIdentity {
                scheme: "ws".to_owned(),
                host: "127.0.0.1".to_owned(),
                port: 1,
            },
        }
    }

    /// Derive the request for a redirect destination. The caller's declared
    /// scope is unchanged; only the endpoint is replaced, so the gate must
    /// reauthorize the new authority before it is contacted.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidEndpoint`] for an unparseable URL.
    pub fn for_endpoint(&self, url: &str) -> Result<Self, RightsError> {
        let mut next = self.clone();
        next.endpoint_identity = EndpointIdentity::from_url(url)?;
        Ok(next)
    }

    /// Derive a source-contact request from the declared intent for a probe.
    /// No data scope or retention is implied by contacting a source.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidEndpoint`] for an unparseable URL.
    pub fn for_source_contact(&self, url: &str) -> Result<Self, RightsError> {
        let mut next = self.for_endpoint(url)?;
        next.operation = Operation::SourceContact;
        next.instruments = ScopeSet::NotApplicable;
        next.fields = ScopeSet::NotApplicable;
        next.modalities = ScopeSet::NotApplicable;
        next.data_time_window = TimeWindow::default();
        next.retention_request = Retention::NONE;
        Ok(next)
    }

    /// Derive a request with a widened modality scope. Used by session
    /// reauthorization checkpoints when a subscription widens.
    #[must_use]
    pub fn with_modalities(&self, modalities: ScopeSet<Modality>) -> Self {
        let mut next = self.clone();
        next.modalities = modalities;
        next
    }
}

/// Versioned file wrapper for a declared [`EgressIntent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressIntentFile {
    pub schema_version: u32,
    pub intent: EgressIntent,
}

/// Explicit builder for [`EgressIntent`]. No value is inferred from a command
/// name, an environment variable, settings or an installed proof.
#[derive(Debug, Default)]
pub struct EgressIntentBuilder {
    provider_id: Option<String>,
    source_id: Option<String>,
    source_product_id: Option<String>,
    venue_id: Option<String>,
    segment_id: Option<String>,
    dataset_id: Option<String>,
    actor: Option<Actor>,
    operation: Option<Operation>,
    data_object: Option<DataObject>,
    purpose: Option<Purpose>,
    usage_mode: Option<UsageMode>,
    usage_right: Option<UsageRight>,
    licensee: Option<Licensee>,
    recipient_class: Option<RecipientClass>,
    recipient_identity: Option<RecipientIdentity>,
    territory: Option<CountryCode>,
    instruments: Option<ScopeSet<String>>,
    fields: Option<ScopeSet<String>>,
    modalities: Option<ScopeSet<Modality>>,
    data_time_window: Option<TimeWindow>,
    retention_request: Option<Retention>,
    delivery_method: Option<DeliveryMethod>,
    endpoint_identity: Option<EndpointIdentity>,
}

impl EgressIntentBuilder {
    /// Set the exact provider identity.
    #[must_use]
    pub fn provider_id(mut self, value: impl Into<String>) -> Self {
        self.provider_id = Some(value.into());
        self
    }

    /// Set the exact source record identity.
    #[must_use]
    pub fn source_id(mut self, value: impl Into<String>) -> Self {
        self.source_id = Some(value.into());
        self
    }

    /// Set the exact source-product identity.
    #[must_use]
    pub fn source_product_id(mut self, value: impl Into<String>) -> Self {
        self.source_product_id = Some(value.into());
        self
    }

    /// Set the exact venue identity.
    #[must_use]
    pub fn venue_id(mut self, value: impl Into<String>) -> Self {
        self.venue_id = Some(value.into());
        self
    }

    /// Set the exact venue market segment.
    #[must_use]
    pub fn segment_id(mut self, value: impl Into<String>) -> Self {
        self.segment_id = Some(value.into());
        self
    }

    /// Set the exact dataset identity.
    #[must_use]
    pub fn dataset_id(mut self, value: impl Into<String>) -> Self {
        self.dataset_id = Some(value.into());
        self
    }

    /// Set the exact declared actor.
    #[must_use]
    pub fn actor(mut self, value: Actor) -> Self {
        self.actor = Some(value);
        self
    }

    /// Set the exact typed operation. No second producer enum exists.
    #[must_use]
    pub fn operation(mut self, value: Operation) -> Self {
        self.operation = Some(value);
        self
    }

    /// Set the exact typed object: kind, identity and version.
    #[must_use]
    pub fn data_object(mut self, value: DataObject) -> Self {
        self.data_object = Some(value);
        self
    }

    /// Set the exact reviewed purpose.
    #[must_use]
    pub fn purpose(mut self, value: Purpose) -> Self {
        self.purpose = Some(value);
        self
    }

    /// Set the exact usage mode.
    #[must_use]
    pub fn usage_mode(mut self, value: UsageMode) -> Self {
        self.usage_mode = Some(value);
        self
    }

    /// Set the exact usage right.
    #[must_use]
    pub fn usage_right(mut self, value: UsageRight) -> Self {
        self.usage_right = Some(value);
        self
    }

    /// Set the exact named licensee.
    #[must_use]
    pub fn licensee(mut self, value: Licensee) -> Self {
        self.licensee = Some(value);
        self
    }

    /// Set the exact recipient class. `Internal` is a class, not an identity.
    #[must_use]
    pub fn recipient_class(mut self, value: RecipientClass) -> Self {
        self.recipient_class = Some(value);
        self
    }

    /// Set the exact named recipient identity.
    #[must_use]
    pub fn recipient_identity(mut self, value: RecipientIdentity) -> Self {
        self.recipient_identity = Some(value);
        self
    }

    /// Set the exact territory.
    #[must_use]
    pub fn territory(mut self, value: CountryCode) -> Self {
        self.territory = Some(value);
        self
    }

    /// Set the exact instrument scope.
    #[must_use]
    pub fn instruments(mut self, value: ScopeSet<String>) -> Self {
        self.instruments = Some(value);
        self
    }

    /// Set the exact field scope.
    #[must_use]
    pub fn fields(mut self, value: ScopeSet<String>) -> Self {
        self.fields = Some(value);
        self
    }

    /// Set the exact modality scope.
    #[must_use]
    pub fn modalities(mut self, value: ScopeSet<Modality>) -> Self {
        self.modalities = Some(value);
        self
    }

    /// Set the exact data-time window.
    #[must_use]
    pub fn data_time_window(mut self, value: TimeWindow) -> Self {
        self.data_time_window = Some(value);
        self
    }

    /// Set the exact retention request.
    #[must_use]
    pub fn retention_request(mut self, value: Retention) -> Self {
        self.retention_request = Some(value);
        self
    }

    /// Set the exact delivery method.
    #[must_use]
    pub fn delivery_method(mut self, value: DeliveryMethod) -> Self {
        self.delivery_method = Some(value);
        self
    }

    /// Set the actual endpoint from a URL.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidEndpoint`] when the URL has no endpoint.
    pub fn endpoint(mut self, url: &str) -> Result<Self, RightsError> {
        self.endpoint_identity = Some(EndpointIdentity::from_url(url)?);
        Ok(self)
    }

    /// Set an already parsed endpoint identity.
    #[must_use]
    pub fn endpoint_identity(mut self, value: EndpointIdentity) -> Self {
        self.endpoint_identity = Some(value);
        self
    }

    /// Finish the intent, failing closed on the first missing value.
    ///
    /// # Errors
    /// Returns [`RightsError::MissingField`] for an absent required value.
    pub fn build(self) -> Result<EgressIntent, RightsError> {
        macro_rules! required {
            ($field:literal, $value:expr) => {
                $value.ok_or(RightsError::MissingField { field: $field })?
            };
        }
        let intent = EgressIntent {
            provider_id: required!("provider_id", self.provider_id),
            source_id: required!("source_id", self.source_id),
            source_product_id: required!("source_product_id", self.source_product_id),
            venue_id: required!("venue_id", self.venue_id),
            segment_id: required!("segment_id", self.segment_id),
            dataset_id: required!("dataset_id", self.dataset_id),
            actor: required!("actor", self.actor),
            operation: required!("operation", self.operation),
            data_object: required!("data_object", self.data_object),
            purpose: required!("purpose", self.purpose),
            usage_mode: required!("usage_mode", self.usage_mode),
            usage_right: required!("usage_right", self.usage_right),
            licensee: required!("licensee", self.licensee),
            recipient_class: required!("recipient_class", self.recipient_class),
            recipient_identity: required!("recipient_identity", self.recipient_identity),
            territory: required!("territory", self.territory),
            instruments: required!("instruments", self.instruments),
            fields: required!("fields", self.fields),
            modalities: required!("modalities", self.modalities),
            data_time_window: required!("data_time_window", self.data_time_window),
            retention_request: required!("retention_request", self.retention_request),
            delivery_method: required!("delivery_method", self.delivery_method),
            endpoint_identity: required!("endpoint_identity", self.endpoint_identity),
        };
        intent.validate()?;
        Ok(intent)
    }
}

/// Immutable identity of the grant snapshot a session was authorized against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSnapshot {
    pub registry_revision: u64,
    pub snapshot_id: String,
    pub lease_duration_us: u64,
    pub issued_at_us: i64,
}

impl GrantSnapshot {
    /// Build a snapshot, rejecting a lease longer than the declared maximum.
    ///
    /// # Errors
    /// Returns [`RightsError::LeaseTooLong`] when `lease_duration_us` exceeds
    /// [`MAX_LEASE_DURATION`] or is zero.
    pub fn new(
        registry_revision: u64,
        snapshot_id: String,
        lease_duration_us: u64,
        issued_at_us: i64,
    ) -> Result<Self, RightsError> {
        let ceiling = MAX_LEASE_DURATION.as_micros() as u64;
        if lease_duration_us == 0 || lease_duration_us > ceiling {
            return Err(RightsError::LeaseTooLong);
        }
        Ok(Self {
            registry_revision,
            snapshot_id,
            lease_duration_us,
            issued_at_us,
        })
    }

    /// The instant at which this snapshot's lease expires.
    #[must_use]
    pub fn expires_at_us(&self) -> i64 {
        self.issued_at_us
            .saturating_add(i64::try_from(self.lease_duration_us).unwrap_or(i64::MAX))
    }
}

/// A live authorization session bound to one grant snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationSession {
    pub session_id: String,
    pub snapshot: GrantSnapshot,
    pub expires_at_us: i64,
    pub renewals: u64,
}

/// The authority state observed at a reauthorization checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorityState {
    pub revision: u64,
    pub valid_snapshots: BTreeSet<String>,
}

/// Refreshable authority used by the gate at each checkpoint.
///
/// A refresh error denies egress: an authority that cannot be consulted is not
/// an authority that granted anything.
pub trait AuthorityRefresh: fmt::Debug + Send + Sync {
    /// Return the current registry revision and valid snapshot identities.
    ///
    /// # Errors
    /// Returns an error when the authority cannot be consulted; the gate fails
    /// closed on every error.
    fn refresh(&self) -> anyhow::Result<AuthorityState>;
}

/// In-process authority used by production and by deterministic tests.
#[derive(Debug)]
pub struct InMemoryAuthority {
    state: Mutex<AuthorityState>,
    failing: Mutex<bool>,
}

impl InMemoryAuthority {
    /// Create an authority holding one valid snapshot at `revision`.
    #[must_use]
    pub fn new(revision: u64, snapshot_id: impl Into<String>) -> Self {
        Self {
            state: Mutex::new(AuthorityState {
                revision,
                valid_snapshots: BTreeSet::from([snapshot_id.into()]),
            }),
            failing: Mutex::new(false),
        }
    }

    fn state(&self) -> MutexGuard<'_, AuthorityState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record a new registry revision, invalidating every previous snapshot.
    pub fn advance_revision(&self, revision: u64, valid: impl IntoIterator<Item = String>) {
        let mut state = self.state();
        state.revision = revision;
        state.valid_snapshots = valid.into_iter().collect();
    }

    /// Revoke one grant snapshot without changing the revision.
    pub fn revoke(&self, snapshot_id: &str) {
        self.state().valid_snapshots.remove(snapshot_id);
    }

    /// Make every subsequent refresh fail, modelling an unreachable authority.
    pub fn set_failing(&self, failing: bool) {
        *self
            .failing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = failing;
    }
}

impl AuthorityRefresh for InMemoryAuthority {
    fn refresh(&self) -> anyhow::Result<AuthorityState> {
        if *self
            .failing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            anyhow::bail!("authority could not be refreshed");
        }
        Ok(self.state().clone())
    }
}

/// Resolve the declared egress intent for a command from runtime settings.
///
/// The intent is a separate, operator-supplied declaration; it is never built
/// from a command name or from an installed proof.
#[must_use]
pub fn declared_intent(settings: &Settings) -> Option<&EgressIntent> {
    settings.governance.declared_intent.as_ref()
}

/// Current wall-clock instant in microseconds, failing closed when unavailable.
///
/// # Errors
/// Returns an error when the system clock cannot be read.
pub fn checkpoint_now() -> anyhow::Result<i64> {
    now_us().context("reading the clock for authorization checkpoint")
}
