//! Visual screenshot digest, Service Worker lifecycle, and extended TLS/CAA diagnostics (Wave IV-H).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::functional_intelligence::ElementBoundingBox;

/// Visual landmark region bounding box and viewport intersection summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VisualRegionLandmarkObs {
    /// Semantic landmark role or tag (`header`, `nav`, `main`, `footer`, `dialog`, `hero`).
    pub landmark_role: String,
    /// Rendered bounding box in CSS pixels.
    pub bbox: ElementBoundingBox,
    /// Percentage of the initial viewport area covered by this landmark in thousandths (`1000` = `100%`).
    pub viewport_coverage_milli: u32,
    /// Whether this landmark is visible above the fold.
    pub above_the_fold: bool,
}

/// Visual artifact evidence including a deterministic SHA-256 viewport screenshot digest.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct VisualArtifactEvidence {
    /// Lowercase hex SHA-256 digest of the captured viewport PNG screenshot bytes, if captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewport_screenshot_sha256: Option<String>,
    /// Byte length of the captured viewport PNG screenshot; `None` when no screenshot was captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot_byte_len: Option<u64>,
    /// Viewport width in CSS pixels at screenshot capture, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewport_width: Option<u32>,
    /// Viewport height in CSS pixels at screenshot capture, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewport_height: Option<u32>,
    /// Estimated coverage of the above-the-fold viewport by retained eligible element
    /// rectangles, in thousandths (`0..=1000`).
    ///
    /// This is a geometric estimate from a fixed sample grid over the bounding boxes of
    /// selected element families. It is not pixel-derived visual coverage, painted area,
    /// text occupancy or content density, and `None` means no eligible rectangle was
    /// retained or the viewport could not be measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub above_fold_retained_element_coverage_milli: Option<u32>,
    /// Number of columns in the sampling grid used for the coverage estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_grid_columns: Option<u32>,
    /// Number of rows in the sampling grid used for the coverage estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_grid_rows: Option<u32>,
    /// Number of element rectangles retained for the coverage estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_retained_element_count: Option<u32>,
    /// Maximum number of element rectangles the collector retains for the estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_retained_element_limit: Option<u32>,
    /// Whether additional eligible rectangles were discarded by the retention limit.
    #[serde(default)]
    pub coverage_elements_truncated: bool,
    /// Bounded list of primary visual landmark boxes (capped at 16).
    pub landmarks: Vec<VisualRegionLandmarkObs>,
}

/// Service Worker registration and activation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceWorkerRegistrationState {
    /// No Service Worker registration exists for this scope.
    #[default]
    None,
    /// A Service Worker is installing.
    Installing,
    /// A Service Worker is installed and waiting to activate.
    Waiting,
    /// A Service Worker is activating.
    Activating,
    /// An active Service Worker is registered for this scope.
    Activated,
    /// Service Worker inspection failed or was blocked by browser policy.
    Unavailable,
}

/// Service Worker, Cache Storage, and Web App Manifest lifecycle evidence.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ServiceWorkerLifecycleEvidence {
    /// Effective Service Worker registration state.
    pub registration_state: ServiceWorkerRegistrationState,
    /// Whether `navigator.serviceWorker.controller` actively controls the current page.
    pub page_controlled: bool,
    /// Secret-safe pathname of the registered Service Worker script, if registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_path: Option<String>,
    /// Secret-safe scope pathname of the Service Worker registration, if registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_path: Option<String>,
    /// Number of Cache Storage (`window.caches.keys()`) buckets discovered.
    pub cache_storage_bucket_count: u32,
    /// Sanitized names of discovered Cache Storage buckets (capped at 16).
    pub cache_bucket_names: Vec<String>,
    /// Number of network requests during page load served by a Service Worker.
    pub sw_served_request_count: u32,
    /// Number of network requests served from disk or prefetch cache.
    pub disk_or_prefetch_cache_request_count: u32,
    /// Whether a `<link rel="manifest">` Web App Manifest is declared in `<head>`.
    pub manifest_link_present: bool,
}

/// Certificate Transparency (CT) compliance status observed by Chromium or x509 inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateTransparencyStatus {
    /// Certificate satisfies Certificate Transparency policy.
    Compliant,
    /// Certificate does not satisfy CT policy.
    NotCompliant,
    /// CT compliance was not evaluated or is unknown.
    #[default]
    Unknown,
}

/// Extended X.509 leaf certificate and CT diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct TlsLeafCertificateDiagnostics {
    /// Total Subject Alternative Name (SAN) DNS entries on the leaf certificate.
    pub san_count: u32,
    /// Bounded sample of SAN DNS entries (capped at 32).
    pub san_entries: Vec<String>,
    /// Certificate `NotBefore` timestamp as Unix epoch seconds, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_unix_secs: Option<i64>,
    /// Certificate `NotAfter` timestamp as Unix epoch seconds.
    pub not_after_unix_secs: i64,
    /// Public key algorithm OID or name (`id-ecPublicKey`, `rsaEncryption`, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<String>,
    /// Signature algorithm OID or name (`ecdsa-with-SHA256`, `sha256WithRSAEncryption`, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    /// Whether the certificate is self-signed (`subject == issuer`).
    pub self_signed: bool,
    /// Certificate Transparency compliance status from browser security state.
    pub certificate_transparency_status: CertificateTransparencyStatus,
    /// Number of Signed Certificate Timestamps (SCTs) observed by the browser.
    pub signed_certificate_timestamp_count: u32,
}

/// Combined TLS leaf certificate, browser security state, and DNS CAA diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct TlsAndCaaDiagnostics {
    /// Negotiated TLS protocol version (`TLS 1.3`, `TLS 1.2`), if reported by browser/transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// Negotiated cipher suite name, if reported by browser/transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// Browser security state (`secure`, `neutral`, `insecure`, `insecure-broken`), if captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_security_state: Option<String>,
    /// Extended leaf certificate diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_certificate: Option<TlsLeafCertificateDiagnostics>,
    /// DNS CAA records discovered for the target host/domain (e.g. `0 issue "letsencrypt.org"`).
    pub caa_records: Vec<String>,
    /// Whether DNS CAA lookup was attempted and succeeded.
    pub caa_query_succeeded: bool,
    /// Explicit outcome of the DNS CAA lookup, including failure and policy states.
    #[serde(default)]
    pub caa_lookup_outcome: crate::domain::CaaLookupOutcome,
}
