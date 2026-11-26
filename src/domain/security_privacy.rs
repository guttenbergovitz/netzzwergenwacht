//! Security, privacy, third-party capability, and anti-bot challenge domain contracts (Wave IV-D).
//!
//! Never stores raw cookie values, session tokens, or storage values—only
//! attribute metadata, value byte lengths, and key names.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Cookie `SameSite` enforcement mode observed via CDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CookieSameSiteMode {
    /// `SameSite=Strict`.
    Strict,
    /// `SameSite=Lax`.
    Lax,
    /// `SameSite=None`.
    None,
    /// Attribute omitted by server (browser default applies).
    Unspecified,
}

/// Sanitized runtime cookie observation from CDP `Network.getCookies`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeCookieObs {
    /// Cookie name (sanitized, max 128 chars). Never the value.
    pub name: String,
    /// Cookie domain attribute.
    pub domain: String,
    /// Cookie path attribute.
    pub path: String,
    /// Whether the `Secure` flag is set.
    pub secure: bool,
    /// Whether the `HttpOnly` flag is set.
    pub http_only: bool,
    /// Effective `SameSite` policy.
    pub same_site: CookieSameSiteMode,
    /// Whether this is a session cookie (no `Expires`/`Max-Age`).
    pub session: bool,
    /// Byte length of the cookie value (raw value is never stored).
    pub value_byte_len: u32,
    /// Whether the cookie domain is third-party relative to the audited page host.
    pub third_party: bool,
    /// Whether the cookie uses `__Host-` or `__Secure-` prefix naming.
    pub has_security_prefix: bool,
    /// Whether the cookie was present before any consent interaction, when a consent
    /// probe actually established the ordering (`None` means unobserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_before_consent: Option<bool>,
}

/// Web Storage (`localStorage` / `sessionStorage`) area selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebStorageArea {
    /// `window.localStorage`.
    LocalStorage,
    /// `window.sessionStorage`.
    SessionStorage,
}

/// Sanitized Web Storage key metadata (key name and value byte length only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StorageKeyObs {
    /// Storage area (`local_storage` or `session_storage`).
    pub area: WebStorageArea,
    /// Key identifier (sanitized, max 128 chars).
    pub key: String,
    /// Approximate byte length of the stored value (raw value is never stored).
    pub value_byte_len: u32,
}

/// Collection bounds for runtime cookie and storage inspection.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct CookieStorageLimits {
    /// Maximum cookie records retained (`128`).
    pub max_cookies: u32,
    /// Whether additional cookies were truncated.
    pub cookies_truncated: bool,
    /// Maximum storage keys retained (`128`).
    pub max_storage_keys: u32,
    /// Whether additional storage keys were truncated.
    pub storage_keys_truncated: bool,
}

/// Complete cookie and Web Storage inventory captured before consent interaction.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct CookieAndStorageInventory {
    /// Sanitized cookies present in the browser context.
    pub cookies: Vec<RuntimeCookieObs>,
    /// Sanitized `localStorage` and `sessionStorage` keys.
    pub storage_keys: Vec<StorageKeyObs>,
    /// Number of `IndexedDB` databases detected (when enumerable).
    pub indexed_db_count: u32,
    /// Sanitized `IndexedDB` database names discovered via `indexedDB.databases()` (up to 16).
    #[serde(default)]
    pub indexed_db_databases: Vec<String>,
    /// Whether asynchronous `indexedDB.databases()` enumeration was attempted and succeeded.
    #[serde(default)]
    pub indexed_db_enumerated: bool,
    /// Collection bounds and truncation flags.
    pub limits: CookieStorageLimits,
}

/// Execution and privilege capabilities granted to a third-party origin.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ThirdPartyCapabilitySummary {
    /// Whether the origin executes JavaScript directly in the top-level document context.
    pub executes_script_in_main_frame: bool,
    /// Number of external `<script>` tags loaded from this origin without `integrity` (SRI).
    pub script_without_sri_count: u32,
    /// Number of external `<script>` tags loaded from this origin with valid `integrity` (SRI).
    pub script_with_sri_count: u32,
    /// Number of `<iframe>` elements hosted from this origin.
    pub iframe_count: u32,
    /// Number of `<iframe>` elements from this origin lacking a `sandbox` attribute.
    pub unsandboxed_iframe_count: u32,
    /// Whether cookies were set or sent for this third-party origin.
    pub sets_or_sends_cookies: bool,
}

/// Aggregated network and privilege footprint for a single third-party origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ThirdPartyOriginObs {
    /// Normalized origin (`scheme://host[:port]`).
    pub origin: String,
    /// Total requests sent to this origin.
    pub total_requests: u32,
    /// Total transfer bytes observed from this origin.
    pub total_transfer_bytes: u64,
    /// Number of script requests (`Script`).
    pub script_requests: u32,
    /// Number of XHR/Fetch/Beacon requests.
    pub xhr_fetch_beacon_requests: u32,
    /// Number of subdocument/iframe requests.
    pub iframe_requests: u32,
    /// Number of failed or blocked requests to this origin.
    pub failed_or_blocked_requests: u32,
    /// Privilege and capability posture granted to this origin.
    pub capability: ThirdPartyCapabilitySummary,
}

/// Complete third-party origin and capability inventory for a page load.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ThirdPartyInventory {
    /// Distinct third-party origins sorted by privilege and request volume (capped at 128).
    pub origins: Vec<ThirdPartyOriginObs>,
    /// Whether additional third-party origins were truncated.
    pub truncated: bool,
}

/// Consolidated HTTP and browser security posture summary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SecurityPostureSummary {
    /// Whether the final document was delivered over HTTPS.
    pub https_final_url: bool,
    /// Whether a `Content-Security-Policy` header or `<meta>` tag is present.
    pub csp_present: bool,
    /// Whether CSP is report-only (`Content-Security-Policy-Report-Only` without enforcing policy).
    pub csp_report_only: bool,
    /// Whether `script-src` or `default-src` permits `'unsafe-inline'`.
    pub csp_unsafe_inline_script: bool,
    /// Whether `script-src` or `default-src` permits `'unsafe-eval'`.
    pub csp_unsafe_eval_script: bool,
    /// Whether `Strict-Transport-Security` (HSTS) is present.
    pub hsts_present: bool,
    /// Parsed HSTS `max-age` in seconds, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hsts_max_age_secs: Option<u64>,
    /// Whether `X-Content-Type-Options: nosniff` is present.
    pub x_content_type_options_nosniff: bool,
    /// Whether clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`) is present.
    pub x_frame_options_present: bool,
    /// Whether `Referrer-Policy` is present.
    pub referrer_policy_present: bool,
    /// Whether `Permissions-Policy` is present.
    pub permissions_policy_present: bool,
    /// Whether `Cross-Origin-Opener-Policy` (COOP) is present.
    pub coop_present: bool,
    /// Whether `Cross-Origin-Embedder-Policy` (COEP) is present.
    pub coep_present: bool,
    /// Whether `Cross-Origin-Resource-Policy` (CORP) is present.
    pub corp_present: bool,
    /// Number of runtime CSP violations observed in the browser timeline.
    pub runtime_csp_violation_count: u32,
    /// Number of mixed-content (`http://` on `https://`) subresources observed.
    pub mixed_content_request_count: u32,
    /// Number of external scripts lacking Subresource Integrity (`integrity`).
    pub external_scripts_without_sri: u32,
    /// Number of external links with `target="_blank"` lacking `rel="noopener"`.
    pub unsafe_target_blank_links: u32,
}

/// Detected WAF, anti-bot, or challenge provider family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeProviderKind {
    /// Cloudflare Turnstile / IUAM / Challenge page.
    Cloudflare,
    /// Akamai Bot Manager.
    Akamai,
    /// `DataDome` bot protection.
    DataDome,
    /// Imperva / Incapsula.
    Imperva,
    /// Fastly / Signal Sciences.
    Fastly,
    /// AWS WAF CAPTCHA / Challenge.
    AwsWaf,
    /// Google reCAPTCHA or hCaptcha widget.
    CaptchaWidget,
    /// Generic HTTP 403/429/503 challenge or rate-limit interstitial.
    GenericInterstitial,
}

/// Evidence of anti-bot challenges, WAF interstitials, or CAPTCHA walls.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SecurityChallengeEvidence {
    /// Whether an active challenge or bot-mitigation wall was detected.
    pub challenge_detected: bool,
    /// Identified challenge provider family, if matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ChallengeProviderKind>,
    /// Whether the challenge replaced the primary page content (interstitial block).
    pub blocking_page_content: bool,
    /// Initial HTTP status code when associated with a challenge (`403`, `429`, `503`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status_code: Option<u16>,
    /// Number of CAPTCHA or challenge iframes detected in the DOM.
    pub captcha_frame_count: u32,
    /// Matching structural indicators (e.g. `cf-mitigated`, `challenge-platform`, `g-recaptcha`).
    pub matched_indicators: Vec<String>,
}
