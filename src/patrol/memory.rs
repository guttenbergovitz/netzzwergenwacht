//! Structured persistent institutional memory for recurring web quality patrols.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::analysis::AuditReport;
use crate::discovery::PageType;
use crate::domain::{AuditTarget, Origin};
use crate::persistence::PersistenceError;

/// Version of the persisted [`ApplicationMemory`] schema.
pub const MEMORY_SCHEMA_VERSION: &str = "1.0.0";

/// Stable identifier derived from a canonical [`Origin`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ApplicationId(pub String);

impl ApplicationId {
    /// Derives a deterministic, filesystem-safe [`ApplicationId`] from `origin`.
    #[must_use]
    pub fn from_origin(origin: &Origin) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in origin.canonical_string().as_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        Self(format!("app-{hash:016x}"))
    }
}

/// Lifecycle freshness state of a remembered observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    /// Verified during the current patrol.
    CurrentlyVerified,
    /// Verified in a prior patrol within the freshness TTL.
    PreviouslyVerified,
    /// Older than the configured freshness TTL.
    PotentiallyStale,
    /// Could not be verified due to skipped, partial, or failed collection.
    Unverified,
}

/// Per-URL institutional memory recorded across patrols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberedPage {
    /// Canonical page URL.
    pub url: String,
    /// Detected locale/market tag if known.
    pub locale: Option<String>,
    /// Classified page type.
    pub page_type: PageType,
    /// Structural template fingerprint if observed.
    pub template_fingerprint: Option<String>,
    /// Content hash of the last complete HTTP body observed.
    pub content_hash: Option<String>,
    /// Unix timestamp of the last inspection.
    pub last_inspected_unix_secs: u64,
    /// Count of actionable (`Low`..`Critical`) findings on the last inspection.
    pub open_finding_count: usize,
    /// Number of consecutive inspections with zero actionable findings.
    pub healthy_streak: usize,
    /// Freshness classification of this record.
    pub freshness: EvidenceFreshness,
}

/// Persistent institutional memory for a single patrolled web application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationMemory {
    /// Memory schema version.
    pub schema_version: String,
    /// Stable application identifier.
    pub app_id: ApplicationId,
    /// Canonical origin of the application.
    pub origin: String,
    /// Total completed patrols recorded for this application.
    pub patrol_count: usize,
    /// Initial baseline report from Patrol #1.
    pub baseline_report: Option<AuditReport>,
    /// Most recent seed [`AuditReport`] for change comparison.
    pub latest_report: Option<AuditReport>,
    /// Remembered per-page state keyed by URL.
    pub page_records: BTreeMap<String, RememberedPage>,
    /// Distinct locale tags observed across patrols.
    pub known_locales: Vec<String>,
    /// Unix timestamp of the most recent patrol.
    pub last_patrolled_unix_secs: u64,
}

impl ApplicationMemory {
    /// Creates an empty memory record for `target`.
    #[must_use]
    pub fn new(target: &AuditTarget, now_unix_secs: u64) -> Self {
        let origin = Origin::from_target(target);
        Self {
            schema_version: MEMORY_SCHEMA_VERSION.to_owned(),
            app_id: ApplicationId::from_origin(&origin),
            origin: origin.canonical_string(),
            patrol_count: 0,
            baseline_report: None,
            latest_report: None,
            page_records: BTreeMap::new(),
            known_locales: Vec::new(),
            last_patrolled_unix_secs: now_unix_secs,
        }
    }
}

/// Computes a deterministic 64-bit FNV-1a hex digest of `body`.
#[must_use]
pub fn hash_body(body: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in body.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("fnv1a-{hash:016x}")
}

/// Loads [`ApplicationMemory`] for `app_id` from `dir`, returning `Ok(None)` if absent.
///
/// # Errors
///
/// Returns [`PersistenceError`] if reading or JSON deserialisation fails.
pub fn load_memory(
    dir: &Path,
    app_id: &ApplicationId,
) -> Result<Option<ApplicationMemory>, PersistenceError> {
    let path = dir.join(format!("{}.json", app_id.0));
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)?;
    let mem: ApplicationMemory = serde_json::from_str(&raw)?;
    Ok(Some(mem))
}

/// Persists [`ApplicationMemory`] atomically-ish to `<dir>/<app_id>.json`.
///
/// # Errors
///
/// Returns [`PersistenceError`] if directory creation, serialisation, or writing fails.
pub fn save_memory(dir: &Path, memory: &ApplicationMemory) -> Result<(), PersistenceError> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", memory.app_id.0));
    let json = serde_json::to_string_pretty(memory)?;
    fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TargetPolicy;

    #[test]
    fn memory_roundtrips_by_application_id() {
        let dir = std::env::temp_dir().join("nzw_patrol_mem_test");
        let _ = fs::remove_dir_all(&dir);
        let target = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let mut mem = ApplicationMemory::new(&target, 1_700_000_000);
        mem.patrol_count = 1;
        mem.known_locales = vec!["en-GB".to_owned()];

        save_memory(&dir, &mem).unwrap();
        let loaded = load_memory(&dir, &mem.app_id).unwrap().unwrap();
        assert_eq!(loaded.patrol_count, 1);
        assert_eq!(loaded.known_locales, vec!["en-GB"]);

        let _ = fs::remove_dir_all(&dir);
    }
}
