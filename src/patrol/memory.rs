//! Structured persistent institutional memory for recurring web quality patrols.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::analysis::AuditReport;
use crate::discovery::PageType;
use crate::domain::{AuditTarget, Origin, Severity};
use crate::patrol::{AnomalyCategory, PatrolReport};
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
    /// Verified during the current patrol (full inspection).
    CurrentlyVerified,
    /// HTTP representation verified unchanged via `304`/matching `ETag` (does not prove runtime/browser stability).
    HttpRepresentationOnly,
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
    /// Optional `ETag` header from the last response.
    #[serde(default)]
    pub etag: Option<String>,
    /// Optional `Last-Modified` header from the last response.
    #[serde(default)]
    pub last_modified: Option<String>,
    /// Last full deterministic [`AuditReport`] captured for this page.
    #[serde(default)]
    pub latest_report: Option<AuditReport>,
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
    /// Graph rule IDs observed on the most recent patrol (prevents repeat `NewDefect` escalation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_graph_rule_ids: Vec<String>,
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
            known_graph_rule_ids: Vec::new(),
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

/// Persists [`ApplicationMemory`] atomically (`write temp + rename`) to `<dir>/<app_id>.json`
/// and updates the shared transactional [`PatrolIndexCatalog`] (`<dir>/catalog.index.json`).
///
/// # Errors
///
/// Returns [`PersistenceError`] if directory creation, serialisation, writing,
/// or atomic rename fails.
pub fn save_memory(dir: &Path, memory: &ApplicationMemory) -> Result<(), PersistenceError> {
    fs::create_dir_all(dir)?;
    let _lock = acquire_catalog_lock(dir)?;
    let path = dir.join(format!("{}.json", memory.app_id.0));
    let tmp_path = dir.join(format!("{}.json.tmp", memory.app_id.0));
    let json = serde_json::to_string_pretty(memory)?;
    fs::write(&tmp_path, json)?;
    fs::rename(&tmp_path, &path)?;

    let mut catalog = load_or_rebuild_catalog_unlocked(dir)?;
    upsert_memory_into_catalog(&mut catalog, memory);
    save_catalog_unlocked(dir, &catalog)?;
    Ok(())
}

/// Schema version of the persisted [`PatrolIndexCatalog`].
pub const CATALOG_SCHEMA_VERSION: u32 = 1;

/// Indexed target summary row in the portfolio patrol catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogTargetRow {
    /// Deterministic application identifier (`app-<16hex>`).
    pub app_id: String,
    /// Canonical origin string.
    pub origin: String,
    /// Unix timestamp of the most recent completed patrol run.
    pub last_patrolled_unix_secs: u64,
    /// Total completed patrols recorded for this target.
    pub patrol_count: usize,
    /// Number of remembered pages in the target's application map.
    pub page_count: usize,
    /// Total actionable (`Low`..`Critical`) findings on the latest seed report.
    pub active_finding_count: usize,
    /// Complete collector count from the latest seed snapshot integrity posture.
    pub complete_collectors: usize,
    /// Total collector count from the latest seed snapshot integrity posture.
    pub total_collectors: usize,
    /// Whether any collector truncated data in the latest seed snapshot.
    pub any_truncated: bool,
}

/// Indexed page row in the portfolio patrol catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPageRow {
    /// Deterministic application identifier (`app-<16hex>`).
    pub app_id: String,
    /// Canonical origin string.
    pub origin: String,
    /// Canonical page URL.
    pub url: String,
    /// Classified page type.
    pub page_type: PageType,
    /// Detected locale/market tag if known.
    pub locale: Option<String>,
    /// Structural template fingerprint if observed.
    pub template_fingerprint: Option<String>,
    /// Unix timestamp when this page was last inspected.
    pub last_inspected_unix_secs: u64,
    /// Last observed HTTP `ETag` header.
    pub etag: Option<String>,
    /// Last observed HTTP `Last-Modified` header.
    pub last_modified: Option<String>,
    /// Count of actionable findings on the last inspection.
    pub open_finding_count: usize,
    /// Consecutive inspections with zero actionable findings.
    pub healthy_streak: usize,
    /// Lifecycle freshness classification.
    pub freshness: EvidenceFreshness,
}

/// Indexed patrol run summary row in the portfolio patrol catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRunRow {
    /// Deterministic application identifier (`app-<16hex>`).
    pub app_id: String,
    /// Canonical origin string.
    pub origin: String,
    /// Stable patrol run identifier.
    pub patrol_id: String,
    /// 1-based patrol sequence number for this origin.
    pub patrol_number: usize,
    /// Unix timestamp when the patrol run completed.
    pub patrolled_at_unix_secs: u64,
    /// Number of URLs discovered in the application map.
    pub discovered_urls: usize,
    /// Number of URLs actively inspected during this run.
    pub inspected_urls: usize,
    /// Number of healthy remembered URLs reused.
    pub reused_urls: usize,
    /// Number of anomalies detected during this run.
    pub anomaly_count: usize,
    /// Whether the patrol completed quietly without material new anomalies.
    pub is_quiet_patrol: bool,
    /// Wall-clock duration of the patrol run in milliseconds.
    pub duration_ms: u64,
}

/// Indexed anomaly row in the portfolio patrol catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogAnomalyRow {
    /// Deterministic application identifier (`app-<16hex>`).
    pub app_id: String,
    /// Canonical origin string.
    pub origin: String,
    /// Stable patrol run identifier.
    pub patrol_id: String,
    /// Unix timestamp when the patrol run completed.
    pub patrolled_at_unix_secs: u64,
    /// Anomaly identifier within the patrol run.
    pub anomaly_id: String,
    /// Anomaly category (`NewDefect`, `MaterialRegression`, `TopologyChange`).
    pub category: AnomalyCategory,
    /// Affected page URL.
    pub affected_url: String,
    /// Preliminary severity of the anomaly.
    pub severity: Severity,
    /// Human-readable description of the anomaly.
    pub summary: String,
}

/// Filter criteria for querying indexed portfolio anomalies across targets.
#[derive(Debug, Clone, Default)]
pub struct CatalogAnomalyFilter<'a> {
    /// Optional application ID filter (`app-<16hex>`).
    pub app_id: Option<&'a str>,
    /// Optional minimum severity threshold.
    pub min_severity: Option<Severity>,
    /// Optional anomaly category filter.
    pub category: Option<AnomalyCategory>,
}

/// Normalized relational index catalog persisted alongside per-target JSON/JSONL files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatrolIndexCatalog {
    /// Schema version of the catalog index (`1`).
    pub schema_version: u32,
    /// Indexed target rows keyed by `app_id`.
    pub targets: BTreeMap<String, CatalogTargetRow>,
    /// Indexed page rows across all patrolled targets.
    pub pages: Vec<CatalogPageRow>,
    /// Chronological run summary rows across all patrolled targets.
    pub runs: Vec<CatalogRunRow>,
    /// Indexed anomaly rows across all patrolled targets.
    pub anomalies: Vec<CatalogAnomalyRow>,
}

struct CatalogLockGuard {
    lock_path: PathBuf,
}

impl Drop for CatalogLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn acquire_catalog_lock(dir: &Path) -> Result<CatalogLockGuard, PersistenceError> {
    fs::create_dir_all(dir)?;
    let lock_path = dir.join(".catalog.lock");
    for attempt in 0..50u32 {
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            let _ = writeln!(file, "pid={}", std::process::id());
            return Ok(CatalogLockGuard { lock_path });
        }
        if attempt == 25
            && let Ok(meta) = fs::metadata(&lock_path)
            && let Ok(modified) = meta.modified()
            && SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::ZERO)
                > Duration::from_secs(30)
        {
            let _ = fs::remove_file(&lock_path);
            continue;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = fs::remove_file(&lock_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)?;
    let _ = writeln!(file, "pid={}", std::process::id());
    Ok(CatalogLockGuard { lock_path })
}

fn catalog_path(dir: &Path) -> PathBuf {
    dir.join("catalog.index.json")
}

fn save_catalog_unlocked(dir: &Path, catalog: &PatrolIndexCatalog) -> Result<(), PersistenceError> {
    let path = catalog_path(dir);
    let tmp_path = dir.join(format!("catalog.index.{}.tmp", std::process::id()));
    let json = serde_json::to_string_pretty(catalog)?;
    fs::write(&tmp_path, json)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

fn upsert_memory_into_catalog(catalog: &mut PatrolIndexCatalog, memory: &ApplicationMemory) {
    catalog.schema_version = CATALOG_SCHEMA_VERSION;
    let (active_finding_count, complete_collectors, total_collectors, any_truncated) =
        memory.latest_report.as_ref().map_or((0, 0, 0, false), |r| {
            let active = r.summary.critical_findings
                + r.summary.high_findings
                + r.summary.medium_findings
                + r.summary.low_findings;
            let mut comp = usize::from(matches!(
                r.http,
                crate::domain::CollectorOutcome::Captured { .. }
            ));
            let mut tot = 1_usize;
            let mut trunc = match &r.http {
                crate::domain::CollectorOutcome::Captured { data } => data.body_truncated,
                crate::domain::CollectorOutcome::Partial { .. } => true,
                crate::domain::CollectorOutcome::Failed { .. }
                | crate::domain::CollectorOutcome::Skipped { .. } => false,
            };
            for col in &r.level2_collectors {
                tot += 1;
                if col.state == "captured" {
                    comp += 1;
                } else if col.state == "partial" {
                    trunc = true;
                }
            }
            (active, comp, tot, trunc)
        });

    catalog.targets.insert(
        memory.app_id.0.clone(),
        CatalogTargetRow {
            app_id: memory.app_id.0.clone(),
            origin: memory.origin.clone(),
            last_patrolled_unix_secs: memory.last_patrolled_unix_secs,
            patrol_count: memory.patrol_count,
            page_count: memory.page_records.len(),
            active_finding_count,
            complete_collectors,
            total_collectors,
            any_truncated,
        },
    );

    catalog.pages.retain(|p| p.app_id != memory.app_id.0);
    for page in memory.page_records.values() {
        catalog.pages.push(CatalogPageRow {
            app_id: memory.app_id.0.clone(),
            origin: memory.origin.clone(),
            url: page.url.clone(),
            page_type: page.page_type,
            locale: page.locale.clone(),
            template_fingerprint: page.template_fingerprint.clone(),
            last_inspected_unix_secs: page.last_inspected_unix_secs,
            etag: page.etag.clone(),
            last_modified: page.last_modified.clone(),
            open_finding_count: page.open_finding_count,
            healthy_streak: page.healthy_streak,
            freshness: page.freshness,
        });
    }
}

fn upsert_run_into_catalog(
    catalog: &mut PatrolIndexCatalog,
    app_id: &ApplicationId,
    report: &PatrolReport,
) {
    catalog.schema_version = CATALOG_SCHEMA_VERSION;
    let origin = report.application_map.origin.clone();
    let patrolled_at = report.application_map.last_patrolled_unix_secs;
    catalog
        .runs
        .retain(|r| !(r.app_id == app_id.0 && r.patrol_id == report.patrol_id));
    catalog.runs.push(CatalogRunRow {
        app_id: app_id.0.clone(),
        origin: origin.clone(),
        patrol_id: report.patrol_id.clone(),
        patrol_number: report.patrol_number,
        patrolled_at_unix_secs: patrolled_at,
        discovered_urls: report.coverage_matrix.discovered_urls,
        inspected_urls: report.coverage_matrix.inspected_urls,
        reused_urls: report.coverage_matrix.reused_urls,
        anomaly_count: report.anomalies.len(),
        is_quiet_patrol: report.is_quiet_patrol,
        duration_ms: report.resource_ledger.duration_ms,
    });
    catalog
        .runs
        .sort_by_key(|r| (r.patrolled_at_unix_secs, r.patrol_number));

    catalog
        .anomalies
        .retain(|a| !(a.app_id == app_id.0 && a.patrol_id == report.patrol_id));
    for anomaly in &report.anomalies {
        catalog.anomalies.push(CatalogAnomalyRow {
            app_id: app_id.0.clone(),
            origin: origin.clone(),
            patrol_id: report.patrol_id.clone(),
            patrolled_at_unix_secs: patrolled_at,
            anomaly_id: anomaly.id.clone(),
            category: anomaly.category,
            affected_url: anomaly.affected_url.clone(),
            severity: anomaly.severity,
            summary: anomaly.summary.clone(),
        });
    }
}

fn load_or_rebuild_catalog_unlocked(dir: &Path) -> Result<PatrolIndexCatalog, PersistenceError> {
    let path = catalog_path(dir);
    if path.exists()
        && let Ok(raw) = fs::read_to_string(&path)
        && let Ok(catalog) = serde_json::from_str::<PatrolIndexCatalog>(&raw)
        && catalog.schema_version == CATALOG_SCHEMA_VERSION
    {
        return Ok(catalog);
    }

    let mut catalog = PatrolIndexCatalog {
        schema_version: CATALOG_SCHEMA_VERSION,
        ..PatrolIndexCatalog::default()
    };
    if !dir.exists() {
        return Ok(catalog);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_path = entry.path();
        let Some(name) = file_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with("app-")
            && Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            && !name.ends_with(".index.json")
        {
            if let Ok(raw) = fs::read_to_string(&file_path)
                && let Ok(mem) = serde_json::from_str::<ApplicationMemory>(&raw)
            {
                upsert_memory_into_catalog(&mut catalog, &mem);
            }
        } else if name.starts_with("app-")
            && name.ends_with(".runs.jsonl")
            && let Ok(raw) = fs::read_to_string(&file_path)
        {
            let stem = name.trim_end_matches(".runs.jsonl");
            let app_id = ApplicationId(stem.to_owned());
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(run_report) = serde_json::from_str::<PatrolReport>(line) {
                    upsert_run_into_catalog(&mut catalog, &app_id, &run_report);
                }
            }
        }
    }
    Ok(catalog)
}

/// Appends a completed [`PatrolReport`] to `<dir>/<app_id>.runs.jsonl` and updates
/// the transactional [`PatrolIndexCatalog`] (`runs` and `anomalies` tables).
///
/// # Errors
///
/// Returns [`PersistenceError`] if directory creation, lock acquisition, or writing fails.
pub fn record_patrol_run(
    dir: &Path,
    app_id: &ApplicationId,
    report: &PatrolReport,
) -> Result<(), PersistenceError> {
    fs::create_dir_all(dir)?;
    let _lock = acquire_catalog_lock(dir)?;
    let runs_path = dir.join(format!("{}.runs.jsonl", app_id.0));
    let mut line = serde_json::to_string(report)?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(runs_path)?;
    file.write_all(line.as_bytes())?;

    let mut catalog = load_or_rebuild_catalog_unlocked(dir)?;
    upsert_run_into_catalog(&mut catalog, app_id, report);
    save_catalog_unlocked(dir, &catalog)?;
    Ok(())
}

/// Loads the [`PatrolIndexCatalog`] from `dir`, automatically migrating and rebuilding
/// it from existing `app-*.json` and `app-*.runs.jsonl` files if absent.
///
/// # Errors
///
/// Returns [`PersistenceError`] if directory reading or persistence fails.
pub fn load_or_rebuild_catalog(dir: &Path) -> Result<PatrolIndexCatalog, PersistenceError> {
    if !dir.exists() {
        return Ok(PatrolIndexCatalog {
            schema_version: CATALOG_SCHEMA_VERSION,
            ..PatrolIndexCatalog::default()
        });
    }
    let _lock = acquire_catalog_lock(dir)?;
    let catalog = load_or_rebuild_catalog_unlocked(dir)?;
    save_catalog_unlocked(dir, &catalog)?;
    Ok(catalog)
}

/// Returns all indexed target summary rows from the portfolio patrol catalog,
/// ordered by `app_id`.
///
/// # Errors
///
/// Returns [`PersistenceError`] if catalog loading fails.
pub fn query_catalog_targets(dir: &Path) -> Result<Vec<CatalogTargetRow>, PersistenceError> {
    let catalog = load_or_rebuild_catalog(dir)?;
    Ok(catalog.targets.into_values().collect())
}

/// Queries indexed anomaly rows across one or all patrolled targets in `dir`.
///
/// # Errors
///
/// Returns [`PersistenceError`] if catalog loading fails.
pub fn query_catalog_anomalies(
    dir: &Path,
    filter: &CatalogAnomalyFilter<'_>,
) -> Result<Vec<CatalogAnomalyRow>, PersistenceError> {
    let catalog = load_or_rebuild_catalog(dir)?;
    Ok(catalog
        .anomalies
        .into_iter()
        .filter(|a| {
            filter.app_id.is_none_or(|id| a.app_id == id)
                && filter.min_severity.is_none_or(|min| a.severity >= min)
                && filter.category.is_none_or(|cat| a.category == cat)
        })
        .collect())
}

/// Queries remembered pages across all patrolled targets in `dir` whose
/// `last_inspected_unix_secs` is strictly older than `before_unix_secs`, ordered
/// oldest-first for rotation scheduling.
///
/// # Errors
///
/// Returns [`PersistenceError`] if catalog loading fails.
pub fn query_catalog_stale_pages(
    dir: &Path,
    before_unix_secs: u64,
) -> Result<Vec<CatalogPageRow>, PersistenceError> {
    let catalog = load_or_rebuild_catalog(dir)?;
    let mut pages: Vec<CatalogPageRow> = catalog
        .pages
        .into_iter()
        .filter(|p| p.last_inspected_unix_secs < before_unix_secs)
        .collect();
    pages.sort_by_key(|p| p.last_inspected_unix_secs);
    Ok(pages)
}

/// Queries indexed patrol run summaries across one or all targets, returning up to
/// `limit` most recent runs.
///
/// # Errors
///
/// Returns [`PersistenceError`] if catalog loading fails.
pub fn query_catalog_runs(
    dir: &Path,
    app_id: Option<&str>,
    limit: usize,
) -> Result<Vec<CatalogRunRow>, PersistenceError> {
    let catalog = load_or_rebuild_catalog(dir)?;
    let mut matching: Vec<CatalogRunRow> = catalog
        .runs
        .into_iter()
        .filter(|r| app_id.is_none_or(|id| r.app_id == id))
        .collect();
    if matching.len() > limit {
        matching = matching.split_off(matching.len() - limit);
    }
    Ok(matching)
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

        let targets = query_catalog_targets(&dir).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].app_id, mem.app_id.0);
        assert_eq!(targets[0].patrol_count, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalog_queries_stale_pages_and_automatically_rebuilds_from_legacy_files() {
        let dir = std::env::temp_dir().join("nzw_patrol_catalog_test");
        let _ = fs::remove_dir_all(&dir);
        let target = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let mut mem = ApplicationMemory::new(&target, 1_700_005_000);
        mem.patrol_count = 2;
        mem.page_records.insert(
            String::from("https://example.org/pricing"),
            RememberedPage {
                url: String::from("https://example.org/pricing"),
                locale: Some(String::from("en-GB")),
                page_type: PageType::Article,
                template_fingerprint: Some(String::from("tpl-pricing")),
                content_hash: Some(String::from("fnv1a-1234")),
                etag: Some(String::from("\"v1\"")),
                last_modified: None,
                latest_report: None,
                last_inspected_unix_secs: 1_700_001_000,
                open_finding_count: 1,
                healthy_streak: 0,
                freshness: EvidenceFreshness::PreviouslyVerified,
            },
        );
        mem.page_records.insert(
            String::from("https://example.org/docs"),
            RememberedPage {
                url: String::from("https://example.org/docs"),
                locale: Some(String::from("en-GB")),
                page_type: PageType::Article,
                template_fingerprint: Some(String::from("tpl-docs")),
                content_hash: Some(String::from("fnv1a-5678")),
                etag: None,
                last_modified: None,
                latest_report: None,
                last_inspected_unix_secs: 1_700_004_500,
                open_finding_count: 0,
                healthy_streak: 3,
                freshness: EvidenceFreshness::CurrentlyVerified,
            },
        );
        save_memory(&dir, &mem).unwrap();

        let stale = query_catalog_stale_pages(&dir, 1_700_002_000).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].url, "https://example.org/pricing");

        // Remove catalog.index.json and verify automatic migration/rebuild from app-*.json.
        fs::remove_file(dir.join("catalog.index.json")).unwrap();
        let rebuilt_targets = query_catalog_targets(&dir).unwrap();
        assert_eq!(rebuilt_targets.len(), 1);
        assert_eq!(rebuilt_targets[0].page_count, 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
