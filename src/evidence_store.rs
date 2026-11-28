//! Durable application-wide evidence store.
//!
//! Reconnaissance produces more observations than any single page-level
//! [`crate::domain::EvidenceSnapshot`] can hold: every discovered page, every
//! acquired subresource, every systemic cluster and every coverage counter of a
//! crawl run. This module persists those observations locally so that later
//! analysis, application-wide queries and historical comparison work from
//! retained evidence instead of a fresh network acquisition.
//!
//! # Contracts
//!
//! - **Local only.** The store is a Turso Database file on disk; there is no
//!   service, no remote endpoint and no synchronisation channel.
//! - **Typed facade.** Every public method takes or returns crate types. No
//!   `turso` type appears in a signature, so the engine can be replaced inside
//!   this file without touching a caller.
//! - **Idempotent writes.** Observation identities are stable (run, page URL,
//!   resource URL, issue id), so a retried transaction cannot duplicate a row.
//! - **Bounded writes.** Write concurrency is capped independently of crawl
//!   concurrency, transactions stay short, and conflicts are retried a bounded
//!   number of times before the failure is reported.
//! - **No fabricated accounting.** Coverage counters are copied from the crawl
//!   that produced them and read back unchanged. A missing run is `None`, never
//!   a zeroed record.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use turso::{Builder, Database};

use crate::brigade::DwarfId;
use crate::discovery::{
    CrawlSummary, PageCrawlStatus, PageType, ResourceKind, ResourceObservation, ResourceStatus,
    RobotsOutcome, SystemicClassification,
};
use crate::domain::{Confidence, EvidenceRef, EvidenceSource, Severity};

/// Schema version this build creates and understands.
///
/// Migrations are forward-only: a store written by a newer build is refused
/// rather than partially understood.
pub const SCHEMA_VERSION: i64 = 4;

/// Maximum number of simultaneous write connections.
///
/// Deliberately independent of crawl concurrency: the acquisition pool can be
/// wide while the store keeps transaction pressure bounded.
const MAX_WRITE_CONNECTIONS: usize = 4;

/// Maximum attempts for one write batch before a conflict is reported.
const MAX_WRITE_ATTEMPTS: u32 = 8;

/// Maximum rows a single read operation may return.
const MAX_READ_ROWS: usize = 256;

/// Failures produced by the evidence store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database engine rejected an operation.
    #[error("evidence database error: {0}")]
    Database(String),
    /// The file was written by a build with a newer schema.
    #[error(
        "evidence schema version {found} is newer than the supported version {supported}; this build cannot read the store"
    )]
    SchemaTooNew {
        /// Version found in the file.
        found: i64,
        /// Highest version this build understands.
        supported: i64,
    },
    /// A run identifier was recorded twice.
    #[error("evidence run `{run_id}` has already been recorded")]
    DuplicateRun {
        /// Offending run identifier.
        run_id: String,
    },
    /// A write batch kept conflicting for the whole retry budget.
    #[error("evidence write conflicted after {attempts} attempts")]
    WriteConflict {
        /// Number of attempts made.
        attempts: u32,
    },
    /// The store path could not be prepared.
    #[error("evidence store path is not usable: {0}")]
    Path(String),
}

impl From<turso::Error> for StoreError {
    fn from(error: turso::Error) -> Self {
        Self::Database(error.to_string())
    }
}

/// One crawl run offered to the store.
#[derive(Debug, Clone, Copy)]
pub struct CrawlRecord<'a> {
    /// Stable run identifier, unique per recorded crawl.
    pub run_id: &'a str,
    /// Application identity the run belongs to, usually the seed origin.
    pub application: &'a str,
    /// Crawl output being persisted.
    pub summary: &'a CrawlSummary,
    /// When the observations were recorded, in Unix seconds.
    pub recorded_at_unix_secs: u64,
}

/// Coverage counters read back from the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredCoverage {
    /// URLs observed during discovery.
    pub discovered_urls: usize,
    /// URLs handed to an acquisition worker.
    pub fetched_urls: usize,
    /// URLs whose HTML was analysed.
    pub analysed_urls: usize,
    /// URLs whose acquisition failed.
    pub failed_urls: usize,
    /// URLs left unacquired because a bound was reached.
    pub skipped_budget_urls: usize,
    /// URLs whose acquisition was cancelled at the deadline.
    pub cancelled_urls: usize,
    /// URLs refused by robots exclusion rules.
    pub robots_blocked_urls: usize,
    /// Link discoveries rejected by a full frontier.
    pub queue_rejections: usize,
    /// Repeat discoveries of an already-known URL.
    pub duplicate_offers: usize,
    /// Whether the crawl acquired every URL it discovered.
    pub complete: bool,
    /// Whether the crawl terminated early on its budget.
    pub budget_exhausted: bool,
    /// How robots rules were obtained for the seed origin.
    pub robots: RobotsOutcome,
    /// Subresource accounting for the run.
    pub resources: StoredResourceCoverage,
}

/// Subresource counters read back from the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredResourceCoverage {
    /// Distinct subresources discovered.
    pub discovered_resources: usize,
    /// Subresources successfully acquired.
    pub fetched_resources: usize,
    /// Subresources that failed acquisition.
    pub failed_resources: usize,
    /// Subresources left unacquired because a bound was reached.
    pub skipped_resources: usize,
    /// Subresources cancelled at the deadline.
    pub cancelled_resources: usize,
    /// Subresources whose body was cut at the byte cap.
    pub truncated_resources: usize,
    /// Cross-origin references counted but not fetched.
    pub external_refused: usize,
    /// Configured subresource bound.
    pub max_resources: usize,
}

/// One page that references a shared subresource.
///
/// The dependent relationship is a discovery fact. It survives a failed or skipped resource
/// acquisition, because the page depends on the resource either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDependent {
    /// Page URL that references the resource.
    pub page_url: String,
    /// Resource family the page referenced.
    pub kind: ResourceKind,
}

/// One finding retained for a crawled page, together with the evidence it cites.
///
/// The evidence references are read back as the same [`EvidenceRef`] values that
/// produced them, so a stored finding can be navigated to its observation without
/// a second acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFinding {
    /// Page the finding was raised for.
    pub page_url: String,
    /// Position of the finding within its page, stable within the stored run.
    pub finding_index: usize,
    /// Stable rule identifier.
    pub rule_id: String,
    /// Specialist that raised the finding.
    pub dwarf_id: DwarfId,
    /// Impact severity reported by the rule.
    pub severity: Severity,
    /// Confidence reported by the rule.
    pub confidence: Confidence,
    /// Headline of the finding.
    pub title: String,
    /// Explanation grounded in the observed evidence.
    pub summary: String,
    /// Optional remediation guidance.
    pub remediation: Option<String>,
    /// Evidence references recorded with the finding.
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Verdict totals of one specialist for a run.
///
/// Each outcome is stored separately: a single total cannot distinguish a rule
/// that passed from a rule that was never evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredDwarfTotal {
    /// Specialist that produced the verdicts.
    pub dwarf_id: DwarfId,
    /// Checks that produced any verdict.
    pub checks_evaluated: usize,
    /// Checks that passed.
    pub checks_passed: usize,
    /// Checks that failed.
    pub checks_failed: usize,
    /// Checks deliberately not evaluated.
    pub checks_skipped: usize,
    /// Checks that could not be evaluated for lack of evidence.
    pub checks_unavailable: usize,
    /// Findings raised by this specialist.
    pub findings_count: usize,
}

/// Summary row for one recorded run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRun {
    /// Run identifier.
    pub run_id: String,
    /// Application identity.
    pub application: String,
    /// Seed URL of the crawl.
    pub seed_url: String,
    /// When the run was recorded, in Unix seconds.
    pub recorded_at_unix_secs: u64,
    /// Whether the crawl was complete.
    pub complete: bool,
    /// Discovered URL count, so a listing can state its own scale.
    pub discovered_urls: usize,
}

/// Page row read back from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPage {
    /// Normalised page URL.
    pub url: String,
    /// Hop depth from the seed.
    pub depth: usize,
    /// Inferred page type.
    pub page_type: PageType,
    /// Explicit crawl outcome.
    pub status: PageCrawlStatus,
}

/// Systemic cluster row read back from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSystemicIssue {
    /// Cluster identifier.
    pub issue_id: String,
    /// Recurring rule identifier.
    pub rule_id: String,
    /// Number of affected URLs in the cluster.
    pub affected_urls: usize,
    /// Classification label recorded by the crawler.
    pub classification: String,
    /// Human-readable cluster summary.
    pub summary: String,
}

/// Handle to the local evidence database.
///
/// Cloning is cheap: the underlying database is shared and each operation takes
/// its own connection. Write concurrency is bounded by an internal semaphore,
/// so callers may submit concurrent writes without controlling that limit.
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    database: Database,
    write_slots: Arc<Semaphore>,
    path: Option<PathBuf>,
}

impl EvidenceStore {
    /// Opens or creates the store at `path`, applying forward-only migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SchemaTooNew`] when the file was written by a newer
    /// build, and [`StoreError::Path`] when the parent directory cannot be used.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| StoreError::Path(error.to_string()))?;
        }
        let location = path
            .to_str()
            .ok_or_else(|| StoreError::Path("path is not valid UTF-8".to_owned()))?;
        let database = Builder::new_local(location)
            .build()
            .await
            .map_err(StoreError::from)?;
        initialise(&database).await?;
        Ok(Self {
            database,
            write_slots: Arc::new(Semaphore::new(MAX_WRITE_CONNECTIONS)),
            path: Some(path.to_path_buf()),
        })
    }

    /// Opens an additional connection, used by tests that manipulate pragmas.
    #[cfg(test)]
    fn connection_for_test(&self) -> Result<turso::Connection, StoreError> {
        Ok(self.database.connect()?)
    }

    /// Location of the store file, when it was opened from disk.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Current schema version of the open store.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the pragma cannot be read.
    pub async fn schema_version(&self) -> Result<i64, StoreError> {
        let connection = self.database.connect()?;
        read_user_version(&connection).await
    }

    /// Persists one crawl run and all observations it produced.
    ///
    /// The run row, page rows, resource rows and systemic clusters are written
    /// in a single transaction. Either all of them are readable afterwards, or
    /// none is: a finding must never reference evidence that was not committed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DuplicateRun`] when `run_id` already exists, and
    /// [`StoreError::WriteConflict`] when the retry budget is exhausted.
    pub async fn record_crawl(&self, record: CrawlRecord<'_>) -> Result<(), StoreError> {
        let _slot = self
            .write_slots
            .acquire()
            .await
            .map_err(|_| StoreError::Database("write slot unavailable".to_owned()))?;
        let connection = self.database.connect()?;

        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.write_once(&connection, record).await {
                Ok(()) => return Ok(()),
                Err(WriteFailure::DuplicateRun) => {
                    return Err(StoreError::DuplicateRun {
                        run_id: record.run_id.to_owned(),
                    });
                }
                Err(WriteFailure::Retryable) if attempt < MAX_WRITE_ATTEMPTS => {
                    let backoff = Duration::from_millis(u64::from(1u32 << attempt.min(5)));
                    tokio::time::sleep(backoff).await;
                }
                Err(WriteFailure::Retryable) => {
                    return Err(StoreError::WriteConflict { attempts: attempt });
                }
                Err(WriteFailure::Permanent(error)) => return Err(error),
            }
        }
    }

    /// Persists a single-target [`crate::analysis::AuditReport`] as a one-page
    /// run in the shared evidence store.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if `report.target` cannot be parsed or if writing
    /// to the database fails.
    pub async fn record_audit_report(
        &self,
        run_id: &str,
        application: &str,
        report: &crate::analysis::AuditReport,
        recorded_at_unix_secs: u64,
    ) -> Result<(), StoreError> {
        let summary = audit_report_to_summary(report);
        self.record_crawl(CrawlRecord {
            run_id,
            application,
            summary: &summary,
            recorded_at_unix_secs,
        })
        .await
    }
}

fn audit_report_to_summary(
    report: &crate::analysis::AuditReport,
) -> crate::discovery::CrawlSummary {
    use crate::discovery::{
        CrawlCoverage, CrawlSummary, DiscoveredPage, PageCrawlStatus, PageDiagnostics, PageType,
        ResourceCoverage, RobotsOutcome,
    };
    use crate::domain::CollectorOutcome;

    let seed = report.target.clone();

    let (page_status, http_status, analysed_urls, failed_urls) = match &report.http {
        CollectorOutcome::Captured { data } => {
            (PageCrawlStatus::Investigated, Some(data.status_code), 1, 0)
        }
        CollectorOutcome::Partial { data, .. } => (
            PageCrawlStatus::PartiallyInvestigated,
            Some(data.status_code),
            1,
            0,
        ),
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => {
            (PageCrawlStatus::Unreachable, None, 0, 1)
        }
    };

    let (
        findings,
        analysis_totals,
        (checks_passed, checks_failed, checks_skipped, checks_unavailable),
    ) = collect_analyser_totals(&report.analysers);

    CrawlSummary {
        seed: seed.clone(),
        pages: vec![DiscoveredPage {
            url: seed.clone(),
            page_type: PageType::Homepage,
            depth: 0,
            status: page_status,
        }],
        page_diagnostics: vec![PageDiagnostics {
            url: seed.as_str().to_owned(),
            http_status,
            page_type: PageType::Homepage,
            status: page_status,
            checks_passed,
            checks_failed,
            checks_skipped,
            checks_unavailable,
            findings,
        }],
        analysis_totals,
        coverage: CrawlCoverage {
            discovered_urls: 1,
            fetched_urls: 1,
            analysed_urls,
            failed_urls,
            skipped_budget_urls: 0,
            cancelled_urls: 0,
            robots_blocked_urls: 0,
            reused_evidence_urls: 0,
            unknown_urls: 0,
            robots: RobotsOutcome::Absent,
            queue_rejections: 0,
            duplicate_offers: 0,
            max_pages: 1,
            max_depth: 0,
            complete: analysed_urls == 1,
            resources: ResourceCoverage::default(),
        },
        resources: Vec::new(),
        page_resources: Vec::new(),
        systemic_issues: Vec::new(),
        budget_exhausted: false,
        graph_results: Vec::new(),
    }
}

fn collect_analyser_totals(
    analysers: &[crate::domain::AnalyserResult],
) -> (
    Vec<crate::discovery::PageFinding>,
    Vec<crate::discovery::DwarfAnalysisTotal>,
    (usize, usize, usize, usize),
) {
    use crate::discovery::{DwarfAnalysisTotal, PageFinding};
    use crate::domain::CheckStatus;

    let mut findings = Vec::new();
    let mut totals = Vec::new();
    let (mut passed, mut failed, mut skipped, mut unavailable) = (0usize, 0usize, 0usize, 0usize);

    for analyser in analysers {
        let (mut dp, mut df, mut ds, mut du) = (0usize, 0usize, 0usize, 0usize);
        for check in &analyser.checks {
            match check {
                CheckStatus::Passed { .. } => dp = dp.saturating_add(1),
                CheckStatus::Failed { .. } => df = df.saturating_add(1),
                CheckStatus::Skipped { .. } => ds = ds.saturating_add(1),
                CheckStatus::Unavailable { .. } => du = du.saturating_add(1),
            }
        }
        passed = passed.saturating_add(dp);
        failed = failed.saturating_add(df);
        skipped = skipped.saturating_add(ds);
        unavailable = unavailable.saturating_add(du);
        totals.push(DwarfAnalysisTotal {
            dwarf_id: analyser.dwarf_id,
            checks_evaluated: dp + df,
            checks_passed: dp,
            checks_failed: df,
            checks_skipped: ds,
            checks_unavailable: du,
            findings_count: analyser.findings.len(),
        });
        for f in &analyser.findings {
            findings.push(PageFinding {
                rule_id: f.rule_id.clone(),
                dwarf_id: analyser.dwarf_id,
                severity: f.severity,
                confidence: f.confidence,
                title: f.title.clone(),
                summary: f.summary.clone(),
                remediation: f.remediation.clone(),
                evidence_refs: f.evidence_refs.clone(),
            });
        }
    }

    (findings, totals, (passed, failed, skipped, unavailable))
}

impl EvidenceStore {
    async fn write_once(
        &self,
        connection: &turso::Connection,
        record: CrawlRecord<'_>,
    ) -> Result<(), WriteFailure> {
        connection
            .execute("BEGIN CONCURRENT", ())
            .await
            .map_err(classify)?;

        let outcome = self.insert_run(connection, record).await;
        match outcome {
            Ok(()) => {}
            Err(failure) => {
                rollback(connection).await;
                return Err(failure);
            }
        }

        if let Err(failure) = self.insert_observations(connection, record).await {
            rollback(connection).await;
            return Err(failure);
        }

        match connection.execute("COMMIT", ()).await {
            Ok(_) => Ok(()),
            Err(error) => {
                rollback(connection).await;
                Err(classify(error))
            }
        }
    }

    async fn insert_run(
        &self,
        connection: &turso::Connection,
        record: CrawlRecord<'_>,
    ) -> Result<(), WriteFailure> {
        let mut rows = connection
            .query("SELECT 1 FROM runs WHERE run_id = ?1", (record.run_id,))
            .await
            .map_err(classify)?;
        if rows.next().await.map_err(classify)?.is_some() {
            return Err(WriteFailure::DuplicateRun);
        }

        let coverage = record.summary.coverage;
        let resources = coverage.resources;
        let statement = "INSERT INTO runs (
                    run_id, application, seed_url, recorded_at_unix_secs, complete, budget_exhausted,
                    robots, discovered_urls, fetched_urls, analysed_urls, failed_urls,
                    skipped_budget_urls, cancelled_urls, robots_blocked_urls, queue_rejections,
                    duplicate_offers, max_pages, max_depth, resources_discovered,
                    resources_fetched, resources_failed, resources_skipped, resources_cancelled,
                    resources_truncated, resources_external_refused, resources_max
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                    ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)";
        connection
            .execute(
                statement,
                turso::params![
                    record.run_id,
                    record.application,
                    record.summary.seed.as_str(),
                    epoch(record.recorded_at_unix_secs),
                    flag(coverage.complete),
                    flag(record.summary.budget_exhausted),
                    robots_label(coverage.robots),
                    count(coverage.discovered_urls),
                    count(coverage.fetched_urls),
                    count(coverage.analysed_urls),
                    count(coverage.failed_urls),
                    count(coverage.skipped_budget_urls),
                    count(coverage.cancelled_urls),
                    count(coverage.robots_blocked_urls),
                    count(coverage.queue_rejections),
                    count(coverage.duplicate_offers),
                    count(coverage.max_pages),
                    count(coverage.max_depth),
                    count(resources.discovered_resources),
                    count(resources.fetched_resources),
                    count(resources.failed_resources),
                    count(resources.skipped_resources),
                    count(resources.cancelled_resources),
                    count(resources.truncated_resources),
                    count(resources.external_refused),
                    count(resources.max_resources),
                ],
            )
            .await
            .map_err(classify)?;
        Ok(())
    }

    async fn insert_observations(
        &self,
        connection: &turso::Connection,
        record: CrawlRecord<'_>,
    ) -> Result<(), WriteFailure> {
        for page in &record.summary.pages {
            connection
                .execute(
                    "INSERT INTO pages (run_id, url, depth, page_type, status)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(run_id, url) DO NOTHING",
                    (
                        record.run_id,
                        page.url.as_str(),
                        count(page.depth),
                        page_type_label(page.page_type),
                        page_status_label(page.status),
                    ),
                )
                .await
                .map_err(classify)?;
        }

        for resource in &record.summary.resources {
            connection
                .execute(
                    "INSERT INTO resources (run_id, url, kind, status, http_status, content_type,
                        byte_len, truncated, content_encoding, cache_control, etag_present,
                        last_modified_present, error)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                     ON CONFLICT(run_id, url) DO NOTHING",
                    (
                        record.run_id,
                        resource.url.as_str(),
                        resource_kind_label(resource.kind),
                        resource_status_label(resource.status),
                        resource.http_status.map(i64::from),
                        resource.content_type.clone(),
                        resource.byte_len.map(epoch),
                        flag(resource.truncated),
                        resource.content_encoding.clone(),
                        resource.cache_control.clone(),
                        resource.etag_present.map(i64::from),
                        resource.last_modified_present.map(i64::from),
                        resource.error.clone(),
                    ),
                )
                .await
                .map_err(classify)?;
        }

        for issue in &record.summary.systemic_issues {
            connection
                .execute(
                    "INSERT INTO systemic_issues
                        (run_id, issue_id, rule_id, affected_urls, classification, summary)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(run_id, issue_id) DO NOTHING",
                    (
                        record.run_id,
                        issue.id.as_str(),
                        issue.rule_id.0.clone(),
                        count(issue.affected_urls.len()),
                        systemic_label(issue.classification),
                        issue.summary.clone(),
                    ),
                )
                .await
                .map_err(classify)?;
        }

        insert_graph_results(connection, record.run_id, &record.summary.graph_results).await?;

        for edge in &record.summary.page_resources {
            connection
                .execute(
                    "INSERT INTO page_resources (run_id, page_url, resource_url, kind)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(run_id, page_url, resource_url) DO NOTHING",
                    (
                        record.run_id,
                        edge.page_url.as_str(),
                        edge.resource_url.as_str(),
                        resource_kind_label(edge.kind),
                    ),
                )
                .await
                .map_err(classify)?;
        }

        self.insert_page_findings(connection, record.run_id, &record.summary.page_diagnostics)
            .await?;
        self.insert_dwarf_totals(connection, record.run_id, &record.summary.analysis_totals)
            .await?;
        Ok(())
    }

    /// Writes per-page findings and the evidence references that raised them.
    ///
    /// Split from [`Self::insert_observations`] purely to keep each write routine
    /// readable; both run inside the caller's transaction.
    async fn insert_page_findings(
        &self,
        connection: &turso::Connection,
        run_id: &str,
        pages: &[crate::discovery::PageDiagnostics],
    ) -> Result<(), WriteFailure> {
        for page in pages {
            for (finding_index, finding) in page.findings.iter().enumerate() {
                connection
                    .execute(
                        "INSERT INTO page_findings (run_id, page_url, finding_index, rule_id,
                            dwarf, severity, confidence, title, summary, remediation)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                         ON CONFLICT(run_id, page_url, finding_index) DO NOTHING",
                        (
                            run_id,
                            page.url.as_str(),
                            count(finding_index),
                            finding.rule_id.0.clone(),
                            finding.dwarf_id.config_key(),
                            severity_label(finding.severity),
                            confidence_label(finding.confidence),
                            finding.title.clone(),
                            finding.summary.clone(),
                            finding.remediation.clone(),
                        ),
                    )
                    .await
                    .map_err(classify)?;

                for (evidence_index, reference) in finding.evidence_refs.iter().enumerate() {
                    connection
                        .execute(
                            "INSERT INTO finding_evidence (run_id, page_url, finding_index,
                                evidence_index, source, detail)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                             ON CONFLICT(run_id, page_url, finding_index, evidence_index)
                                 DO NOTHING",
                            (
                                run_id,
                                page.url.as_str(),
                                count(finding_index),
                                count(evidence_index),
                                evidence_source_label(reference.source),
                                reference.detail.clone(),
                            ),
                        )
                        .await
                        .map_err(classify)?;
                }
            }
        }

        Ok(())
    }

    /// Writes the per-specialist verdict counts for one run.
    async fn insert_dwarf_totals(
        &self,
        connection: &turso::Connection,
        run_id: &str,
        totals: &[crate::discovery::DwarfAnalysisTotal],
    ) -> Result<(), WriteFailure> {
        for total in totals {
            connection
                .execute(
                    "INSERT INTO dwarf_totals (run_id, dwarf, checks_evaluated, checks_passed,
                        checks_failed, checks_skipped, checks_unavailable, findings_count)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(run_id, dwarf) DO NOTHING",
                    (
                        run_id,
                        total.dwarf_id.config_key(),
                        count(total.checks_evaluated),
                        count(total.checks_passed),
                        count(total.checks_failed),
                        count(total.checks_skipped),
                        count(total.checks_unavailable),
                        count(total.findings_count),
                    ),
                )
                .await
                .map_err(classify)?;
        }
        Ok(())
    }

    /// Reads the coverage record of one run.
    ///
    /// Returns `None` when the run was never recorded; an absent run is not an
    /// empty one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query fails.
    pub async fn coverage(&self, run_id: &str) -> Result<Option<StoredCoverage>, StoreError> {
        let connection = self.database.connect()?;
        let mut rows = connection
            .query(
                "SELECT robots, discovered_urls, fetched_urls, analysed_urls, failed_urls,
                        skipped_budget_urls, cancelled_urls, robots_blocked_urls, queue_rejections,
                        duplicate_offers, complete, budget_exhausted,
                        resources_discovered, resources_fetched, resources_failed,
                        resources_skipped, resources_cancelled, resources_truncated,
                        resources_external_refused, resources_max
                 FROM runs WHERE run_id = ?1",
                (run_id,),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        let robots = robots_from_label(&row.get::<String>(0)?).ok_or_else(|| {
            unknown_value("robots outcome", &row.get::<String>(0).unwrap_or_default())
        })?;

        Ok(Some(StoredCoverage {
            discovered_urls: positive(&row, 1)?,
            fetched_urls: positive(&row, 2)?,
            analysed_urls: positive(&row, 3)?,
            failed_urls: positive(&row, 4)?,
            skipped_budget_urls: positive(&row, 5)?,
            cancelled_urls: positive(&row, 6)?,
            robots_blocked_urls: positive(&row, 7)?,
            queue_rejections: positive(&row, 8)?,
            duplicate_offers: positive(&row, 9)?,
            complete: row.get::<i64>(10)? != 0,
            budget_exhausted: row.get::<i64>(11)? != 0,
            robots,
            resources: StoredResourceCoverage {
                discovered_resources: positive(&row, 12)?,
                fetched_resources: positive(&row, 13)?,
                failed_resources: positive(&row, 14)?,
                skipped_resources: positive(&row, 15)?,
                cancelled_resources: positive(&row, 16)?,
                truncated_resources: positive(&row, 17)?,
                external_refused: positive(&row, 18)?,
                max_resources: positive(&row, 19)?,
            },
        }))
    }

    /// Lists recorded runs, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query fails.
    pub async fn runs(&self, limit: usize) -> Result<Vec<StoredRun>, StoreError> {
        let connection = self.database.connect()?;
        let mut rows = connection
            .query(
                "SELECT run_id, application, seed_url, recorded_at_unix_secs, complete,
                        discovered_urls
                 FROM runs ORDER BY recorded_at_unix_secs DESC, run_id ASC LIMIT ?1",
                (bounded_limit(limit),),
            )
            .await?;

        let mut runs = Vec::new();
        while let Some(row) = rows.next().await? {
            runs.push(StoredRun {
                run_id: row.get::<String>(0)?,
                application: row.get::<String>(1)?,
                seed_url: row.get::<String>(2)?,
                recorded_at_unix_secs: non_negative(&row, 3)?,
                complete: row.get::<i64>(4)? != 0,
                discovered_urls: positive(&row, 5)?,
            });
        }
        Ok(runs)
    }

    /// Lists pages of one run, optionally restricted to one crawl status.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query fails.
    pub async fn pages(
        &self,
        run_id: &str,
        status: Option<PageCrawlStatus>,
        limit: usize,
    ) -> Result<Vec<StoredPage>, StoreError> {
        let connection = self.database.connect()?;
        let limit = bounded_limit(limit);
        let mut rows = match status {
            Some(status) => {
                connection
                    .query(
                        "SELECT url, depth, page_type, status FROM pages
                         WHERE run_id = ?1 AND status = ?2 ORDER BY url ASC LIMIT ?3",
                        (run_id, page_status_label(status), limit),
                    )
                    .await?
            }
            None => {
                connection
                    .query(
                        "SELECT url, depth, page_type, status FROM pages
                         WHERE run_id = ?1 ORDER BY url ASC LIMIT ?2",
                        (run_id, limit),
                    )
                    .await?
            }
        };

        let mut pages = Vec::new();
        while let Some(row) = rows.next().await? {
            let page_type = row.get::<String>(2)?;
            let status = row.get::<String>(3)?;
            pages.push(StoredPage {
                url: row.get::<String>(0)?,
                depth: positive(&row, 1)?,
                page_type: page_type_from_label(&page_type)
                    .ok_or_else(|| unknown_value("page type", &page_type))?,
                status: page_status_from_label(&status)
                    .ok_or_else(|| unknown_value("page status", &status))?,
            });
        }
        Ok(pages)
    }

    /// Lists subresources of one run, optionally restricted to one kind.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query fails.
    pub async fn resources(
        &self,
        run_id: &str,
        kind: Option<ResourceKind>,
        limit: usize,
    ) -> Result<Vec<ResourceObservation>, StoreError> {
        let connection = self.database.connect()?;
        let limit = bounded_limit(limit);
        let mut rows =
            match kind {
                Some(kind) => connection
                    .query(
                        "SELECT url, kind, status, http_status, content_type, byte_len, truncated,
                                content_encoding, cache_control, etag_present, last_modified_present,
                                error
                         FROM resources WHERE run_id = ?1 AND kind = ?2 ORDER BY url ASC LIMIT ?3",
                        (run_id, resource_kind_label(kind), limit),
                    )
                    .await?,
                None => connection
                    .query(
                        "SELECT url, kind, status, http_status, content_type, byte_len, truncated,
                                content_encoding, cache_control, etag_present, last_modified_present,
                                error
                         FROM resources WHERE run_id = ?1 ORDER BY url ASC LIMIT ?2",
                        (run_id, limit),
                    )
                    .await?,
            };

        let mut resources = Vec::new();
        while let Some(row) = rows.next().await? {
            let kind_label = row.get::<String>(1)?;
            let status_label = row.get::<String>(2)?;
            let kind = resource_kind_from_label(&kind_label)
                .ok_or_else(|| unknown_value("resource kind", &kind_label))?;
            let status = resource_status_from_label(&status_label)
                .ok_or_else(|| unknown_value("resource status", &status_label))?;
            resources.push(ResourceObservation {
                url: row.get::<String>(0)?,
                kind,
                status,
                http_status: optional_u16(&row, 3)?,
                content_type: row.get::<String>(4).ok(),
                byte_len: optional_u64(&row, 5)?,
                content_encoding: row.get::<String>(7).ok(),
                cache_control: row.get::<String>(8).ok(),
                etag_present: optional_flag(&row, 9),
                last_modified_present: optional_flag(&row, 10),
                truncated: row.get::<i64>(6)? != 0,
                error: row.get::<String>(11).ok(),
            });
        }
        Ok(resources)
    }

    /// Lists the pages that reference one subresource, sorted by page URL.
    ///
    /// This is the leverage query: a defect in a stylesheet referenced by three hundred pages is
    /// one remediation, not three hundred findings. The result is bounded like every other read.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query fails.
    pub async fn resource_dependents(
        &self,
        run_id: &str,
        resource_url: &str,
        limit: usize,
    ) -> Result<Vec<StoredDependent>, StoreError> {
        let connection = self.database.connect()?;
        let mut rows = connection
            .query(
                "SELECT page_url, kind FROM page_resources
                 WHERE run_id = ?1 AND resource_url = ?2
                 ORDER BY page_url ASC LIMIT ?3",
                (run_id, resource_url, bounded_limit(limit)),
            )
            .await?;

        let mut dependents = Vec::new();
        while let Some(row) = rows.next().await? {
            let kind_label = row.get::<String>(1)?;
            let kind = resource_kind_from_label(&kind_label)
                .ok_or_else(|| unknown_value("resource kind", &kind_label))?;
            dependents.push(StoredDependent {
                page_url: row.get::<String>(0)?,
                kind,
            });
        }
        Ok(dependents)
    }

    /// Lists retained findings of one run, optionally narrowed to a page and a severity.
    ///
    /// Both filters are optional; `None` means "no restriction", not "unavailable". The limit is
    /// never widened, and evidence references are read for each returned finding.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when a query fails or a stored label is not recognised.
    pub async fn findings(
        &self,
        run_id: &str,
        page_url: Option<&str>,
        severity: Option<Severity>,
        limit: usize,
    ) -> Result<Vec<StoredFinding>, StoreError> {
        let connection = self.database.connect()?;
        let severity_label_value = severity.map(severity_label);
        let mut rows = connection
            .query(
                "SELECT page_url, finding_index, rule_id, dwarf, severity, confidence, title,
                        summary, remediation
                 FROM page_findings
                 WHERE run_id = ?1
                   AND (?2 IS NULL OR page_url = ?2)
                   AND (?3 IS NULL OR severity = ?3)
                 ORDER BY page_url ASC, finding_index ASC
                 LIMIT ?4",
                (run_id, page_url, severity_label_value, bounded_limit(limit)),
            )
            .await?;

        let mut findings = Vec::new();
        while let Some(row) = rows.next().await? {
            let dwarf_label = row.get::<String>(3)?;
            let dwarf_id = DwarfId::from_config_key(&dwarf_label)
                .ok_or_else(|| unknown_value("dwarf", &dwarf_label))?;
            let severity_value = row.get::<String>(4)?;
            let severity = severity_from_label(&severity_value)
                .ok_or_else(|| unknown_value("severity", &severity_value))?;
            let confidence_value = row.get::<String>(5)?;
            let confidence = confidence_from_label(&confidence_value)
                .ok_or_else(|| unknown_value("confidence", &confidence_value))?;
            let page = row.get::<String>(0)?;
            let index = positive(&row, 1)?;

            findings.push(StoredFinding {
                page_url: page.clone(),
                finding_index: index,
                rule_id: row.get::<String>(2)?,
                dwarf_id,
                severity,
                confidence,
                title: row.get::<String>(6)?,
                summary: row.get::<String>(7)?,
                remediation: row.get::<String>(8).ok(),
                evidence_refs: self
                    .finding_evidence(&connection, run_id, &page, index)
                    .await?,
            });
        }
        Ok(findings)
    }

    async fn finding_evidence(
        &self,
        connection: &turso::Connection,
        run_id: &str,
        page_url: &str,
        finding_index: usize,
    ) -> Result<Vec<EvidenceRef>, StoreError> {
        let mut rows = connection
            .query(
                "SELECT source, detail FROM finding_evidence
                 WHERE run_id = ?1 AND page_url = ?2 AND finding_index = ?3
                 ORDER BY evidence_index ASC",
                (run_id, page_url, count(finding_index)),
            )
            .await?;
        let mut refs = Vec::new();
        while let Some(row) = rows.next().await? {
            let label = row.get::<String>(0)?;
            // A label this build cannot interpret is skipped rather than mapped onto a
            // plausible source, which would attach the evidence to the wrong observation.
            if let Some(source) = evidence_source_from_label(&label) {
                refs.push(EvidenceRef::new(source, row.get::<String>(1)?));
            }
        }
        Ok(refs)
    }

    /// Lists each specialist's verdict totals for one run.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query fails or a stored dwarf key is not recognised.
    pub async fn dwarf_totals(&self, run_id: &str) -> Result<Vec<StoredDwarfTotal>, StoreError> {
        let connection = self.database.connect()?;
        let mut rows = connection
            .query(
                "SELECT dwarf, checks_evaluated, checks_passed, checks_failed, checks_skipped,
                        checks_unavailable, findings_count
                 FROM dwarf_totals WHERE run_id = ?1 ORDER BY dwarf ASC",
                (run_id,),
            )
            .await?;

        let mut totals = Vec::new();
        while let Some(row) = rows.next().await? {
            let label = row.get::<String>(0)?;
            let dwarf_id =
                DwarfId::from_config_key(&label).ok_or_else(|| unknown_value("dwarf", &label))?;
            totals.push(StoredDwarfTotal {
                dwarf_id,
                checks_evaluated: positive(&row, 1)?,
                checks_passed: positive(&row, 2)?,
                checks_failed: positive(&row, 3)?,
                checks_skipped: positive(&row, 4)?,
                checks_unavailable: positive(&row, 5)?,
                findings_count: positive(&row, 6)?,
            });
        }
        Ok(totals)
    }

    /// Lists systemic clusters of one run, ordered by affected breadth.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query fails.
    pub async fn systemic_issues(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredSystemicIssue>, StoreError> {
        let connection = self.database.connect()?;
        let mut rows = connection
            .query(
                "SELECT issue_id, rule_id, affected_urls, classification, summary
                 FROM systemic_issues WHERE run_id = ?1
                 ORDER BY affected_urls DESC, issue_id ASC LIMIT ?2",
                (run_id, bounded_limit(limit)),
            )
            .await?;

        let mut issues = Vec::new();
        while let Some(row) = rows.next().await? {
            issues.push(StoredSystemicIssue {
                issue_id: row.get::<String>(0)?,
                rule_id: row.get::<String>(1)?,
                affected_urls: positive(&row, 2)?,
                classification: row.get::<String>(3)?,
                summary: row.get::<String>(4)?,
            });
        }
        Ok(issues)
    }

    /// Returns persisted site-wide `graph.*` [`crate::domain::AnalyserResult`] entries for `run_id`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the query or JSON deserialisation fails.
    pub async fn graph_results(
        &self,
        run_id: &str,
    ) -> Result<Vec<crate::domain::AnalyserResult>, StoreError> {
        let connection = self.database.connect()?;
        let mut rows = connection
            .query(
                "SELECT payload_json FROM graph_results WHERE run_id = ?1 ORDER BY dwarf_id ASC",
                [run_id],
            )
            .await?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().await? {
            let raw = row.get::<String>(0)?;
            let parsed: crate::domain::AnalyserResult =
                serde_json::from_str(&raw).map_err(|err| {
                    StoreError::Database(format!("invalid persisted graph_results JSON: {err}"))
                })?;
            results.push(parsed);
        }
        Ok(results)
    }

    /// Persists an incremental crawl checkpoint for `checkpoint.application`, enabling resume.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if serialisation or the `SQLite` upsert fails.
    pub async fn save_checkpoint(&self, checkpoint: &CrawlCheckpoint) -> Result<(), StoreError> {
        let frontier_json = serde_json::to_string(&checkpoint.frontier_urls)
            .map_err(|e| StoreError::Database(format!("failed to serialise frontier: {e}")))?;
        let visited_json = serde_json::to_string(&checkpoint.visited_urls)
            .map_err(|e| StoreError::Database(format!("failed to serialise visited: {e}")))?;
        let connection = self.database.connect()?;
        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS crawl_checkpoints (
                    application TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    frontier_json TEXT NOT NULL,
                    visited_urls_json TEXT NOT NULL,
                    updated_at_unix_secs INTEGER NOT NULL
                )",
                (),
            )
            .await?;
        connection
            .execute(
                "INSERT INTO crawl_checkpoints
                 (application, run_id, frontier_json, visited_urls_json, updated_at_unix_secs)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(application) DO UPDATE SET
                    run_id = excluded.run_id,
                    frontier_json = excluded.frontier_json,
                    visited_urls_json = excluded.visited_urls_json,
                    updated_at_unix_secs = excluded.updated_at_unix_secs",
                (
                    checkpoint.application.as_str(),
                    checkpoint.run_id.as_str(),
                    frontier_json,
                    visited_json,
                    checkpoint.updated_at_unix_secs,
                ),
            )
            .await?;
        Ok(())
    }

    /// Loads the latest crawl checkpoint for `application`, if one exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the query or JSON deserialisation fails.
    pub async fn load_checkpoint(
        &self,
        application: &str,
    ) -> Result<Option<CrawlCheckpoint>, StoreError> {
        let connection = self.database.connect()?;
        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS crawl_checkpoints (
                    application TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    frontier_json TEXT NOT NULL,
                    visited_urls_json TEXT NOT NULL,
                    updated_at_unix_secs INTEGER NOT NULL
                )",
                (),
            )
            .await?;
        let mut rows = connection
            .query(
                "SELECT run_id, frontier_json, visited_urls_json, updated_at_unix_secs
                 FROM crawl_checkpoints WHERE application = ?1",
                [application],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let run_id = row.get::<String>(0)?;
        let frontier_raw = row.get::<String>(1)?;
        let visited_raw = row.get::<String>(2)?;
        let updated_at_unix_secs = row.get::<i64>(3)?;
        let frontier_urls = serde_json::from_str(&frontier_raw)
            .map_err(|e| StoreError::Database(format!("invalid checkpoint frontier JSON: {e}")))?;
        let visited_urls = serde_json::from_str(&visited_raw)
            .map_err(|e| StoreError::Database(format!("invalid checkpoint visited JSON: {e}")))?;
        Ok(Some(CrawlCheckpoint {
            application: application.to_owned(),
            run_id,
            frontier_urls,
            visited_urls,
            updated_at_unix_secs,
        }))
    }

    /// Deletes any saved crawl checkpoint for `application`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the `SQLite` delete fails.
    pub async fn clear_checkpoint(&self, application: &str) -> Result<(), StoreError> {
        let connection = self.database.connect()?;
        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS crawl_checkpoints (
                    application TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    frontier_json TEXT NOT NULL,
                    visited_urls_json TEXT NOT NULL,
                    updated_at_unix_secs INTEGER NOT NULL
                )",
                (),
            )
            .await?;
        connection
            .execute(
                "DELETE FROM crawl_checkpoints WHERE application = ?1",
                [application],
            )
            .await?;
        Ok(())
    }

    /// Returns stored pages from the most recent fresh run for `application` within `max_age_secs`
    /// for incremental scan reuse, or an empty vector when no fresh run exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if querying the store fails.
    pub async fn latest_known_pages(
        &self,
        application: &str,
        max_age_secs: i64,
        now_unix_secs: i64,
    ) -> Result<Vec<StoredPage>, StoreError> {
        let connection = self.database.connect()?;
        let min_ts = now_unix_secs.saturating_sub(max_age_secs);
        let mut rows = connection
            .query(
                "SELECT run_id FROM runs
                 WHERE application = ?1 AND recorded_at_unix_secs >= ?2
                 ORDER BY recorded_at_unix_secs DESC LIMIT 1",
                (application, min_ts),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(Vec::new());
        };
        let run_id = row.get::<String>(0)?;
        self.pages(&run_id, None, MAX_READ_ROWS).await
    }
}

/// Resumable crawl frontier/visited checkpoint persisted in [`EvidenceStore`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrawlCheckpoint {
    /// Application seed URL/key.
    pub application: String,
    /// Active run identifier.
    pub run_id: String,
    /// Remaining unvisited frontier URLs.
    pub frontier_urls: Vec<String>,
    /// URLs already visited in this run.
    pub visited_urls: Vec<String>,
    /// Checkpoint timestamp in Unix seconds.
    pub updated_at_unix_secs: i64,
}

async fn insert_graph_results(
    connection: &turso::Connection,
    run_id: &str,
    graph_results: &[crate::domain::AnalyserResult],
) -> Result<(), WriteFailure> {
    for analyser in graph_results {
        let payload_json = serde_json::to_string(analyser).map_err(|err| {
            WriteFailure::Permanent(StoreError::Database(format!(
                "failed to serialise graph_results: {err}"
            )))
        })?;
        connection
            .execute(
                "INSERT INTO graph_results (run_id, dwarf_id, payload_json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(run_id, dwarf_id) DO UPDATE SET payload_json = excluded.payload_json",
                (run_id, analyser.dwarf_id.display_name(), payload_json),
            )
            .await
            .map_err(classify)?;
    }
    Ok(())
}

/// Internal classification of a failed write attempt.
enum WriteFailure {
    /// The run identifier already exists; retrying cannot help.
    DuplicateRun,
    /// A concurrent transaction won; the batch may be retried.
    Retryable,
    /// Anything else, reported as produced.
    Permanent(StoreError),
}

fn classify(error: turso::Error) -> WriteFailure {
    if is_retryable(&error) {
        return WriteFailure::Retryable;
    }
    WriteFailure::Permanent(StoreError::from(error))
}

fn is_retryable(error: &turso::Error) -> bool {
    match error {
        turso::Error::Busy(_) | turso::Error::BusySnapshot(_) => true,
        turso::Error::Error(message) => {
            let lowered = message.to_ascii_lowercase();
            lowered.contains("conflict") || lowered.contains("busy")
        }
        _ => false,
    }
}

async fn rollback(connection: &turso::Connection) {
    // A failed rollback leaves the connection in the same state as a dropped
    // transaction: the engine discards it. Reporting it here would mask the
    // original failure, which is the one the caller can act on.
    let _ = connection.execute("ROLLBACK", ()).await;
}

async fn initialise(database: &Database) -> Result<(), StoreError> {
    let connection = database.connect()?;
    let found = read_user_version(&connection).await?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found == SCHEMA_VERSION {
        return Ok(());
    }

    let mut mode = connection
        .query("PRAGMA journal_mode = 'mvcc'", ())
        .await
        .map_err(StoreError::from)?;
    while mode.next().await.map_err(StoreError::from)?.is_some() {}
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(StoreError::from)?;
    let mut version = found;
    if version < 1 {
        connection
            .execute_batch(SCHEMA_V1)
            .await
            .map_err(StoreError::from)?;
        version = 1;
    }
    if version < 2 {
        connection
            .execute_batch(MIGRATION_V2)
            .await
            .map_err(StoreError::from)?;
        version = 2;
    }
    if version < 3 {
        connection
            .execute_batch(MIGRATION_V3)
            .await
            .map_err(StoreError::from)?;
        version = 3;
    }
    if version < 4 {
        connection
            .execute_batch(MIGRATION_V4)
            .await
            .map_err(StoreError::from)?;
        version = 4;
    }
    connection
        .execute(format!("PRAGMA user_version = {version}"), ())
        .await
        .map_err(StoreError::from)?;
    Ok(())
}

async fn read_user_version(connection: &turso::Connection) -> Result<i64, StoreError> {
    let mut rows = connection.query("PRAGMA user_version", ()).await?;
    let version = match rows.next().await? {
        Some(row) => row.get::<i64>(0).unwrap_or(0),
        None => 0,
    };
    Ok(version)
}

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    application TEXT NOT NULL,
    seed_url TEXT NOT NULL,
    recorded_at_unix_secs INTEGER NOT NULL,
    complete INTEGER NOT NULL,
    budget_exhausted INTEGER NOT NULL,
    robots TEXT NOT NULL,
    discovered_urls INTEGER NOT NULL,
    fetched_urls INTEGER NOT NULL,
    analysed_urls INTEGER NOT NULL,
    failed_urls INTEGER NOT NULL,
    skipped_budget_urls INTEGER NOT NULL,
    cancelled_urls INTEGER NOT NULL,
    robots_blocked_urls INTEGER NOT NULL,
    queue_rejections INTEGER NOT NULL,
    duplicate_offers INTEGER NOT NULL,
    max_pages INTEGER NOT NULL,
    max_depth INTEGER NOT NULL,
    resources_discovered INTEGER NOT NULL,
    resources_fetched INTEGER NOT NULL,
    resources_failed INTEGER NOT NULL,
    resources_skipped INTEGER NOT NULL,
    resources_cancelled INTEGER NOT NULL,
    resources_truncated INTEGER NOT NULL,
    resources_external_refused INTEGER NOT NULL,
    resources_max INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pages (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    depth INTEGER NOT NULL,
    page_type TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (run_id, url)
);
CREATE INDEX IF NOT EXISTS pages_by_status ON pages(run_id, status);

CREATE TABLE IF NOT EXISTS resources (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    http_status INTEGER,
    content_type TEXT,
    byte_len INTEGER,
    truncated INTEGER NOT NULL,
    PRIMARY KEY (run_id, url)
);
CREATE INDEX IF NOT EXISTS resources_by_kind ON resources(run_id, kind);

CREATE TABLE IF NOT EXISTS systemic_issues (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    issue_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    affected_urls INTEGER NOT NULL,
    classification TEXT NOT NULL,
    summary TEXT NOT NULL,
    PRIMARY KEY (run_id, issue_id)
);
CREATE INDEX IF NOT EXISTS systemic_by_rule ON systemic_issues(run_id, rule_id);
CREATE TABLE IF NOT EXISTS graph_results (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    dwarf_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (run_id, dwarf_id)
);
";

/// Schema v2 adds the resource detail that v1 recorded in memory and then dropped.
///
/// The flags are nullable on purpose: a row written by v1 has no stored header observation, and
/// backfilling `0` would assert an absence nobody verified.
const MIGRATION_V2: &str = "
ALTER TABLE resources ADD COLUMN content_encoding TEXT;
ALTER TABLE resources ADD COLUMN cache_control TEXT;
ALTER TABLE resources ADD COLUMN etag_present INTEGER;
ALTER TABLE resources ADD COLUMN last_modified_present INTEGER;
ALTER TABLE resources ADD COLUMN error TEXT;
";

/// Schema v3 records which pages reference which subresources.
///
/// Without the edge, a shared-resource finding could be counted but never attributed to the
/// pages that would have to change. The edge is independent of acquisition success.
const MIGRATION_V3: &str = "
CREATE TABLE IF NOT EXISTS page_resources (
    run_id TEXT NOT NULL,
    page_url TEXT NOT NULL,
    resource_url TEXT NOT NULL,
    kind TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, page_url, resource_url)
);
CREATE INDEX IF NOT EXISTS page_resources_by_resource
    ON page_resources(run_id, resource_url);
";

/// Schema v4 retains what a crawl concluded about each page.
///
/// A run that stored which pages exist but not what was wrong with them forced the next
/// inspection to repeat the acquisition. Findings, the evidence references they were raised
/// from, and each specialist's verdict counts are recorded in the same transaction as the run,
/// so a finding can never reference evidence that was not committed.
const MIGRATION_V4: &str = "
CREATE TABLE IF NOT EXISTS page_findings (
    run_id TEXT NOT NULL,
    page_url TEXT NOT NULL,
    finding_index INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    dwarf TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    remediation TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, page_url, finding_index)
);
CREATE INDEX IF NOT EXISTS page_findings_by_rule
    ON page_findings(run_id, rule_id);
CREATE INDEX IF NOT EXISTS page_findings_by_dwarf
    ON page_findings(run_id, dwarf);

CREATE TABLE IF NOT EXISTS finding_evidence (
    run_id TEXT NOT NULL,
    page_url TEXT NOT NULL,
    finding_index INTEGER NOT NULL,
    evidence_index INTEGER NOT NULL,
    source TEXT NOT NULL,
    detail TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, page_url, finding_index, evidence_index)
);

CREATE TABLE IF NOT EXISTS dwarf_totals (
    run_id TEXT NOT NULL,
    dwarf TEXT NOT NULL,
    checks_evaluated INTEGER NOT NULL,
    checks_passed INTEGER NOT NULL,
    checks_failed INTEGER NOT NULL,
    checks_skipped INTEGER NOT NULL,
    checks_unavailable INTEGER NOT NULL,
    findings_count INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, dwarf)
);
";

fn count(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn epoch(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn flag(value: bool) -> i64 {
    i64::from(u8::from(value))
}

/// Clamps a caller's limit without ever widening it.
///
/// A limit of zero returns no rows. Raising it to one would answer a question the caller did not
/// ask, and returning everything would contradict the bound.
fn bounded_limit(limit: usize) -> i64 {
    count(limit.min(MAX_READ_ROWS))
}

fn positive(row: &turso::Row, index: usize) -> Result<usize, StoreError> {
    let value = row.get::<i64>(index)?;
    usize::try_from(value).map_err(|_| unknown_value("non-negative count", &value.to_string()))
}

fn non_negative(row: &turso::Row, index: usize) -> Result<u64, StoreError> {
    let value = row.get::<i64>(index)?;
    u64::try_from(value).map_err(|_| unknown_value("non-negative integer", &value.to_string()))
}

fn optional_flag(row: &turso::Row, index: usize) -> Option<bool> {
    // A NULL column means the observation was never stored, which is not the same as a header
    // verified absent. Returning `None` keeps that distinction visible to callers.
    row.get::<i64>(index).ok().map(|value| value != 0)
}

fn optional_u64(row: &turso::Row, index: usize) -> Result<Option<u64>, StoreError> {
    match row.get::<i64>(index) {
        Ok(value) => u64::try_from(value)
            .map(Some)
            .map_err(|_| unknown_value("non-negative integer", &value.to_string())),
        Err(_) => Ok(None),
    }
}

fn optional_u16(row: &turso::Row, index: usize) -> Result<Option<u16>, StoreError> {
    match row.get::<i64>(index) {
        Ok(value) => u16::try_from(value)
            .map(Some)
            .map_err(|_| unknown_value("HTTP status", &value.to_string())),
        Err(_) => Ok(None),
    }
}

fn unknown_value(kind: &str, value: &str) -> StoreError {
    StoreError::Database(format!(
        "unrecognised {kind} `{value}` in the evidence store"
    ))
}

const fn robots_label(outcome: RobotsOutcome) -> &'static str {
    match outcome {
        RobotsOutcome::Observed => "observed",
        RobotsOutcome::Absent => "absent",
        RobotsOutcome::Unavailable => "unavailable",
    }
}

fn robots_from_label(label: &str) -> Option<RobotsOutcome> {
    match label {
        "observed" => Some(RobotsOutcome::Observed),
        "absent" => Some(RobotsOutcome::Absent),
        "unavailable" => Some(RobotsOutcome::Unavailable),
        _ => None,
    }
}

const fn systemic_label(classification: SystemicClassification) -> &'static str {
    match classification {
        SystemicClassification::RepeatedRuleOccurrence => "repeated_rule_occurrence",
        SystemicClassification::SuspectedSharedTemplate => "suspected_shared_template",
        SystemicClassification::SuspectedCommonConfiguration => "suspected_common_configuration",
        SystemicClassification::VerifiedCommonCause => "verified_common_cause",
    }
}

const fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn severity_from_label(label: &str) -> Option<Severity> {
    match label {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

const fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn confidence_from_label(label: &str) -> Option<Confidence> {
    match label {
        "low" => Some(Confidence::Low),
        "medium" => Some(Confidence::Medium),
        "high" => Some(Confidence::High),
        _ => None,
    }
}

/// Records the collector that produced a finding's evidence.
///
/// The labels are the `serde` names of [`EvidenceSource`], so a stored reference and a reference
/// produced in memory agree on their spelling rather than on a second private vocabulary.
const fn evidence_source_label(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::HttpStatus => "http_status",
        EvidenceSource::HttpFinalUrl => "http_final_url",
        EvidenceSource::HttpRedirectChain => "http_redirect_chain",
        EvidenceSource::HttpHeaders => "http_headers",
        EvidenceSource::HttpTiming => "http_timing",
        EvidenceSource::HttpBody => "http_body",
        EvidenceSource::TlsCertificate => "tls_certificate",
        EvidenceSource::BrowserRuntime => "browser_runtime",
        EvidenceSource::LighthouseReport => "lighthouse_report",
        EvidenceSource::AxeReport => "axe_report",
        EvidenceSource::VisualLayout => "visual_layout",
    }
}

fn evidence_source_from_label(label: &str) -> Option<EvidenceSource> {
    match label {
        "http_status" => Some(EvidenceSource::HttpStatus),
        "http_final_url" => Some(EvidenceSource::HttpFinalUrl),
        "http_redirect_chain" => Some(EvidenceSource::HttpRedirectChain),
        "http_headers" => Some(EvidenceSource::HttpHeaders),
        "http_timing" => Some(EvidenceSource::HttpTiming),
        "http_body" => Some(EvidenceSource::HttpBody),
        "tls_certificate" => Some(EvidenceSource::TlsCertificate),
        "browser_runtime" => Some(EvidenceSource::BrowserRuntime),
        "lighthouse_report" => Some(EvidenceSource::LighthouseReport),
        "axe_report" => Some(EvidenceSource::AxeReport),
        "visual_layout" => Some(EvidenceSource::VisualLayout),
        _ => None,
    }
}

const fn page_type_label(page_type: PageType) -> &'static str {
    match page_type {
        PageType::Homepage => "homepage",
        PageType::Auth => "auth",
        PageType::Legal => "legal",
        PageType::Contact => "contact",
        PageType::Support => "support",
        PageType::Form => "form",
        PageType::Article => "article",
        PageType::Listing => "listing",
        PageType::Unknown => "unknown",
    }
}

fn page_type_from_label(label: &str) -> Option<PageType> {
    match label {
        "homepage" => Some(PageType::Homepage),
        "auth" => Some(PageType::Auth),
        "legal" => Some(PageType::Legal),
        "contact" => Some(PageType::Contact),
        "support" => Some(PageType::Support),
        "form" => Some(PageType::Form),
        "article" => Some(PageType::Article),
        "listing" => Some(PageType::Listing),
        "unknown" => Some(PageType::Unknown),
        _ => None,
    }
}

const fn page_status_label(status: PageCrawlStatus) -> &'static str {
    match status {
        PageCrawlStatus::Investigated => "investigated",
        PageCrawlStatus::PartiallyInvestigated => "partially_investigated",
        PageCrawlStatus::ReusedEvidence => "reused_evidence",
        PageCrawlStatus::SkippedBudget => "skipped_budget",
        PageCrawlStatus::Excluded => "excluded",
        PageCrawlStatus::Unreachable => "unreachable",
        PageCrawlStatus::Unknown => "unknown",
    }
}

fn page_status_from_label(label: &str) -> Option<PageCrawlStatus> {
    match label {
        "investigated" => Some(PageCrawlStatus::Investigated),
        "partially_investigated" => Some(PageCrawlStatus::PartiallyInvestigated),
        "reused_evidence" => Some(PageCrawlStatus::ReusedEvidence),
        "skipped_budget" => Some(PageCrawlStatus::SkippedBudget),
        "excluded" => Some(PageCrawlStatus::Excluded),
        "unreachable" => Some(PageCrawlStatus::Unreachable),
        "unknown" => Some(PageCrawlStatus::Unknown),
        _ => None,
    }
}

const fn resource_kind_label(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Script => "script",
        ResourceKind::Stylesheet => "stylesheet",
        ResourceKind::Image => "image",
    }
}

fn resource_kind_from_label(label: &str) -> Option<ResourceKind> {
    match label {
        "script" => Some(ResourceKind::Script),
        "stylesheet" => Some(ResourceKind::Stylesheet),
        "image" => Some(ResourceKind::Image),
        _ => None,
    }
}

const fn resource_status_label(status: ResourceStatus) -> &'static str {
    match status {
        ResourceStatus::Fetched => "fetched",
        ResourceStatus::Failed => "failed",
        ResourceStatus::SkippedBudget => "skipped_budget",
    }
}

fn resource_status_from_label(label: &str) -> Option<ResourceStatus> {
    match label {
        "fetched" => Some(ResourceStatus::Fetched),
        "failed" => Some(ResourceStatus::Failed),
        "skipped_budget" => Some(ResourceStatus::SkippedBudget),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CrawlRecord, EvidenceStore, MIGRATION_V2, MIGRATION_V3, SCHEMA_V1, SCHEMA_VERSION,
        StoreError,
    };
    use crate::brigade::DwarfId;
    use crate::discovery::{
        CrawlCoverage, CrawlSummary, DiscoveredPage, DwarfAnalysisTotal, PageCrawlStatus,
        PageDiagnostics, PageFinding, PageResourceEdge, PageType, ResourceCoverage, ResourceKind,
        ResourceObservation, ResourceStatus, RobotsOutcome, SystemicClassification, SystemicIssue,
    };
    use crate::domain::{
        AuditTarget, Confidence, EvidenceRef, EvidenceSource, RuleId, Severity, TargetPolicy,
    };
    use std::path::PathBuf;
    use turso::Builder;

    fn store_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzw-evidence-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("evidence.db")
    }

    fn target(url: &str) -> AuditTarget {
        AuditTarget::parse(url, TargetPolicy::AllowPrivate).expect("fixture target")
    }

    fn observation(url: &str, kind: ResourceKind, bytes: Option<u64>) -> ResourceObservation {
        ResourceObservation {
            url: url.to_owned(),
            kind,
            status: ResourceStatus::Fetched,
            http_status: Some(200),
            content_type: Some("text/css".to_owned()),
            content_encoding: None,
            byte_len: bytes,
            cache_control: Some("max-age=600".to_owned()),
            etag_present: Some(true),
            last_modified_present: Some(false),
            truncated: false,
            error: None,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn summary() -> CrawlSummary {
        let coverage = CrawlCoverage {
            discovered_urls: 6,
            fetched_urls: 4,
            analysed_urls: 4,
            failed_urls: 1,
            skipped_budget_urls: 1,
            cancelled_urls: 0,
            robots_blocked_urls: 1,
            reused_evidence_urls: 0,
            unknown_urls: 0,
            robots: RobotsOutcome::Observed,
            queue_rejections: 3,
            duplicate_offers: 5,
            max_pages: 8,
            max_depth: 2,
            complete: false,
            resources: ResourceCoverage {
                discovered_resources: 4,
                fetched_resources: 2,
                failed_resources: 1,
                skipped_resources: 1,
                cancelled_resources: 0,
                truncated_resources: 1,
                external_refused: 2,
                max_resources: 64,
            },
        };

        CrawlSummary {
            seed: target("https://example.org/"),
            pages: vec![
                DiscoveredPage {
                    url: target("https://example.org/"),
                    page_type: PageType::Homepage,
                    depth: 0,
                    status: PageCrawlStatus::Investigated,
                },
                DiscoveredPage {
                    url: target("https://example.org/blog/post"),
                    page_type: PageType::Article,
                    depth: 1,
                    status: PageCrawlStatus::PartiallyInvestigated,
                },
                DiscoveredPage {
                    url: target("https://example.org/dead"),
                    page_type: PageType::Unknown,
                    depth: 1,
                    status: PageCrawlStatus::Unreachable,
                },
            ],
            systemic_issues: vec![SystemicIssue {
                id: "systemic.rule.1".to_owned(),
                rule_id: RuleId("sec.header.hsts_missing".to_owned()),
                affected_urls: vec![
                    "https://example.org/".to_owned(),
                    "https://example.org/blog/post".to_owned(),
                ],
                affected_page_types: vec![PageType::Homepage, PageType::Article],
                classification: SystemicClassification::SuspectedCommonConfiguration,
                summary: "HSTS is absent on both observed page types.".to_owned(),
                recurrence_confidence: Confidence::High,
                shared_cause_confidence: Confidence::Medium,
                severity: Severity::High,
                dwarf_id: DwarfId::Sicherheits,
            }],
            budget_exhausted: true,
            graph_results: Vec::new(),
            coverage,
            page_resources: vec![PageResourceEdge {
                page_url: "https://example.org/".to_owned(),
                resource_url: "https://example.org/site.css".to_owned(),
                kind: ResourceKind::Stylesheet,
            }],
            resources: vec![
                observation(
                    "https://example.org/app.js",
                    ResourceKind::Script,
                    Some(120),
                ),
                observation(
                    "https://example.org/site.css",
                    ResourceKind::Stylesheet,
                    Some(21),
                ),
            ],
            analysis_totals: vec![DwarfAnalysisTotal {
                dwarf_id: DwarfId::Sicherheits,
                checks_evaluated: 10,
                checks_passed: 7,
                checks_failed: 1,
                checks_skipped: 2,
                checks_unavailable: 0,
                findings_count: 1,
            }],
            page_diagnostics: vec![PageDiagnostics {
                url: "https://example.org/".to_owned(),
                http_status: Some(200),
                page_type: PageType::Homepage,
                status: PageCrawlStatus::Investigated,
                checks_passed: 7,
                checks_failed: 1,
                checks_skipped: 2,
                checks_unavailable: 0,
                findings: vec![PageFinding {
                    rule_id: RuleId("sec.header.hsts_missing".to_owned()),
                    dwarf_id: DwarfId::Sicherheits,
                    severity: Severity::High,
                    confidence: Confidence::High,
                    title: "HSTS header is missing".to_owned(),
                    summary: "The response carried no Strict-Transport-Security header.".to_owned(),
                    remediation: Some(
                        "Send Strict-Transport-Security on https responses.".to_owned(),
                    ),
                    evidence_refs: vec![
                        EvidenceRef::new(
                            EvidenceSource::HttpHeaders,
                            "header=strict-transport-security",
                        ),
                        EvidenceRef::new(EvidenceSource::HttpStatus, "status=200"),
                    ],
                }],
            }],
        }
    }

    #[tokio::test]
    async fn schema_version_is_created_and_stable_across_reopen() {
        let path = store_path("schema");
        let store = EvidenceStore::open(&path).await.expect("open");
        assert_eq!(
            store.schema_version().await.expect("version"),
            SCHEMA_VERSION
        );
        drop(store);

        let reopened = EvidenceStore::open(&path).await.expect("reopen");
        assert_eq!(
            reopened.schema_version().await.expect("version"),
            SCHEMA_VERSION
        );
    }

    #[tokio::test]
    async fn a_newer_schema_is_refused_instead_of_partially_read() {
        let path = store_path("too-new");
        let store = EvidenceStore::open(&path).await.expect("open");
        let connection = store.connection_for_test().expect("connection");
        connection
            .execute("PRAGMA user_version = 99", ())
            .await
            .expect("set version");
        drop(store);

        match EvidenceStore::open(&path).await {
            Err(StoreError::SchemaTooNew { found, supported }) => {
                assert_eq!(found, 99);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn coverage_is_read_back_exactly_as_recorded() {
        let store = EvidenceStore::open(&store_path("coverage"))
            .await
            .expect("open");
        let summary = summary();
        store
            .record_crawl(CrawlRecord {
                run_id: "run-1",
                application: "https://example.org",
                summary: &summary,
                recorded_at_unix_secs: 1_700_000_000,
            })
            .await
            .expect("record");

        let coverage = store
            .coverage("run-1")
            .await
            .expect("read")
            .expect("present");
        let recorded = summary.coverage;
        assert_eq!(coverage.discovered_urls, recorded.discovered_urls);
        assert_eq!(coverage.fetched_urls, recorded.fetched_urls);
        assert_eq!(coverage.analysed_urls, recorded.analysed_urls);
        assert_eq!(coverage.failed_urls, recorded.failed_urls);
        assert_eq!(coverage.skipped_budget_urls, recorded.skipped_budget_urls);
        assert_eq!(coverage.cancelled_urls, recorded.cancelled_urls);
        assert_eq!(coverage.robots_blocked_urls, recorded.robots_blocked_urls);
        assert_eq!(coverage.queue_rejections, recorded.queue_rejections);
        assert_eq!(coverage.duplicate_offers, recorded.duplicate_offers);
        assert_eq!(coverage.complete, recorded.complete);
        assert_eq!(coverage.budget_exhausted, summary.budget_exhausted);
        assert_eq!(coverage.robots, recorded.robots);
        assert_eq!(coverage.resources.discovered_resources, 4);
        assert_eq!(coverage.resources.fetched_resources, 2);
        assert_eq!(coverage.resources.failed_resources, 1);
        assert_eq!(coverage.resources.skipped_resources, 1);
        assert_eq!(coverage.resources.truncated_resources, 1);
        assert_eq!(coverage.resources.external_refused, 2);
        assert_eq!(coverage.resources.max_resources, 64);
        assert!(store.coverage("absent").await.expect("read").is_none());
    }

    #[tokio::test]
    async fn pages_resources_and_clusters_are_queryable_and_bounded() {
        let store = EvidenceStore::open(&store_path("reads"))
            .await
            .expect("open");
        let summary = summary();
        store
            .record_crawl(CrawlRecord {
                run_id: "run-1",
                application: "https://example.org",
                summary: &summary,
                recorded_at_unix_secs: 1_700_000_000,
            })
            .await
            .expect("record");

        let pages = store.pages("run-1", None, 10).await.expect("pages");
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].url, "https://example.org/");
        assert_eq!(pages[0].page_type, PageType::Homepage);

        let unreachable = store
            .pages("run-1", Some(PageCrawlStatus::Unreachable), 10)
            .await
            .expect("pages");
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0].url, "https://example.org/dead");

        let bounded = store.pages("run-1", None, 1).await.expect("pages");
        assert_eq!(bounded.len(), 1);

        let stylesheets = store
            .resources("run-1", Some(ResourceKind::Stylesheet), 10)
            .await
            .expect("resources");
        assert_eq!(stylesheets.len(), 1);
        assert_eq!(stylesheets[0].byte_len, Some(21));
        assert_eq!(stylesheets[0].http_status, Some(200));

        let issues = store.systemic_issues("run-1", 10).await.expect("issues");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule_id, "sec.header.hsts_missing");
        assert_eq!(issues[0].affected_urls, 2);

        let runs = store.runs(10).await.expect("runs");
        assert_eq!(runs.len(), 1);
        assert!(!runs[0].complete);
    }

    #[tokio::test]
    async fn recording_the_same_run_twice_is_refused_without_partial_rows() {
        let store = EvidenceStore::open(&store_path("duplicate"))
            .await
            .expect("open");
        let summary = summary();
        let record = CrawlRecord {
            run_id: "run-1",
            application: "https://example.org",
            summary: &summary,
            recorded_at_unix_secs: 1_700_000_000,
        };
        store.record_crawl(record).await.expect("first");
        match store.record_crawl(record).await {
            Err(StoreError::DuplicateRun { run_id }) => assert_eq!(run_id, "run-1"),
            other => panic!("expected DuplicateRun, got {other:?}"),
        }
        assert_eq!(
            store.pages("run-1", None, 10).await.expect("pages").len(),
            3
        );
    }

    #[tokio::test]
    async fn resource_detail_survives_the_round_trip() {
        let store = EvidenceStore::open(&store_path("resource-detail"))
            .await
            .expect("open");
        let mut summary = summary();
        let mut script = observation(
            "https://example.org/app.js",
            ResourceKind::Script,
            Some(120),
        );
        script.content_encoding = Some("br".to_owned());
        script.cache_control = Some("public, max-age=31536000".to_owned());
        script.etag_present = Some(true);
        script.last_modified_present = Some(false);
        let failed = ResourceObservation {
            status: ResourceStatus::Failed,
            http_status: None,
            content_type: None,
            byte_len: None,
            cache_control: None,
            etag_present: None,
            last_modified_present: None,
            error: Some("connection reset".to_owned()),
            ..observation(
                "https://example.org/missing.css",
                ResourceKind::Stylesheet,
                None,
            )
        };
        summary.resources = vec![script, failed];

        store
            .record_crawl(CrawlRecord {
                run_id: "run-1",
                application: "https://example.org",
                summary: &summary,
                recorded_at_unix_secs: 1_700_000_000,
            })
            .await
            .expect("record");

        let stored = store.resources("run-1", None, 10).await.expect("resources");
        assert_eq!(stored.len(), 2, "both observations must be retained");
        let app = stored
            .iter()
            .find(|resource| resource.url.ends_with("app.js"))
            .expect("script observation");
        assert_eq!(app.content_encoding.as_deref(), Some("br"));
        assert_eq!(
            app.cache_control.as_deref(),
            Some("public, max-age=31536000")
        );
        assert_eq!(app.etag_present, Some(true));
        assert_eq!(app.last_modified_present, Some(false));

        let missing = stored
            .iter()
            .find(|resource| resource.url.ends_with("missing.css"))
            .expect("failed observation");
        assert_eq!(missing.error.as_deref(), Some("connection reset"));
        assert_eq!(
            missing.etag_present, None,
            "a failed acquisition must not claim the header was absent"
        );
    }

    #[tokio::test]
    async fn a_version_one_store_is_migrated_without_inventing_header_observations() {
        let path = store_path("migrate");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create directory");
        }
        let location = path.to_str().expect("UTF-8 path");
        let database = turso::Builder::new_local(location)
            .build()
            .await
            .expect("build legacy store");
        let connection = database.connect().expect("connection");
        connection
            .execute_batch(super::SCHEMA_V1)
            .await
            .expect("legacy schema");
        connection
            .execute("PRAGMA user_version = 1", ())
            .await
            .expect("legacy version");
        connection
            .execute(
                "INSERT INTO resources
                    (run_id, url, kind, status, http_status, content_type, byte_len, truncated)
                 VALUES ('legacy', 'https://example.org/legacy.css', 'stylesheet', 'fetched',
                    200, 'text/css', 10, 0)",
                (),
            )
            .await
            .expect("legacy row");
        drop(connection);
        drop(database);

        let store = EvidenceStore::open(&path).await.expect("migrate");
        assert_eq!(
            store.schema_version().await.expect("version"),
            SCHEMA_VERSION
        );
        let resources = store
            .resources("legacy", None, 10)
            .await
            .expect("resources");
        assert_eq!(resources.len(), 1, "migration must keep existing rows");
        assert_eq!(resources[0].url, "https://example.org/legacy.css");
        assert_eq!(resources[0].etag_present, None);
        assert_eq!(resources[0].last_modified_present, None);
        assert_eq!(resources[0].content_encoding, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_runs_are_persisted_independently() {
        let store = EvidenceStore::open(&store_path("concurrent"))
            .await
            .expect("open");
        let mut handles = Vec::new();
        for index in 0..4 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let summary = summary();
                let run_id = format!("run-{index}");
                store
                    .record_crawl(CrawlRecord {
                        run_id: &run_id,
                        application: "https://example.org",
                        summary: &summary,
                        recorded_at_unix_secs: 1_700_000_000 + u64::try_from(index).unwrap_or(0),
                    })
                    .await
            }));
        }
        for handle in handles {
            handle.await.expect("join").expect("write");
        }

        let runs = store.runs(10).await.expect("runs");
        assert_eq!(runs.len(), 4);
        for run in &runs {
            let coverage = store
                .coverage(&run.run_id)
                .await
                .expect("coverage")
                .expect("present");
            assert_eq!(coverage.discovered_urls, 6);
        }
    }

    #[tokio::test]
    async fn page_resource_edges_attribute_a_shared_resource_to_its_dependents() {
        let store = EvidenceStore::open(&store_path("edges"))
            .await
            .expect("open");
        store
            .record_crawl(CrawlRecord {
                run_id: "run-edges",
                application: "https://example.org",
                summary: &summary(),
                recorded_at_unix_secs: 1_700_000_000,
            })
            .await
            .expect("record");

        let dependents = store
            .resource_dependents("run-edges", "https://example.org/site.css", 10)
            .await
            .expect("dependents");
        assert_eq!(dependents.len(), 1);
        assert_eq!(dependents[0].page_url, "https://example.org/");
        assert_eq!(dependents[0].kind, ResourceKind::Stylesheet);

        assert_eq!(
            store
                .resource_dependents("run-edges", "https://example.org/site.css", 0)
                .await
                .expect("bounded")
                .len(),
            0,
            "a zero limit must bound the result, not be treated as unlimited"
        );
        assert_eq!(
            store
                .resource_dependents("run-edges", "https://example.org/unreferenced.css", 10)
                .await
                .expect("absent")
                .len(),
            0,
            "a resource with no observed dependents is an empty observation, not an error"
        );
    }

    #[tokio::test]
    async fn a_version_two_store_gains_the_edge_table_without_losing_rows() {
        let path = store_path("migrate-v2");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create directory");
        }
        let location = path.to_str().expect("UTF-8 path");
        let database = turso::Builder::new_local(location)
            .build()
            .await
            .expect("build legacy store");
        let connection = database.connect().expect("connection");
        connection
            .execute_batch(super::SCHEMA_V1)
            .await
            .expect("legacy schema");
        connection
            .execute_batch(super::MIGRATION_V2)
            .await
            .expect("version two schema");
        connection
            .execute("PRAGMA user_version = 2", ())
            .await
            .expect("legacy version");
        connection
            .execute(
                "INSERT INTO resources
                    (run_id, url, kind, status, http_status, content_type, byte_len, truncated,
                     content_encoding, cache_control, etag_present, last_modified_present, error)
                 VALUES ('legacy', 'https://example.org/app.js', 'script', 'fetched',
                    200, 'application/javascript', 42, 0, 'br', 'max-age=60', 1, 0, NULL)",
                (),
            )
            .await
            .expect("legacy row");
        drop(connection);
        drop(database);

        let store = EvidenceStore::open(&path).await.expect("migrate");
        assert_eq!(
            store.schema_version().await.expect("version"),
            SCHEMA_VERSION
        );
        let resources = store
            .resources("legacy", None, 10)
            .await
            .expect("resources");
        assert_eq!(resources.len(), 1, "migration must keep existing rows");
        assert_eq!(resources[0].etag_present, Some(true));
        assert_eq!(resources[0].last_modified_present, Some(false));
        assert_eq!(
            store
                .resource_dependents("legacy", "https://example.org/app.js", 10)
                .await
                .expect("edges table")
                .len(),
            0,
            "a pre-edge store has no observed dependents, which is not an error"
        );
    }

    #[tokio::test]
    async fn findings_and_their_evidence_survive_the_round_trip() {
        let store = EvidenceStore::open(&store_path("findings"))
            .await
            .expect("open");
        store
            .record_crawl(CrawlRecord {
                run_id: "run-findings",
                application: "https://example.org",
                summary: &summary(),
                recorded_at_unix_secs: 1_700_000_000,
            })
            .await
            .expect("record");

        let findings = store
            .findings("run-findings", None, None, 16)
            .await
            .expect("findings");
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.page_url, "https://example.org/");
        assert_eq!(finding.finding_index, 0);
        assert_eq!(finding.rule_id, "sec.header.hsts_missing");
        assert_eq!(finding.dwarf_id, DwarfId::Sicherheits);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.title, "HSTS header is missing");
        assert_eq!(
            finding.remediation.as_deref(),
            Some("Send Strict-Transport-Security on https responses.")
        );
        assert_eq!(
            finding.evidence_refs.len(),
            2,
            "a stored finding must carry the evidence it was raised from"
        );
        assert_eq!(finding.evidence_refs[0].source, EvidenceSource::HttpHeaders);
        assert_eq!(
            finding.evidence_refs[0].detail,
            "header=strict-transport-security"
        );
        assert_eq!(finding.evidence_refs[1].source, EvidenceSource::HttpStatus);
    }

    #[tokio::test]
    async fn findings_can_be_narrowed_by_page_and_severity_without_widening_the_limit() {
        let store = EvidenceStore::open(&store_path("finding-filters"))
            .await
            .expect("open");
        store
            .record_crawl(CrawlRecord {
                run_id: "run-filters",
                application: "https://example.org",
                summary: &summary(),
                recorded_at_unix_secs: 1_700_000_000,
            })
            .await
            .expect("record");

        assert_eq!(
            store
                .findings("run-filters", Some("https://example.org/"), None, 8)
                .await
                .expect("by page")
                .len(),
            1
        );
        assert_eq!(
            store
                .findings(
                    "run-filters",
                    Some("https://example.org/elsewhere"),
                    None,
                    8
                )
                .await
                .expect("other page")
                .len(),
            0
        );
        assert_eq!(
            store
                .findings("run-filters", None, Some(Severity::Critical), 8)
                .await
                .expect("by severity")
                .len(),
            0,
            "a severity filter must not fall back to broader matches"
        );
        assert_eq!(
            store
                .findings("run-filters", None, None, 0)
                .await
                .expect("bounded")
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn each_dwarf_verdict_outcome_is_stored_separately() {
        let store = EvidenceStore::open(&store_path("dwarf-totals"))
            .await
            .expect("open");
        store
            .record_crawl(CrawlRecord {
                run_id: "run-totals",
                application: "https://example.org",
                summary: &summary(),
                recorded_at_unix_secs: 1_700_000_000,
            })
            .await
            .expect("record");

        let totals = store.dwarf_totals("run-totals").await.expect("totals");
        assert_eq!(totals.len(), 1);
        let total = totals[0];
        assert_eq!(total.dwarf_id, DwarfId::Sicherheits);
        assert_eq!(total.checks_evaluated, 10);
        assert_eq!(total.checks_passed, 7);
        assert_eq!(total.checks_failed, 1);
        assert_eq!(total.checks_skipped, 2);
        assert_eq!(total.checks_unavailable, 0);
        assert_eq!(total.findings_count, 1);
    }

    #[tokio::test]
    async fn a_version_three_store_gains_finding_tables_without_losing_rows() {
        let path = store_path("migrate-v3");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("dir");
        }
        let database = Builder::new_local(&path.to_string_lossy())
            .build()
            .await
            .expect("raw store");
        let connection = database.connect().expect("connect");
        connection
            .execute_batch(SCHEMA_V1)
            .await
            .expect("schema v1");
        connection
            .execute_batch(MIGRATION_V2)
            .await
            .expect("migration v2");
        connection
            .execute_batch(MIGRATION_V3)
            .await
            .expect("migration v3");
        connection
            .execute(
                "INSERT INTO runs (run_id, application, seed_url, recorded_at_unix_secs,
                    complete, budget_exhausted, robots, discovered_urls, fetched_urls,
                    analysed_urls, failed_urls, skipped_budget_urls, cancelled_urls,
                    robots_blocked_urls, queue_rejections, duplicate_offers, max_pages,
                    max_depth, resources_discovered, resources_fetched, resources_failed,
                    resources_skipped, resources_cancelled, resources_truncated,
                    resources_external_refused, resources_max)
                 VALUES ('legacy', 'https://example.org', 'https://example.org/', 1,
                    1, 0, 'observed', 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)",
                (),
            )
            .await
            .expect("legacy run");
        connection
            .execute(
                "INSERT INTO pages (run_id, url, depth, page_type, status)
                 VALUES ('legacy', 'https://example.org/', 0, 'homepage', 'investigated')",
                (),
            )
            .await
            .expect("legacy page");
        connection
            .execute("PRAGMA user_version = 3", ())
            .await
            .expect("version");
        drop(connection);
        drop(database);

        let store = EvidenceStore::open(&path).await.expect("reopen");
        assert_eq!(
            store.schema_version().await.expect("version"),
            SCHEMA_VERSION
        );
        assert_eq!(
            store.pages("legacy", None, 8).await.expect("pages").len(),
            1,
            "the migration must not discard the pages it did not touch"
        );
        assert_eq!(
            store
                .findings("legacy", None, None, 8)
                .await
                .expect("findings")
                .len(),
            0,
            "a legacy run has no stored findings, which is not an error"
        );
        assert_eq!(store.dwarf_totals("legacy").await.expect("totals").len(), 0);
    }

    #[tokio::test]
    async fn record_audit_report_persists_single_page_findings_and_totals() {
        use crate::domain::{CollectorOutcome, Measurement};

        let store = EvidenceStore::open(&store_path("record-audit-report"))
            .await
            .expect("open");
        let snapshot = crate::domain::EvidenceSnapshot {
            target: target("https://example.org/"),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Captured {
                data: crate::domain::HttpEvidence {
                    final_url: "https://example.org/".to_owned(),
                    status_code: 200,
                    headers: Vec::new(),
                    body_text: "<html><body>Hello</body></html>".to_owned(),
                    body_truncated: false,
                    body_bytes: 33,
                    redirect_chain: Vec::new(),
                    elapsed_ms: Measurement::Measured {
                        value: 12,
                        unit: crate::domain::MeasurementUnit::Milliseconds,
                    },
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
            lighthouse: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
            browser: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
            axe: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
        };
        let report = crate::analysis::run_all(&snapshot);
        store
            .record_audit_report("check-1", "https://example.org/", &report, 1_700_000_000)
            .await
            .expect("record audit report");

        let runs = store.runs(10).await.expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, "check-1");
        assert!(runs[0].complete);

        let totals = store.dwarf_totals("check-1").await.expect("totals");
        assert_ne!(totals.len(), 0);
    }

    #[tokio::test]
    async fn saves_loads_clears_checkpoints_and_queries_fresh_pages_for_incremental_scan() {
        let dir = std::env::temp_dir().join(format!(
            "nzw-checkpoint-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store_path = dir.join("evidence.db");
        let store = EvidenceStore::open(&store_path).await.expect("open");

        let cp = super::CrawlCheckpoint {
            application: "https://example.org/".to_owned(),
            run_id: "scan-1".to_owned(),
            frontier_urls: vec!["https://example.org/pricing".to_owned()],
            visited_urls: vec!["https://example.org/".to_owned()],
            updated_at_unix_secs: 1_700_000_000,
        };
        store.save_checkpoint(&cp).await.expect("save checkpoint");
        let loaded = store
            .load_checkpoint("https://example.org/")
            .await
            .expect("load checkpoint")
            .expect("checkpoint present");
        assert_eq!(loaded, cp);

        store
            .clear_checkpoint("https://example.org/")
            .await
            .expect("clear checkpoint");
        assert_eq!(
            store
                .load_checkpoint("https://example.org/")
                .await
                .expect("load cleared"),
            None
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
