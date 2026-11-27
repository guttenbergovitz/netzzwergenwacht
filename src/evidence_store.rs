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

use crate::discovery::{
    CrawlSummary, PageCrawlStatus, PageType, ResourceKind, ResourceObservation, ResourceStatus,
    RobotsOutcome, SystemicClassification,
};

/// Schema version this build creates and understands.
///
/// Migrations are forward-only: a store written by a newer build is refused
/// rather than partially understood.
pub const SCHEMA_VERSION: i64 = 1;

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
                        byte_len, truncated)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
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
                        "SELECT url, kind, status, http_status, content_type, byte_len, truncated
                         FROM resources WHERE run_id = ?1 AND kind = ?2 ORDER BY url ASC LIMIT ?3",
                        (run_id, resource_kind_label(kind), limit),
                    )
                    .await?,
                None => connection
                    .query(
                        "SELECT url, kind, status, http_status, content_type, byte_len, truncated
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
                content_encoding: None,
                cache_control: None,
                etag_present: false,
                last_modified_present: false,
                truncated: row.get::<i64>(6)? != 0,
                error: None,
            });
        }
        Ok(resources)
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
    connection
        .execute_batch(SCHEMA_V1)
        .await
        .map_err(StoreError::from)?;
    connection
        .execute(format!("PRAGMA user_version = {SCHEMA_VERSION}"), ())
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

fn bounded_limit(limit: usize) -> i64 {
    count(limit.clamp(1, MAX_READ_ROWS))
}

fn positive(row: &turso::Row, index: usize) -> Result<usize, StoreError> {
    let value = row.get::<i64>(index)?;
    usize::try_from(value).map_err(|_| unknown_value("non-negative count", &value.to_string()))
}

fn non_negative(row: &turso::Row, index: usize) -> Result<u64, StoreError> {
    let value = row.get::<i64>(index)?;
    u64::try_from(value).map_err(|_| unknown_value("non-negative integer", &value.to_string()))
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
        PageCrawlStatus::SkippedBudget => "skipped_budget",
        PageCrawlStatus::Unreachable => "unreachable",
    }
}

fn page_status_from_label(label: &str) -> Option<PageCrawlStatus> {
    match label {
        "investigated" => Some(PageCrawlStatus::Investigated),
        "partially_investigated" => Some(PageCrawlStatus::PartiallyInvestigated),
        "skipped_budget" => Some(PageCrawlStatus::SkippedBudget),
        "unreachable" => Some(PageCrawlStatus::Unreachable),
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
    use super::{CrawlRecord, EvidenceStore, SCHEMA_VERSION, StoreError};
    use crate::discovery::{
        CrawlCoverage, CrawlSummary, DiscoveredPage, PageCrawlStatus, PageType, ResourceCoverage,
        ResourceKind, ResourceObservation, ResourceStatus, RobotsOutcome, SystemicClassification,
        SystemicIssue,
    };
    use crate::domain::{AuditTarget, Confidence, RuleId, TargetPolicy};
    use std::path::PathBuf;

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
            etag_present: true,
            last_modified_present: false,
            truncated: false,
            error: None,
        }
    }

    fn summary() -> CrawlSummary {
        let coverage = CrawlCoverage {
            discovered_urls: 6,
            fetched_urls: 4,
            analysed_urls: 4,
            failed_urls: 1,
            skipped_budget_urls: 1,
            cancelled_urls: 0,
            robots_blocked_urls: 1,
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
            }],
            budget_exhausted: true,
            graph_results: Vec::new(),
            coverage,
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
}
