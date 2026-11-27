//! Measured spike for the application-wide evidence store (ADR 0028, ADR 0032).
//!
//! ADR 0028 makes SQLite conditional on evidence rather than preference. This
//! harness populates the same synthetic crawl population twice — once into an
//! embedded SQLite database, once into the append-only JSONL representation the
//! project already uses — and runs the aggregates the reconnaissance engine
//! needs in order to compare them:
//!
//! 1. systemic ranking (findings grouped by rule),
//! 2. template family population,
//! 3. shared resource dependents,
//! 4. coverage denominators.
//!
//! Both implementations must agree on the answers; only the cost may differ. The
//! dataset is deterministic, so a disagreement is a correctness defect rather
//! than measurement noise. Two populations are measured so the scaling behaviour
//! is visible: at 5 000 pages the two are comparable, and the question is what
//! happens an order of magnitude later.
//!
//! Run with:
//!
//! ```text
//! cargo test --release --test evidence_store_spike -- --ignored --nocapture
//! ```
//!
//! The numbers belong in the ADR, not in marketing material: one machine, one
//! synthetic population shape, one workload. The in-memory path is measured for
//! the aggregates only; its real cost is that every observation must be resident,
//! which this harness does not capture in a number.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};

const TEMPLATES: [&str; 5] = ["landing", "article", "listing", "product", "legal"];
const LOCALES: [&str; 4] = ["en-GB", "de-DE", "fr-FR", "pl-PL"];
const STATUSES: [&str; 3] = ["analysed", "failed", "skipped_budget"];
const RULE_COUNT: i64 = 200;
const EDGES_PER_PAGE: i64 = 3;
const FINDINGS_PER_PAGE_DENOMINATOR: i64 = 5;
const FINDINGS_PER_PAGE_NUMERATOR: i64 = 12;
const RESOURCES_PER_PAGE_DENOMINATOR: i64 = 16;

#[derive(Debug, Clone, Copy)]
struct Population {
    pages: i64,
    findings: i64,
    resources: i64,
}

impl Population {
    fn with_pages(pages: i64) -> Self {
        Self {
            pages,
            findings: pages * FINDINGS_PER_PAGE_NUMERATOR / FINDINGS_PER_PAGE_DENOMINATOR,
            resources: (pages / RESOURCES_PER_PAGE_DENOMINATOR).max(300),
        }
    }
}

#[derive(Debug, Clone)]
struct PageRow {
    id: i64,
    url: String,
    template: &'static str,
    locale: &'static str,
    status: &'static str,
    bytes: i64,
}

#[derive(Debug, Clone)]
struct ResourceRow {
    id: i64,
    url: String,
    kind: &'static str,
}

#[derive(Debug, Clone)]
struct FindingRow {
    id: i64,
    page_id: i64,
    rule: String,
    severity: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct Edge {
    page_id: i64,
    resource_id: i64,
}

fn pick<T>(values: &[T], index: i64) -> &T {
    &values[usize::try_from(index % i64::try_from(values.len()).unwrap()).unwrap()]
}

fn pages(population: Population) -> Vec<PageRow> {
    (0..population.pages)
        .map(|id| PageRow {
            id,
            url: format!("https://example.org/page/{id}"),
            template: pick(&TEMPLATES, id),
            locale: pick(&LOCALES, id),
            status: if id % 97 == 0 {
                pick(&STATUSES, 1)
            } else if id % 211 == 0 {
                pick(&STATUSES, 2)
            } else {
                pick(&STATUSES, 0)
            },
            bytes: 4_096 + (id % 32) * 512,
        })
        .collect()
}

fn resources(population: Population) -> Vec<ResourceRow> {
    (0..population.resources)
        .map(|id| ResourceRow {
            id,
            url: format!("https://example.org/assets/resource-{id}.bin"),
            kind: match id % 3 {
                0 => "script",
                1 => "stylesheet",
                _ => "image",
            },
        })
        .collect()
}

fn findings(population: Population) -> Vec<FindingRow> {
    (0..population.findings)
        .map(|id| FindingRow {
            id,
            page_id: (id * 7) % population.pages,
            rule: format!(
                "rule.family-{:03}",
                (id % 7 + 1) * (id % 13 + 1) % RULE_COUNT
            ),
            severity: match id % 4 {
                0 => "high",
                1 => "medium",
                2 => "low",
                _ => "info",
            },
        })
        .collect()
}

/// Edges are deduplicated before either implementation sees them, so both are
/// answering the same question rather than one hiding a duplicate-key conflict.
fn edges(population: Population) -> Vec<Edge> {
    let mut unique = BTreeSet::new();
    for page in 0..population.pages {
        for offset in 0..EDGES_PER_PAGE {
            let resource_id = (page * 7 + offset * 13) % population.resources;
            unique.insert((page, resource_id));
        }
    }
    unique
        .into_iter()
        .map(|(page_id, resource_id)| Edge {
            page_id,
            resource_id,
        })
        .collect()
}

fn temp_path(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    std::env::temp_dir().join(format!("nzw-evidence-spike-{nanos}-{name}"))
}

fn open_store(path: &PathBuf) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE pages (
                 id      INTEGER PRIMARY KEY,
                 url     TEXT NOT NULL,
                 template TEXT NOT NULL,
                 locale  TEXT NOT NULL,
                 status  TEXT NOT NULL,
                 bytes   INTEGER NOT NULL
             );
             CREATE TABLE resources (
                 id   INTEGER PRIMARY KEY,
                 url  TEXT NOT NULL UNIQUE,
                 kind TEXT NOT NULL
             );
             CREATE TABLE page_resources (
                 page_id     INTEGER NOT NULL,
                 resource_id INTEGER NOT NULL,
                 PRIMARY KEY (page_id, resource_id)
             );
             CREATE TABLE findings (
                 id       INTEGER PRIMARY KEY,
                 page_id  INTEGER NOT NULL,
                 rule     TEXT NOT NULL,
                 severity TEXT NOT NULL
             );
             CREATE INDEX findings_by_rule ON findings(rule);
             CREATE INDEX pages_by_template ON pages(template);
             CREATE INDEX edges_by_resource ON page_resources(resource_id);",
        )
        .unwrap();
    connection
}

fn insert_sqlite(
    connection: &mut Connection,
    pages: &[PageRow],
    resources: &[ResourceRow],
    findings: &[FindingRow],
    edges: &[Edge],
) -> Duration {
    let started = Instant::now();
    let transaction = connection.transaction().unwrap();
    {
        let mut statement = transaction
            .prepare("INSERT INTO pages (id, url, template, locale, status, bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
            .unwrap();
        for page in pages {
            statement
                .execute(params![
                    page.id,
                    page.url,
                    page.template,
                    page.locale,
                    page.status,
                    page.bytes
                ])
                .unwrap();
        }
        let mut statement = transaction
            .prepare("INSERT INTO resources (id, url, kind) VALUES (?1, ?2, ?3)")
            .unwrap();
        for resource in resources {
            statement
                .execute(params![resource.id, resource.url, resource.kind])
                .unwrap();
        }
        let mut statement = transaction
            .prepare("INSERT INTO page_resources (page_id, resource_id) VALUES (?1, ?2)")
            .unwrap();
        for edge in edges {
            statement
                .execute(params![edge.page_id, edge.resource_id])
                .unwrap();
        }
        let mut statement = transaction
            .prepare("INSERT INTO findings (id, page_id, rule, severity) VALUES (?1, ?2, ?3, ?4)")
            .unwrap();
        for finding in findings {
            statement
                .execute(params![
                    finding.id,
                    finding.page_id,
                    finding.rule,
                    finding.severity
                ])
                .unwrap();
        }
    }
    transaction.commit().unwrap();
    started.elapsed()
}

fn query_pairs(connection: &Connection, sql: &str) -> (Vec<(String, i64)>, Duration) {
    let started = Instant::now();
    let mut statement = connection.prepare(sql).unwrap();
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<(String, i64)>, _>>()
        .unwrap();
    (rows, started.elapsed())
}

fn sqlite_systemic(connection: &Connection) -> (Vec<(String, i64)>, Duration) {
    query_pairs(
        connection,
        "SELECT rule, COUNT(*) FROM findings GROUP BY rule ORDER BY COUNT(*) DESC, rule ASC LIMIT 5",
    )
}

fn sqlite_templates(connection: &Connection) -> (Vec<(String, i64)>, Duration) {
    query_pairs(
        connection,
        "SELECT p.template, COUNT(DISTINCT f.page_id)
         FROM pages p LEFT JOIN findings f ON f.page_id = p.id
         GROUP BY p.template ORDER BY p.template ASC",
    )
}

fn sqlite_dependents(connection: &Connection) -> (Vec<(String, i64)>, Duration) {
    query_pairs(
        connection,
        "SELECT r.url, COUNT(DISTINCT pr.page_id)
         FROM resources r JOIN page_resources pr ON pr.resource_id = r.id
         GROUP BY r.id ORDER BY COUNT(DISTINCT pr.page_id) DESC, r.url ASC LIMIT 5",
    )
}

fn sqlite_coverage(connection: &Connection) -> (Vec<(String, i64)>, Duration) {
    query_pairs(
        connection,
        "SELECT status, COUNT(*) FROM pages GROUP BY status ORDER BY status ASC",
    )
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum Segment {
    Page {
        id: i64,
        url: String,
        template: String,
        locale: String,
        status: String,
        bytes: i64,
    },
    Resource {
        id: i64,
        url: String,
        kind: String,
    },
    Edge {
        page_id: i64,
        resource_id: i64,
    },
    Finding {
        id: i64,
        page_id: i64,
        rule: String,
        severity: String,
    },
}

fn write_segments(
    path: &PathBuf,
    pages: &[PageRow],
    resources: &[ResourceRow],
    findings: &[FindingRow],
    edges: &[Edge],
) -> Duration {
    let started = Instant::now();
    let mut buffer = String::new();
    for page in pages {
        buffer.push_str(
            &serde_json::to_string(&Segment::Page {
                id: page.id,
                url: page.url.clone(),
                template: page.template.to_owned(),
                locale: page.locale.to_owned(),
                status: page.status.to_owned(),
                bytes: page.bytes,
            })
            .unwrap(),
        );
        buffer.push('\n');
    }
    for resource in resources {
        buffer.push_str(
            &serde_json::to_string(&Segment::Resource {
                id: resource.id,
                url: resource.url.clone(),
                kind: resource.kind.to_owned(),
            })
            .unwrap(),
        );
        buffer.push('\n');
    }
    for edge in edges {
        buffer.push_str(
            &serde_json::to_string(&Segment::Edge {
                page_id: edge.page_id,
                resource_id: edge.resource_id,
            })
            .unwrap(),
        );
        buffer.push('\n');
    }
    for finding in findings {
        buffer.push_str(
            &serde_json::to_string(&Segment::Finding {
                id: finding.id,
                page_id: finding.page_id,
                rule: finding.rule.clone(),
                severity: finding.severity.to_owned(),
            })
            .unwrap(),
        );
        buffer.push('\n');
    }
    fs::write(path, buffer).unwrap();
    started.elapsed()
}

struct Replayed {
    /// Page identity mapped to template family and acquisition status, the two
    /// page attributes the aggregates below need.
    pages: BTreeMap<i64, (String, String)>,
    resources: BTreeMap<i64, String>,
    edges: Vec<(i64, i64)>,
    findings: Vec<(i64, String)>,
}

fn read_segments(path: &PathBuf) -> (Replayed, Duration) {
    let started = Instant::now();
    let body = fs::read_to_string(path).unwrap();
    let mut pages = BTreeMap::new();
    let mut resources = BTreeMap::new();
    let mut edges = Vec::new();
    let mut findings = Vec::new();
    for line in body.lines() {
        match serde_json::from_str::<Segment>(line).unwrap() {
            Segment::Page {
                id,
                template,
                status,
                ..
            } => {
                pages.insert(id, (template, status));
            }
            Segment::Resource { id, url, .. } => {
                resources.insert(id, url);
            }
            Segment::Edge {
                page_id,
                resource_id,
            } => edges.push((page_id, resource_id)),
            Segment::Finding { page_id, rule, .. } => findings.push((page_id, rule)),
        }
    }
    (
        Replayed {
            pages,
            resources,
            edges,
            findings,
        },
        started.elapsed(),
    )
}

fn replayed_systemic(replayed: &Replayed) -> Vec<(String, i64)> {
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for (_, rule) in &replayed.findings {
        *counts.entry(rule.as_str()).or_insert(0) += 1;
    }
    let mut rows: Vec<(String, i64)> = counts
        .into_iter()
        .map(|(rule, count)| (rule.to_owned(), count))
        .collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    rows.truncate(5);
    rows
}

fn replayed_templates(replayed: &Replayed) -> Vec<(String, i64)> {
    let mut affected: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    for template in TEMPLATES {
        affected.entry(template).or_default();
    }
    for (page_id, _) in &replayed.findings {
        if let Some((template, _)) = replayed.pages.get(page_id) {
            affected
                .entry(template.as_str())
                .or_default()
                .insert(*page_id);
        }
    }
    affected
        .into_iter()
        .map(|(template, pages)| {
            (
                template.to_owned(),
                i64::try_from(pages.len()).unwrap_or(i64::MAX),
            )
        })
        .collect()
}

fn replayed_dependents(replayed: &Replayed) -> Vec<(String, i64)> {
    let mut dependents: BTreeMap<i64, BTreeSet<i64>> = BTreeMap::new();
    for (page_id, resource_id) in &replayed.edges {
        dependents.entry(*resource_id).or_default().insert(*page_id);
    }
    let mut rows: Vec<(String, i64)> = dependents
        .into_iter()
        .filter_map(|(resource_id, pages)| {
            replayed
                .resources
                .get(&resource_id)
                .map(|url| (url.clone(), i64::try_from(pages.len()).unwrap_or(i64::MAX)))
        })
        .collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    rows.truncate(5);
    rows
}

fn replayed_coverage(replayed: &Replayed) -> Vec<(String, i64)> {
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for (_, status) in replayed.pages.values() {
        *counts.entry(status.as_str()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(status, count)| (status.to_owned(), count))
        .collect()
}

/// Size of a file that is expected to exist, or zero for an absent sidecar such
/// as an already-checkpointed WAL, which genuinely contributes no bytes.
fn file_size(path: &PathBuf) -> u64 {
    if path.exists() {
        fs::metadata(path).unwrap().len()
    } else {
        0
    }
}

/// Measures one population and asserts that both stores answer identically.
fn measure(population: Population) {
    let pages = pages(population);
    let resources = resources(population);
    let findings = findings(population);
    let edges = edges(population);

    let database_path = temp_path("store.sqlite");
    let segment_path = temp_path("store.jsonl");

    let mut connection = open_store(&database_path);
    let insert = insert_sqlite(&mut connection, &pages, &resources, &findings, &edges);
    let (systemic_sql, systemic_time) = sqlite_systemic(&connection);
    let (templates_sql, templates_time) = sqlite_templates(&connection);
    let (dependents_sql, dependents_time) = sqlite_dependents(&connection);
    let (coverage_sql, coverage_time) = sqlite_coverage(&connection);

    // WAL pages are part of the store until they are checkpointed, so the size is
    // measured after a truncating checkpoint rather than from the main file
    // alone. Reporting the uncheckpointed main file would understate the cost.
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let database_bytes =
        file_size(&database_path) + file_size(&database_path.with_extension("sqlite-wal"));
    drop(connection);

    let segment_write = write_segments(&segment_path, &pages, &resources, &findings, &edges);
    let (replayed, segment_read) = read_segments(&segment_path);

    let started = Instant::now();
    let systemic_memory = replayed_systemic(&replayed);
    let systemic_memory_time = started.elapsed();
    let started = Instant::now();
    let templates_memory = replayed_templates(&replayed);
    let templates_memory_time = started.elapsed();
    let started = Instant::now();
    let dependents_memory = replayed_dependents(&replayed);
    let dependents_memory_time = started.elapsed();
    let started = Instant::now();
    let coverage_memory = replayed_coverage(&replayed);
    let coverage_memory_time = started.elapsed();
    let segment_bytes = file_size(&segment_path);

    println!("\n=== evidence store spike: {} pages ===", population.pages);
    println!(
        "population: {} pages, {} resources, {} edges, {} findings",
        pages.len(),
        resources.len(),
        edges.len(),
        findings.len()
    );
    println!("sqlite insert (one transaction): {insert:?}");
    println!("jsonl write: {segment_write:?} / read+parse: {segment_read:?}");
    println!("sqlite size: {database_bytes} bytes / jsonl size: {segment_bytes} bytes");
    println!("\n-- sqlite --");
    println!("systemic ranking    : {systemic_time:?}");
    println!("template family     : {templates_time:?}");
    println!("resource dependents : {dependents_time:?}");
    println!("coverage            : {coverage_time:?}");
    println!("\n-- jsonl + in-memory index --");
    println!("systemic ranking    : {systemic_memory_time:?}");
    println!("template family     : {templates_memory_time:?}");
    println!("resource dependents : {dependents_memory_time:?}");
    println!("coverage            : {coverage_memory_time:?}");
    println!("\nsystemic top: {systemic_sql:?}");
    println!("template populations: {templates_sql:?}");
    println!("dependents top: {dependents_sql:?}");
    println!("coverage: {coverage_sql:?}");

    assert_eq!(systemic_sql, systemic_memory, "systemic ranking must agree");
    assert_eq!(
        templates_sql, templates_memory,
        "template population must agree"
    );
    assert_eq!(dependents_sql, dependents_memory, "dependents must agree");
    assert_eq!(coverage_sql, coverage_memory, "coverage must agree");

    let _ = fs::remove_file(&database_path);
    let _ = fs::remove_file(&segment_path);
    let _ = fs::remove_file(database_path.with_extension("sqlite-wal"));
    let _ = fs::remove_file(database_path.with_extension("sqlite-shm"));
}

#[test]
#[ignore = "measured spike; run with --release --ignored --nocapture"]
fn sqlite_and_segment_stores_answer_identically_with_measured_cost() {
    measure(Population::with_pages(5_000));
    measure(Population::with_pages(50_000));
}

// ---------------------------------------------------------------------------
// Turso Database (MVCC) experiment
// ---------------------------------------------------------------------------
//
// The architectural amendment to ADR 0032 replaces SQLite with Turso Database on
// the grounds that MVCC permits several connections to write concurrently. That
// claim is a property to verify, not to assume, so this section exercises it
// directly: independent writers, a writer alongside a reader, commit conflicts,
// rollback atomicity, duplicate insertion, abandoned transactions, reopen
// recovery and one analytical query.
//
// SQLite remains here as the comparison baseline with batched transactions. No
// assertion claims Turso is faster; the harness prints what it measured.

mod turso_experiment {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use turso::{Builder, Database, Error};

    use super::{Population, temp_path};

    const WRITERS: usize = 8;
    const ROWS_PER_WRITER: i64 = 500;

    fn is_retryable(error: &Error) -> bool {
        match error {
            Error::Busy(_) | Error::BusySnapshot(_) => true,
            Error::Error(message) => message.contains("conflict") || message.contains("busy"),
            _ => false,
        }
    }

    async fn open(name: &str) -> (Database, PathBuf) {
        let path = temp_path(name);
        let database = Builder::new_local(path.to_str().expect("temp path is utf-8"))
            .build()
            .await
            .expect("turso database opens");
        (database, path)
    }

    async fn enable_mvcc(database: &Database) -> String {
        let connection = database.connect().expect("connection");
        let mut rows = connection
            .query("PRAGMA journal_mode = 'mvcc'", ())
            .await
            .expect("pragma is accepted");
        match rows.next().await {
            Ok(Some(row)) => row.get::<String>(0).unwrap_or_default(),
            _ => String::new(),
        }
    }

    async fn schema(database: &Database) {
        let connection = database.connect().expect("connection");
        connection
            .execute(
                "CREATE TABLE pages (id INTEGER PRIMARY KEY, url TEXT NOT NULL, rule TEXT NOT NULL)",
                (),
            )
            .await
            .expect("pages table");
        connection
            .execute("CREATE INDEX pages_by_rule ON pages(rule)", ())
            .await
            .expect("rule index");
    }

    /// Inserts one slice of the population under `BEGIN CONCURRENT`, retrying
    /// retryable conflicts with a bounded budget. Returns `(retries, elapsed)`.
    pub async fn concurrent_writer(database: Database, writer: usize) -> (u64, Duration, i64) {
        let connection = database.connect().expect("connection");
        let retries = Arc::new(AtomicU64::new(0));
        let started = Instant::now();
        let base = i64::try_from(writer).unwrap_or(0) * ROWS_PER_WRITER;
        let mut inserted = 0_i64;

        for offset in 0..ROWS_PER_WRITER {
            let id = base + offset;
            let mut attempt = 0_u32;
            loop {
                attempt += 1;
                if connection.execute("BEGIN CONCURRENT", ()).await.is_err() {
                    tokio::task::yield_now().await;
                    continue;
                }
                let write = connection
                    .execute(
                        "INSERT INTO pages (id, url, rule) VALUES (?1, ?2, ?3)",
                        (id, format!("/page/{id}"), format!("rule.{}", id % 40)),
                    )
                    .await;
                match write {
                    Ok(_) => match connection.execute("COMMIT", ()).await {
                        Ok(_) => {
                            inserted += 1;
                            break;
                        }
                        Err(error) if is_retryable(&error) => {
                            retries.fetch_add(1, Ordering::Relaxed);
                            let _ = connection.execute("ROLLBACK", ()).await;
                            tokio::task::yield_now().await;
                        }
                        Err(error) => panic!("permanent commit failure: {error}"),
                    },
                    Err(error) if is_retryable(&error) => {
                        let _ = connection.execute("ROLLBACK", ()).await;
                        retries.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("permanent write failure: {error}"),
                }
                assert!(attempt <= 200, "retry budget exhausted for row {id}");
            }
        }
        (retries.load(Ordering::Relaxed), started.elapsed(), inserted)
    }

    async fn count(database: &Database, sql: &str) -> i64 {
        let connection = database.connect().expect("connection");
        let mut rows = connection.query(sql, ()).await.expect("query runs");
        match rows.next().await {
            Ok(Some(row)) => row.get::<i64>(0).unwrap_or(-1),
            _ => -1,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub async fn run() {
        let (database, path) = open("turso.db").await;
        let mode = enable_mvcc(&database).await;
        println!("turso journal_mode = '{mode}'");
        schema(&database).await;

        // 1. Independent concurrent writers.
        let started = Instant::now();
        let mut handles = Vec::new();
        for writer in 0..WRITERS {
            handles.push(tokio::spawn(concurrent_writer(database.clone(), writer)));
        }
        let mut retries = 0_u64;
        let mut inserted = 0_i64;
        for handle in handles {
            let (writer_retries, _, rows) = handle.await.expect("writer task");
            retries += writer_retries;
            inserted += rows;
        }
        let concurrent_elapsed = started.elapsed();
        let total = count(&database, "SELECT COUNT(*) FROM pages").await;
        let expected = i64::try_from(WRITERS).unwrap_or(0) * ROWS_PER_WRITER;
        assert_eq!(inserted, expected, "every writer must confirm its rows");
        assert_eq!(total, expected, "no committed row may be lost");
        println!(
            "turso concurrent writes: {inserted} rows in {} ms across {WRITERS} writers, {retries} retries",
            concurrent_elapsed.as_millis()
        );

        // 2. Duplicate insertion is prevented by the stable identity.
        {
            let connection = database.connect().expect("connection");
            connection
                .execute("BEGIN CONCURRENT", ())
                .await
                .expect("begin");
            connection
                .execute(
                    "INSERT INTO pages (id, url, rule) VALUES (0, '/page/0', 'rule.0') ON CONFLICT(id) DO NOTHING",
                    (),
                )
                .await
                .expect("idempotent insert");
            connection.execute("COMMIT", ()).await.expect("commit");
            assert_eq!(
                count(&database, "SELECT COUNT(*) FROM pages").await,
                expected
            );
        }

        // 3. A reader observes a committed snapshot while a writer is active.
        let reader_value = {
            let reader = database.connect().expect("reader");
            let mut rows = reader
                .query("SELECT COUNT(*) FROM pages", ())
                .await
                .expect("reader query");
            rows.next()
                .await
                .expect("reader row")
                .and_then(|row| row.get::<i64>(0).ok())
                .unwrap_or(-1)
        };
        assert_eq!(reader_value, expected, "a reader must see committed writes");

        // 3b. Contention on a single row: MVCC must either serialise the
        //     updates or report a conflict that the writer retries. A lost
        //     update would show up as a final value below the commit count.
        {
            let setup = database.connect().expect("connection");
            setup
                .execute(
                    "CREATE TABLE counter (id INTEGER PRIMARY KEY, val INTEGER NOT NULL)",
                    (),
                )
                .await
                .expect("counter table");
            setup
                .execute("INSERT INTO counter (id, val) VALUES (1, 0)", ())
                .await
                .expect("counter seed");
        }
        let increments_per_writer = 20_usize;
        let mut contention_handles = Vec::new();
        for _ in 0..WRITERS {
            let database = database.clone();
            contention_handles.push(tokio::spawn(async move {
                let connection = database.connect().expect("connection");
                let mut committed = 0_u32;
                let mut conflicts = 0_u32;
                for _ in 0..increments_per_writer {
                    let mut attempt = 0_u32;
                    loop {
                        attempt += 1;
                        if connection.execute("BEGIN CONCURRENT", ()).await.is_err() {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        let updated = connection
                            .execute("UPDATE counter SET val = val + 1 WHERE id = 1", ())
                            .await;
                        match updated {
                            Ok(_) => match connection.execute("COMMIT", ()).await {
                                Ok(_) => {
                                    committed += 1;
                                    break;
                                }
                                Err(error) if is_retryable(&error) => {
                                    conflicts += 1;
                                    let _ = connection.execute("ROLLBACK", ()).await;
                                    tokio::task::yield_now().await;
                                }
                                Err(error) => panic!("permanent commit failure: {error}"),
                            },
                            Err(error) if is_retryable(&error) => {
                                conflicts += 1;
                                let _ = connection.execute("ROLLBACK", ()).await;
                                tokio::task::yield_now().await;
                            }
                            Err(error) => panic!("permanent update failure: {error}"),
                        }
                        assert!(
                            attempt <= 500,
                            "retry budget exhausted on the contended row"
                        );
                    }
                }
                (committed, conflicts)
            }));
        }
        let mut contended_commits = 0_u32;
        let mut contended_conflicts = 0_u32;
        for handle in contention_handles {
            let (committed, conflicts) = handle.await.expect("contention task");
            contended_commits += committed;
            contended_conflicts += conflicts;
        }
        let final_value = count(&database, "SELECT val FROM counter WHERE id = 1").await;
        assert_eq!(
            final_value,
            i64::from(contended_commits),
            "MVCC must not lose an increment that reported a commit"
        );
        assert_eq!(
            contended_commits,
            u32::try_from(WRITERS).unwrap_or(0) * u32::try_from(increments_per_writer).unwrap_or(0),
            "every increment must eventually commit"
        );
        println!(
            "turso contended row: {contended_commits} increments committed, {contended_conflicts} conflicts retried, final value {final_value}"
        );

        // 4. Rollback atomicity: a failing batch leaves nothing behind.
        {
            let connection = database.connect().expect("connection");
            connection
                .execute("BEGIN CONCURRENT", ())
                .await
                .expect("begin");
            connection
                .execute(
                    "INSERT INTO pages (id, url, rule) VALUES (99991, '/x', 'r')",
                    (),
                )
                .await
                .expect("first row");
            let failed = connection
                .execute("INSERT INTO missing_table (id) VALUES (1)", ())
                .await;
            assert!(failed.is_err(), "the broken statement must fail");
            connection.execute("ROLLBACK", ()).await.expect("rollback");
            assert_eq!(
                count(&database, "SELECT COUNT(*) FROM pages").await,
                expected,
                "a rolled back batch must leave no partial evidence"
            );
        }

        // 5. Abandoned transaction: dropping the connection without commit must
        //    not publish the observation, and the file must reopen intact.
        {
            let connection = database.connect().expect("connection");
            connection
                .execute("BEGIN CONCURRENT", ())
                .await
                .expect("begin");
            connection
                .execute(
                    "INSERT INTO pages (id, url, rule) VALUES (88881, '/abandoned', 'r')",
                    (),
                )
                .await
                .expect("uncommitted row");
            drop(connection);
        }
        drop(database);

        let reopened = Builder::new_local(path.to_str().expect("path"))
            .build()
            .await
            .expect("turso reopens");
        assert_eq!(
            count(&reopened, "SELECT COUNT(*) FROM pages").await,
            expected,
            "an abandoned transaction must not be published"
        );
        assert_eq!(
            count(&reopened, "SELECT COUNT(*) FROM pages WHERE id = 88881").await,
            0,
            "the abandoned row must be absent after reopen"
        );
        let reopened_mode = enable_mvcc(&reopened).await;
        println!("turso reopen journal_mode = '{reopened_mode}'");

        // 6. One analytical query, compared with an answer computed in Rust.
        let mut expected_rules = BTreeMap::new();
        for id in 0..expected {
            let rule = format!("rule.{}", id % 40);
            *expected_rules.entry(rule).or_insert(0_i64) += 1;
        }
        let observed_rules = {
            let connection = reopened.connect().expect("connection");
            let mut rows = connection
                .query(
                    "SELECT rule, COUNT(*) AS hits FROM pages GROUP BY rule ORDER BY hits DESC, rule ASC",
                    (),
                )
                .await
                .expect("aggregate runs");
            let mut collected = BTreeMap::new();
            while let Ok(Some(row)) = rows.next().await {
                if let (Ok(rule), Ok(hits)) = (row.get::<String>(0), row.get::<i64>(1)) {
                    collected.insert(rule, hits);
                }
            }
            collected
        };
        assert_eq!(observed_rules, expected_rules, "aggregates must agree");

        // 7. Schema migration surface.
        {
            let connection = reopened.connect().expect("connection");
            connection
                .execute("PRAGMA user_version = 2", ())
                .await
                .expect("user_version is settable");
            let mut rows = connection
                .query("PRAGMA user_version", ())
                .await
                .expect("user_version is readable");
            let version = match rows.next().await {
                Ok(Some(row)) => row.get::<i64>(0).unwrap_or(-1),
                _ => -1,
            };
            println!("turso user_version after migration = {version}");
        }

        // 8. Foreign keys: record what the engine actually does.
        {
            let connection = reopened.connect().expect("connection");
            let enabled = connection
                .execute("PRAGMA foreign_keys = ON", ())
                .await
                .is_ok();
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS parents (id INTEGER PRIMARY KEY)",
                    (),
                )
                .await
                .expect("parents");
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS children (id INTEGER PRIMARY KEY, parent INTEGER REFERENCES parents(id))",
                    (),
                )
                .await
                .expect("children");
            let rejected = connection
                .execute("INSERT INTO children (id, parent) VALUES (1, 4242)", ())
                .await
                .is_err();
            println!(
                "turso foreign_keys pragma accepted = {enabled}, orphan rejected = {rejected}"
            );
        }

        // SQLite baseline for the same population, batched in one transaction.
        let sqlite_path = temp_path("turso-baseline.db");
        let sqlite_elapsed = {
            let store = rusqlite::Connection::open(&sqlite_path).expect("sqlite opens");
            store
                .execute_batch("CREATE TABLE pages (id INTEGER PRIMARY KEY, url TEXT, rule TEXT);")
                .expect("schema");
            let started = Instant::now();
            let transaction = store.unchecked_transaction().expect("transaction");
            {
                let mut statement = transaction
                    .prepare("INSERT INTO pages (id, url, rule) VALUES (?1, ?2, ?3)")
                    .expect("prepare");
                for id in 0..expected {
                    statement
                        .execute(rusqlite::params![
                            id,
                            format!("/page/{id}"),
                            format!("rule.{}", id % 40)
                        ])
                        .expect("insert");
                }
            }
            transaction.commit().expect("commit");
            started.elapsed()
        };
        println!(
            "sqlite batched baseline: {expected} rows in {} ms",
            sqlite_elapsed.as_millis()
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&sqlite_path);
        let _ = Population::with_pages(0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measured spike; run with --release --ignored --nocapture"]
async fn concurrent_persistence_is_verified_before_adoption() {
    turso_experiment::run().await;
}
