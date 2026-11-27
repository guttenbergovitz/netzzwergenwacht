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
