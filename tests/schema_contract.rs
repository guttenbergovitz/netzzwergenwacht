//! Schema and contract integration tests for `AuditReport`.

use netzzwergenwacht::analysis::{self, AuditReport, REPORT_SCHEMA_VERSION};
use netzzwergenwacht::domain::{
    AuditTarget, CollectorOutcome, EvidenceSnapshot, HttpEvidence, HttpHeader, Measurement,
    MeasurementUnit, TargetPolicy, TlsEvidence,
};
use schemars::schema_for;

#[test]
fn audit_report_generates_valid_json_schema_and_roundtrips() {
    let schema = schema_for!(AuditReport);
    let schema_json = serde_json::to_value(&schema).unwrap();
    assert_eq!(schema_json["title"], "AuditReport");
    assert!(schema_json["properties"]["schema_version"].is_object());
    assert!(schema_json["properties"]["analysers"].is_object());

    let target = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
    let html = format!(
        "<!doctype html><html lang=\"en-GB\"><head>\
         <title>NetzZwergenWacht Audit Engine</title>\
         <meta name=\"description\" content=\"Deterministic audit.\">\
         <link rel=\"canonical\" href=\"https://example.org/\">\
         </head><body><main><h1>Example</h1><p>{}</p></main></body></html>",
        vec!["word"; 120].join(" ")
    );

    let snapshot = EvidenceSnapshot {
        target,
        captured_at_unix_secs: 1_700_000_000,
        http: CollectorOutcome::Captured {
            data: HttpEvidence {
                final_url: "https://example.org/".to_owned(),
                status_code: 200,
                redirect_chain: Vec::new(),
                headers: vec![
                    HttpHeader {
                        name: "content-type".to_owned(),
                        value: "text/html; charset=utf-8".to_owned(),
                    },
                    HttpHeader {
                        name: "strict-transport-security".to_owned(),
                        value: "max-age=31536000".to_owned(),
                    },
                    HttpHeader {
                        name: "content-security-policy".to_owned(),
                        value: "default-src 'self'".to_owned(),
                    },
                    HttpHeader {
                        name: "x-content-type-options".to_owned(),
                        value: "nosniff".to_owned(),
                    },
                    HttpHeader {
                        name: "x-frame-options".to_owned(),
                        value: "DENY".to_owned(),
                    },
                    HttpHeader {
                        name: "referrer-policy".to_owned(),
                        value: "no-referrer".to_owned(),
                    },
                    HttpHeader {
                        name: "cache-control".to_owned(),
                        value: "max-age=60".to_owned(),
                    },
                    HttpHeader {
                        name: "last-modified".to_owned(),
                        value: "Tue, 24 Nov 2026 12:00:00 GMT".to_owned(),
                    },
                ],
                elapsed_ms: Measurement::Measured {
                    value: 42,
                    unit: MeasurementUnit::Milliseconds,
                },
                body_bytes: html.len(),
                body_truncated: false,
                body_text: html,
            },
        },
        tls: CollectorOutcome::Captured {
            data: TlsEvidence {
                subject: "CN=example.org".to_owned(),
                issuer: "CN=Example CA".to_owned(),
                not_after_unix_secs: 2_000_000_000,
                days_until_expiry: 120,
                ..TlsEvidence::default()
            },
        },
        browser: CollectorOutcome::default(),
        lighthouse: CollectorOutcome::default(),
        axe: CollectorOutcome::default(),
    };

    let report = analysis::run_all(&snapshot);
    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(report.analysers.len(), 9);

    let json = serde_json::to_string(&report).unwrap();
    let decoded: AuditReport = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, report);
}
