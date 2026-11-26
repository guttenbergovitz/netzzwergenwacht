//! Live Chromium integration tests verifying Operation Aufrüstung IV sensory collectors
//! against a controlled loopback fixture with known ground truth.

use std::time::Duration;

use netzzwergenwacht::adapters::browser::run_browser_with_policy;
use netzzwergenwacht::domain::{
    AuditTarget, CollectorOutcome, EvidenceSnapshot, FunctionalComponentKind,
    InteractionSafetyClass, StructuredDataSyntax, TargetPolicy,
};
use netzzwergenwacht::investigation::{
    AccessibilityNodeFilter, CookieStorageFilter, ElementGeometryFilter, EvidenceQueryStatus,
    InteractionTraceFilter, InteractiveElementFilter, LinkGraphFilter, MediaFontFilter,
    ResponsiveAnomalyFilter, StructuredDataFilter, query_accessibility_nodes,
    query_application_state, query_element_geometry, query_indexability_authority,
    query_interaction_trace, query_interactive_elements, query_link_graph, query_media_and_fonts,
    query_performance_attribution, query_responsive_comparison, query_security_challenge,
    query_security_posture, query_service_worker_lifecycle, query_storage_and_cookies,
    query_structured_data, query_visual_artifacts,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SENSORY_FIXTURE_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sensory Ground Truth Shop</title>
  <link rel="canonical" href="/sensory-page">
  <link rel="alternate" hreflang="en" href="/sensory-page">
  <link rel="alternate" hreflang="de" href="/de/sensory-page">
  <link rel="manifest" href="/manifest.json">
  <meta property="og:title" content="Sensory Ground Truth Shop">
  <meta property="og:description" content="Precision fixture for sensory collector verification.">
  <meta property="og:image" content="/hero.svg">
  <meta property="og:url" content="/sensory-page">
  <meta property="og:type" content="website">
  <meta name="twitter:card" content="summary_large_image">
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "Precision Chronometer",
    "offers": { "@type": "Offer", "price": "199.00" }
  }
  </script>
  <style>
    body { margin: 0; font-family: sans-serif; }
    header, nav, main, footer { padding: 16px; }
    .overflow-box {
      width: 140px;
      height: 40px;
      overflow-x: hidden;
      white-space: nowrap;
    }
    .wide-mobile-banner {
      width: 620px;
      height: 36px;
      background: #eee;
    }
  </style>
</head>
<body>
  <header>
    <nav aria-label="Primary">
      <a id="nav-home" href="/sensory-page">Home</a>
      <a id="nav-catalog" href="/catalog">Catalogue</a>
    </nav>
  </header>
  <main>
    <h1 id="hero-heading">Precision Chronometer</h1>
    <p>Engineered for deterministic reliability verification across desktop and mobile viewports.</p>
    <svg id="hero-graphic" width="240" height="120" role="img" aria-label="Chronometer Diagram">
      <rect width="240" height="120" fill="#224466" />
    </svg>
    <div id="clipped-card" class="overflow-box">
      This specification line intentionally exceeds the 140px container width so horizontal clipping is measured.
    </div>
    <div class="wide-mobile-banner">Wide banner causing mobile horizontal overflow</div>
    <details id="specs-accordion">
      <summary id="specs-toggle">Technical Specifications</summary>
      <p> Titanium housing, sapphire crystal, 10 bar water resistance.</p>
    </details>
    <form id="order-form" method="POST" action="/checkout">
      <label for="qty-input">Quantity</label>
      <input id="qty-input" name="quantity" type="number" required value="1">
      <button id="buy-now-btn" type="submit">Buy Now</button>
    </form>
    <div role="alert" id="status-alert">In stock</div>
  </main>
  <footer>
    <a id="footer-terms" href="/terms">Terms</a>
  </footer>
  <script>
    localStorage.setItem('nzw_fixture_cart', '1');
    sessionStorage.setItem('nzw_fixture_step', 'review');
  </script>
</body>
</html>"##;

async fn spawn_sensory_fixture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut input = [0_u8; 4096];
                let bytes = socket.read(&mut input).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&input[..bytes]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                match path {
                    "/sensory-page" => {
                        let headers = concat!(
                            "Set-Cookie: nzw_session=fixture123; Path=/; HttpOnly; SameSite=Lax\r\n",
                            "Content-Security-Policy: default-src 'self' 'unsafe-inline'\r\n",
                            "X-Content-Type-Options: nosniff\r\n",
                            "X-Frame-Options: SAMEORIGIN\r\n",
                            "Referrer-Policy: strict-origin-when-cross-origin\r\n",
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\n{headers}Content-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{SENSORY_FIXTURE_HTML}",
                            SENSORY_FIXTURE_HTML.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                    "/pending-page" => {
                        let body = r#"<!doctype html><html><body><h1>Pending network page</h1><img src="/hang"></body></html>"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                    "/hang" => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    _ => {
                        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
            });
        }
    });
    (address, server)
}

#[tokio::test]
#[ignore = "requires local Chromium and Node.js with ws"]
async fn live_chromium_captures_all_wave_iv_sensory_collectors_and_populates_offline_queries() {
    let (address, server) = spawn_sensory_fixture().await;
    let policy = TargetPolicy::AllowPrivate;
    let target = AuditTarget::parse(&format!("http://{address}/sensory-page"), policy)
        .expect("parse loopback target");

    let outcome = run_browser_with_policy(&target, Duration::from_secs(15), policy).await;
    server.abort();

    let evidence = match &outcome {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        other => panic!("expected captured or partial browser outcome, got: {other:?}"),
    };

    // 1. Interactive Element Inventory
    let interactive = evidence
        .interactive_inventory
        .as_ref()
        .expect("interactive_inventory populated");
    assert!(
        interactive.elements.len() >= 5,
        "expected at least 5 interactive controls, got {}",
        interactive.elements.len()
    );
    assert!(
        interactive.elements.iter().any(|e| {
            e.tag == "button"
                && e.name_present
                && e.accessible_name_fingerprint.is_some()
                && e.safety_class == InteractionSafetyClass::StateChangingSubmission
        }),
        "expected Buy Now submit button with hashed accessible_name_fingerprint"
    );
    assert!(
        interactive.elements.iter().any(|e| {
            e.tag == "summary"
                && e.safety_class == InteractionSafetyClass::ReadOnlyUiToggle
                && e.functional_kind == FunctionalComponentKind::Accordion
        }),
        "expected Technical Specifications summary accordion toggle"
    );

    // 2. Application State
    let app_state = evidence
        .application_state
        .as_ref()
        .expect("application_state populated");
    assert_eq!(app_state.document_ready_state, "complete");
    assert_eq!(app_state.location_path, "/sensory-page");
    assert_eq!(app_state.required_input_count, 1);
    assert_eq!(app_state.alert_region_count, 1);
    assert!(
        app_state.network_idle_reached,
        "expected network_idle_reached to be true when all requests finished"
    );
    assert!(app_state.structural_fingerprint.is_some());

    // 3. User Journey & Interaction Trace (real read-only toggle probe on <summary>)
    let trace = evidence
        .user_journey_trace
        .as_ref()
        .expect("user_journey_trace populated");
    assert!(
        !trace.candidate_scenarios.is_empty(),
        "expected candidate journey scenarios"
    );
    assert!(
        !trace.steps.is_empty(),
        "expected real read-only disclosure toggle step on <summary>"
    );

    // 4. Visual Geometry
    let geo = evidence
        .visual_geometry
        .as_ref()
        .expect("visual_geometry populated");
    assert_eq!(geo.viewport_width, 1280);
    assert!(
        geo.elements
            .iter()
            .any(|e| e.clipped_by_overflow && e.horizontal_overflow_px > 0),
        "expected clipped-card to be detected as clipped_by_overflow"
    );

    // 5. Accessibility Node Inventory
    let ax_inv = evidence
        .ax_node_inventory
        .as_ref()
        .expect("ax_node_inventory populated");
    assert!(!ax_inv.nodes.is_empty());
    assert!(
        ax_inv
            .nodes
            .iter()
            .any(|n| n.role == "button" && n.name_present)
    );

    // 6. Cookie and Storage Inventory (including storage.key(i) and async IndexedDB enumeration)
    let storage = evidence
        .cookie_and_storage
        .as_ref()
        .expect("cookie_and_storage populated");
    assert!(
        storage
            .cookies
            .iter()
            .any(|c| c.name == "nzw_session" && c.http_only),
        "expected nzw_session HttpOnly cookie"
    );
    assert!(
        storage
            .storage_keys
            .iter()
            .any(|k| k.key == "nzw_fixture_cart"),
        "expected localStorage key nzw_fixture_cart"
    );
    assert!(
        storage
            .storage_keys
            .iter()
            .any(|k| k.key == "nzw_fixture_step"),
        "expected sessionStorage key nzw_fixture_step"
    );
    assert!(
        storage.indexed_db_enumerated,
        "expected async window.indexedDB.databases() enumeration to complete"
    );

    // 7. Security Posture & Challenge
    let posture = evidence
        .security_posture
        .as_ref()
        .expect("security_posture populated");
    assert!(posture.csp_present);
    assert!(posture.csp_unsafe_inline_script);
    assert!(posture.x_content_type_options_nosniff);
    assert!(posture.x_frame_options_present);
    assert!(posture.referrer_policy_present);

    let challenge = evidence
        .security_challenge
        .as_ref()
        .expect("security_challenge populated");
    assert!(!challenge.challenge_detected);

    // 8. Performance Attribution & Media/Fonts
    let perf_attr = evidence
        .performance_attribution
        .as_ref()
        .expect("performance_attribution populated");
    assert!(perf_attr.lcp_candidate.is_some());

    let media = evidence
        .media_and_fonts
        .as_ref()
        .expect("media_and_fonts populated");
    assert!(
        media.media_assets.iter().any(|m| m.tag == "svg"),
        "expected hero SVG in media_assets"
    );

    // 9. Indexability & Structured Data
    let indexability = evidence
        .indexability_authority
        .as_ref()
        .expect("indexability_authority populated");
    assert!(indexability.effectively_indexable);
    assert_eq!(indexability.canonical_tag_count, 1);
    assert!(indexability.canonical_is_self_referential);
    assert_eq!(indexability.hreflang_alternates.len(), 2);

    let sd = evidence
        .structured_data
        .as_ref()
        .expect("structured_data populated");
    assert_eq!(sd.json_ld_block_count, 1);
    assert_eq!(sd.entities.len(), 1);
    assert_eq!(sd.entities[0].syntax, StructuredDataSyntax::JsonLd);
    assert_eq!(sd.entities[0].schema_type, "Product");
    assert!(sd.social_card.og_complete);
    assert!(sd.social_card.rendered_title_fingerprint.is_some());

    // 10. Responsive Comparison (mobile 375px vs 620px wide banner -> horizontal overflow)
    let resp = evidence
        .responsive_comparison
        .as_ref()
        .expect("responsive_comparison populated");
    assert_eq!(resp.desktop_viewport_width, 1280);
    assert_eq!(resp.mobile_viewport_width, 390);
    assert!(
        resp.mobile_scroll_width > resp.mobile_viewport_width,
        "expected mobile_scroll_width ({}) > 390 due to 620px banner",
        resp.mobile_scroll_width
    );
    assert!(!resp.anomalies.is_empty());

    // 11. Link Graph & Forms
    let links = evidence.link_graph.as_ref().expect("link_graph populated");
    assert_eq!(links.links.len(), 3);
    assert_eq!(links.forms.len(), 1);
    assert_eq!(links.forms[0].method, "POST");
    assert_eq!(links.forms[0].required_field_count, 1);

    // 12. Visual Artifacts & Service Worker
    let vis = evidence
        .visual_artifacts
        .as_ref()
        .expect("visual_artifacts populated");
    assert!(vis.viewport_screenshot_sha256.is_some());
    assert!(vis.screenshot_byte_len > 0);
    assert!(
        vis.above_fold_coverage_milli > 0 && vis.above_fold_coverage_milli <= 1000,
        "expected measured above_fold_coverage_milli in 1..=1000, got {}",
        vis.above_fold_coverage_milli
    );
    assert!(!vis.landmarks.is_empty());

    let sw = evidence
        .service_worker
        .as_ref()
        .expect("service_worker populated");
    assert!(sw.manifest_link_present);

    // Verify all offline Evidence Query Engine operations return Captured over the live snapshot
    let snapshot = EvidenceSnapshot {
        target,
        captured_at_unix_secs: 1_700_000_000,
        http: CollectorOutcome::default(),
        tls: CollectorOutcome::default(),
        browser: outcome,
        lighthouse: CollectorOutcome::default(),
        axe: CollectorOutcome::default(),
    };
    assert_eq!(
        query_interactive_elements(&snapshot, &InteractiveElementFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_application_state(&snapshot).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_interaction_trace(&snapshot, &InteractionTraceFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_element_geometry(&snapshot, &ElementGeometryFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_accessibility_nodes(&snapshot, &AccessibilityNodeFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_storage_and_cookies(&snapshot, &CookieStorageFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_security_posture(&snapshot).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_security_challenge(&snapshot).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_performance_attribution(&snapshot).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_media_and_fonts(&snapshot, &MediaFontFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_indexability_authority(&snapshot).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_structured_data(&snapshot, &StructuredDataFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_responsive_comparison(&snapshot, &ResponsiveAnomalyFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_link_graph(&snapshot, &LinkGraphFilter::default(), 0).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_visual_artifacts(&snapshot).status,
        EvidenceQueryStatus::Captured
    );
    assert_eq!(
        query_service_worker_lifecycle(&snapshot).status,
        EvidenceQueryStatus::Captured
    );
}

#[tokio::test]
#[ignore = "requires local Chromium and Node.js with ws"]
async fn live_chromium_pending_request_sets_network_idle_reached_false() {
    let (address, server) = spawn_sensory_fixture().await;
    let policy = TargetPolicy::AllowPrivate;
    let target = AuditTarget::parse(&format!("http://{address}/pending-page"), policy)
        .expect("parse loopback target");

    let outcome = run_browser_with_policy(&target, Duration::from_secs(12), policy).await;
    server.abort();

    let evidence = match &outcome {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        other => panic!("expected captured or partial browser outcome, got: {other:?}"),
    };
    let app_state = evidence
        .application_state
        .as_ref()
        .expect("application_state populated");
    assert!(
        !app_state.network_idle_reached,
        "expected network_idle_reached to be false when /hang request never completes before timeout"
    );
}
