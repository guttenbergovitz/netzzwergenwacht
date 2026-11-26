//! End-to-end integration tests for Operation Aufrüstung IV (Waves IV-A2.2 to IV-I):
//! - Offline Evidence Query Engine across all 21 query operations
//! - `KommandantZwerg` offline tool execution and citation validation
//! - `Zwergenleitstand` TUI rendering across all 19 Evidence categories
//! - Indexed `PatrolIndexCatalog` queries

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netzzwergenwacht::analysis;
use netzzwergenwacht::discovery::{CrawlBudget, CrawlSummary};
use netzzwergenwacht::domain::{
    AccessibilityNodeInventory, AccessibilityNodeObs, AccessibilityTreeSummary,
    ApplicationStateSnapshot, AuditTarget, AxeEvidence, AxeViolation, BehaviouralA11yObs,
    BrowserEventDetail, BrowserEventTime, BrowserEvidence, BrowserTimeline, BrowserTimelineEvent,
    CollectorOutcome, ConsoleErrorEvent, CookieAndStorageInventory, CookieSameSite,
    CookieSecurityObs, CspDirectiveStrength, DocumentLinkGraph, ElementBoundingBox,
    ElementGeometryObs, EvidenceSnapshot, EvidenceSource, ExecutionBudget, FailedRequestEvent,
    FontAssetObs, FormSecurityObs, HttpEvidence, HttpHeader, IndexabilityAuthorityInventory,
    InteractionCandidateScenario, InteractionStepObs, InteractionStepResult,
    InteractiveControlKind, InteractiveElementInventory, InteractiveElementObs,
    InteractiveSafetyClass, LcpCandidateObs, LighthouseMetrics, LinkClusterSummary, LinkEdgeKind,
    LinkTargetObs, Measurement, MeasurementUnit, MediaAndFontInventory, MediaElementObs, MediaKind,
    PerformanceAttributionEvidence, RedirectHop, RenderedBlockId, RenderedBlockIdentity,
    RenderedBlockKind, RenderedContentBlock, RenderedContentLimits, RenderedContentSegmentation,
    RenderedCssVisibility, RenderedTextFingerprint, RequestHop, ResourceTimingObs,
    ResponsiveAnomalyKind, ResponsiveLayoutAnomaly, ResponsiveViewportComparison,
    RuntimeSecurityPosture, SecurityChallengeEvidence, ServiceWorkerLifecycleEvidence,
    ServiceWorkerState, StackingContextObs, StorageKeyObs, StorageScope, StructuredDataFormat,
    StructuredDataInventory, StructuredEntityObs, TargetPolicy, ThirdPartyCapability,
    ThirdPartyOriginInventory, ThirdPartyOriginObs, TimelineCacheSource, TimelineEnd,
    TimelinePhaseTimings, TimelineRuntimeKind, TlsAndCaaDiagnostics, TlsEvidence, UserJourneyTrace,
    ViewportObs, VisualArtifactEvidence, VisualGeometryInventory,
};
use netzzwergenwacht::intelligence::{LlmError, LlmFuture, LlmProvider, LlmRequest, LlmResponse};
use netzzwergenwacht::investigation::{
    AccessibilityNodeFilter, BrowserTimelineFilter, CollectFuture, CookieAndStorageFilter,
    DiagnosticBackend, ElementGeometryFilter, EvidenceQueryStatus, FailedDependencyCategory,
    FailedDependencyFilter, HypothesisStatus, InteractionStepFilter, InteractiveElementFilter,
    InvestigationBudget, LinkGraphFilter, MediaAndFontFilter, RenderedBlockFilter,
    RequestChainFilter, RequestChainOutcome, ResponsiveAnomalyFilter, SourceRenderedDiffFilter,
    StructuredDataFilter, ThirdPartyOriginFilter, compare_source_and_rendered,
    query_accessibility_nodes, query_application_state, query_browser_timeline_filtered,
    query_element_geometry, query_failed_dependencies, query_indexability_authority,
    query_interaction_trace, query_interactive_elements, query_link_graph, query_media_and_fonts,
    query_performance_attribution, query_rendered_content, query_request_chains,
    query_responsive_comparison, query_security_challenge, query_security_posture,
    query_service_worker_lifecycle, query_storage_and_cookies, query_structured_data,
    query_third_party_origins, query_tls_and_caa, query_visual_artifacts, run_investigation,
};
use netzzwergenwacht::patrol::PageType;
use netzzwergenwacht::patrol::memory::{
    ApplicationMemory, CatalogAnomalyFilter, EvidenceFreshness, RememberedPage,
    query_catalog_anomalies, query_catalog_runs, query_catalog_stale_pages, query_catalog_targets,
    save_memory,
};
use netzzwergenwacht::tui::{
    AppAction, AppState, DiagnosticArtefacts, DiagnosticRunMode, EvidenceCategory, GlyphSet,
    ThemeMode, UserAction, WorkbenchView, reduce, render,
};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn sample_identity(tag: &str, id_key: Option<&str>) -> RenderedBlockIdentity {
    RenderedBlockIdentity {
        path: Some(vec!["main".to_owned(), tag.to_owned()]),
        id: match id_key {
            Some(k) => RenderedBlockId::Unique { key: k.to_owned() },
            None => RenderedBlockId::Absent,
        },
    }
}

fn sample_fingerprint(hex_char: char) -> RenderedTextFingerprint {
    RenderedTextFingerprint {
        version: 1,
        digest: hex_char.to_string().repeat(64),
    }
}

#[allow(clippy::too_many_lines)]
fn build_rich_wave_iv_snapshot() -> EvidenceSnapshot {
    let target = AuditTarget::parse("https://example.com/shop", TargetPolicy::default())
        .expect("valid target");

    let html = r#"<!doctype html>
<html lang="en">
<head>
  <title>Example Shop</title>
  <link rel="canonical" href="https://example.com/shop">
</head>
<body>
  <header><nav><a href="/cart">Cart</a></nav></header>
  <main>
    <h1>Flagship Widget</h1>
    <p>High precision industrial widget for reliability auditing and verification.</p>
  </main>
  <footer><p>Copyright Example Corp</p></footer>
</body>
</html>"#
        .to_owned();

    let http = CollectorOutcome::Captured {
        data: HttpEvidence {
            final_url: "https://example.com/shop".to_owned(),
            status_code: 200,
            redirect_chain: vec![RedirectHop {
                from_url: "https://example.com/old-shop".to_owned(),
                status_code: 301,
                to_url: "https://example.com/shop".to_owned(),
            }],
            headers: vec![
                HttpHeader {
                    name: "content-type".to_owned(),
                    value: "text/html; charset=utf-8".to_owned(),
                },
                HttpHeader {
                    name: "content-security-policy".to_owned(),
                    value: "default-src 'self' 'unsafe-inline'".to_owned(),
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
    };

    let tls = CollectorOutcome::Captured {
        data: TlsEvidence {
            protocol_version: Some("TLSv1.3".to_owned()),
            subject: Some("CN=example.com".to_owned()),
            issuer: Some("CN=Example Trust CA".to_owned()),
            not_before_unix_secs: Some(1_700_000_000),
            not_after_unix_secs: Some(1_900_000_000),
            days_until_expiry: Measurement::Measured {
                value: 180,
                unit: MeasurementUnit::Days,
            },
            subject_alt_names: vec!["example.com".to_owned(), "*.example.com".to_owned()],
            signature_algorithm: Some("ecdsa-with-SHA256".to_owned()),
            public_key_algorithm: Some("id-ecPublicKey".to_owned()),
            public_key_bits: Some(256),
            self_signed: false,
            caa_records: vec!["0 issue \"letsencrypt.org\"".to_owned()],
            caa_query_succeeded: true,
        },
    };

    let timeline = BrowserTimeline {
        events: vec![
            BrowserTimelineEvent {
                sequence: 1,
                time: BrowserEventTime::Monotonic(0),
                request: Some(RequestHop { id: 1, hop: 0 }),
                frame: Some("1".to_owned()),
                loader: Some(1),
                detail: BrowserEventDetail::RequestStarted {
                    origin: Some("https://example.com".to_owned()),
                    endpoint_path: Some("/old-shop".to_owned()),
                    method: "GET".to_owned(),
                    resource_type: Some("Document".to_owned()),
                    initiator_type: Some("other".to_owned()),
                    same_origin: Some(true),
                },
            },
            BrowserTimelineEvent {
                sequence: 2,
                time: BrowserEventTime::Monotonic(12),
                request: Some(RequestHop { id: 1, hop: 1 }),
                frame: Some("1".to_owned()),
                loader: Some(1),
                detail: BrowserEventDetail::Redirect {
                    status: 301,
                    from_origin: Some("https://example.com".to_owned()),
                    from_endpoint_path: Some("/old-shop".to_owned()),
                    to_origin: Some("https://example.com".to_owned()),
                    to_endpoint_path: Some("/shop".to_owned()),
                    same_origin: Some(true),
                },
            },
            BrowserTimelineEvent {
                sequence: 3,
                time: BrowserEventTime::Monotonic(28),
                request: Some(RequestHop { id: 1, hop: 1 }),
                frame: Some("1".to_owned()),
                loader: Some(1),
                detail: BrowserEventDetail::Response {
                    origin: Some("https://example.com".to_owned()),
                    endpoint_path: Some("/shop".to_owned()),
                    status: 200,
                    protocol: Some("h2".to_owned()),
                    mime_type: Some("text/html".to_owned()),
                    cache_source: Some(TimelineCacheSource::Network),
                    timings: Some(TimelinePhaseTimings {
                        dns_ms: Some(2),
                        connect_ms: Some(5),
                        tls_ms: Some(4),
                        send_ms: Some(1),
                        ttfb_ms: Some(14),
                    }),
                },
            },
            BrowserTimelineEvent {
                sequence: 4,
                time: BrowserEventTime::Monotonic(35),
                request: Some(RequestHop { id: 1, hop: 1 }),
                frame: Some("1".to_owned()),
                loader: Some(1),
                detail: BrowserEventDetail::Completed {
                    encoded_data_length: Some(4096),
                },
            },
            BrowserTimelineEvent {
                sequence: 5,
                time: BrowserEventTime::Monotonic(40),
                request: Some(RequestHop { id: 2, hop: 0 }),
                frame: Some("1".to_owned()),
                loader: Some(1),
                detail: BrowserEventDetail::RequestStarted {
                    origin: Some("https://api.example.com".to_owned()),
                    endpoint_path: Some("/v1/checkout".to_owned()),
                    method: "POST".to_owned(),
                    resource_type: Some("Fetch".to_owned()),
                    initiator_type: Some("script".to_owned()),
                    same_origin: Some(false),
                },
            },
            BrowserTimelineEvent {
                sequence: 6,
                time: BrowserEventTime::Monotonic(55),
                request: Some(RequestHop { id: 2, hop: 0 }),
                frame: Some("1".to_owned()),
                loader: Some(1),
                detail: BrowserEventDetail::Response {
                    origin: Some("https://api.example.com".to_owned()),
                    endpoint_path: Some("/v1/checkout".to_owned()),
                    status: 503,
                    protocol: Some("h2".to_owned()),
                    mime_type: Some("application/json".to_owned()),
                    cache_source: Some(TimelineCacheSource::Network),
                    timings: None,
                },
            },
            BrowserTimelineEvent {
                sequence: 7,
                time: BrowserEventTime::Monotonic(60),
                request: None,
                frame: Some("1".to_owned()),
                loader: None,
                detail: BrowserEventDetail::RuntimeError {
                    category: TimelineRuntimeKind::UncaughtException,
                },
            },
        ],
        truncated: false,
        end: TimelineEnd::Loaded,
    };

    let rendered_content = RenderedContentSegmentation {
        viewport_width: 1280,
        viewport_height: 800,
        blocks: vec![
            RenderedContentBlock {
                node: 1,
                kind: RenderedBlockKind::Main,
                visibility: RenderedCssVisibility::Visible,
                visible_text: "Flagship Widget High precision industrial widget for reliability auditing and verification. Dynamic hydrated specification table.".to_owned(),
                text_truncated: false,
                identity: Some(sample_identity("main", Some("sha256:main1"))),
                text_fingerprint: Some(sample_fingerprint('a')),
            },
            RenderedContentBlock {
                node: 2,
                kind: RenderedBlockKind::Navigation,
                visibility: RenderedCssVisibility::Visible,
                visible_text: "Cart Products Docs".to_owned(),
                text_truncated: false,
                identity: Some(sample_identity("nav", Some("sha256:nav1"))),
                text_fingerprint: Some(sample_fingerprint('b')),
            },
        ],
        limits: RenderedContentLimits {
            nodes: false,
            depth: false,
            blocks: false,
        },
        id_census_complete: Some(true),
        page_key: Some("c".repeat(64)),
    };

    let browser = CollectorOutcome::Captured {
        data: BrowserEvidence {
            final_url: "https://example.com/shop".to_owned(),
            browser_version: Some("HeadlessChrome/130.0.0.0".to_owned()),
            timeline: Some(timeline),
            rendered_content: Some(rendered_content),
            console_errors: vec![ConsoleErrorEvent {
                level: "error".to_owned(),
                text: "TypeError: checkout endpoint unavailable".to_owned(),
                error_kind: Some("exception".to_owned()),
                source_url: Some("https://example.com/app.js".to_owned()),
                line_number: Some(42),
            }],
            hydration_errors: Vec::new(),
            failed_requests: vec![FailedRequestEvent {
                url: "https://api.example.com/v1/checkout".to_owned(),
                resource_type: Some("Fetch".to_owned()),
                reason: "HTTP 503".to_owned(),
                status_code: Some(503),
            }],
            viewports: vec![
                ViewportObs {
                    name: "desktop".to_owned(),
                    width: 1280,
                    height: 800,
                    horizontal_overflow_px: 0,
                    small_touch_targets_count: 0,
                    content_clipped: false,
                },
                ViewportObs {
                    name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    horizontal_overflow_px: 18,
                    small_touch_targets_count: 1,
                    content_clipped: true,
                },
            ],
            resources: vec![ResourceTimingObs {
                url: "https://example.com/shop".to_owned(),
                resource_type: "Document".to_owned(),
                status_code: Some(200),
                transfer_size: Some(4096),
                duration_ms: Some(28),
                mime_type: Some("text/html".to_owned()),
                protocol: Some("h2".to_owned()),
                cache_control: Some("max-age=60".to_owned()),
                content_encoding: Some("br".to_owned()),
                priority: Some("VeryHigh".to_owned()),
                initiator_type: Some("other".to_owned()),
                initiator_url: None,
                start_time_ms: Some(0),
                request_id: Some("1".to_owned()),
                endpoint_path: Some("/shop".to_owned()),
                cache_source: Some(TimelineCacheSource::Network),
                timings: None,
            }],
            resources_truncated: false,
            rendered_images: Vec::new(),
            rendered_images_truncated: false,
            rendered_dom_elements: Some(48),
            rendered_word_count: Some(24),
            ax_tree: Some(AccessibilityTreeSummary {
                total_nodes: 18,
                ignored_nodes: 2,
                interactive_without_name: 0,
                hidden_focusable_count: 0,
                truncated: false,
            }),
            performance: None,
            storage_summary: None,
            coverage: None,
            behavioural_a11y: Some(BehaviouralA11yObs {
                tab_stops_observed: 4,
                tabbable_candidates: 4,
                focus_trap_detected: false,
                missing_focus_indicator_count: 0,
                open_dialogs_count: 1,
                focus_sequence: vec!["a#skip".to_owned(), "button#buy".to_owned()],
                tab_budget_exhausted: false,
                dialog_escape_closed: Some(true),
                focus_lost_after_dialog_close: Some(false),
                escape_dismissed_modal: Some(true),
                focus_restored_after_modal: Some(true),
                live_region_count: 1,
                aria_invalid_count: 0,
            }),
            cpu_profile: None,
            consent_banner: None,
            provenance: None,
            interactive_inventory: Some(InteractiveElementInventory {
                elements: vec![InteractiveElementObs {
                    node: 10,
                    identity: sample_identity("button", Some("sha256:btn-buy")),
                    tag: "button".to_owned(),
                    role: Some("button".to_owned()),
                    control_type: InteractiveControlKind::Cta,
                    safety_class: InteractiveSafetyClass::StateChangingSubmission,
                    name_present: true,
                    accessible_name_char_count: 7,
                    accessible_name_fingerprint: Some(sample_fingerprint('d')),
                    visible: true,
                    enabled: true,
                    disabled: false,
                    bbox: ElementBoundingBox {
                        x: 24,
                        y: 320,
                        width: 180,
                        height: 44,
                    },
                    ..Default::default()
                }],
                ..Default::default()
            }),
            application_state: Some(ApplicationStateSnapshot {
                document_ready_state: "complete".to_owned(),
                structural_fingerprint: Some("e".repeat(64)),
                network_idle_reached: true,
                ..Default::default()
            }),
            user_journey_trace: Some(UserJourneyTrace {
                candidate_scenarios: vec![InteractionCandidateScenario::FaqAccordion],
                steps: vec![InteractionStepObs {
                    step_index: 1,
                    target_node: 10,
                    action: "expand_accordion".to_owned(),
                    result: InteractionStepResult::Applied,
                    aria_expanded_changed: true,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            visual_geometry: Some(VisualGeometryInventory {
                viewport_width: 1280,
                viewport_height: 800,
                elements: vec![ElementGeometryObs {
                    node: 10,
                    identity: sample_identity("div", Some("sha256:hero-card")),
                    tag: "div".to_owned(),
                    horizontal_overflow_px: 24,
                    clipped_by_overflow: true,
                    stacking: StackingContextObs {
                        z_index: Some(10),
                        establishes_stacking_context: true,
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ax_node_inventory: Some(AccessibilityNodeInventory {
                nodes: vec![AccessibilityNodeObs {
                    node_index: 0,
                    ax_node_id: "ax-1".to_owned(),
                    role: "button".to_owned(),
                    name_present: true,
                    name_length: 7,
                    name_fingerprint: Some("9".repeat(64)),
                    focusable: true,
                    interactive: true,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            cookie_and_storage: Some(CookieAndStorageInventory {
                cookies: vec![CookieSecurityObs {
                    name: "session_id".to_owned(),
                    secure: true,
                    http_only: true,
                    same_site: CookieSameSite::Lax,
                    session_cookie: true,
                    first_party: true,
                    ..Default::default()
                }],
                storage_keys: vec![StorageKeyObs {
                    scope: StorageScope::LocalStorage,
                    key_name: "cart_count".to_owned(),
                    value_byte_length: 2,
                }],
                ..Default::default()
            }),
            third_party_inventory: Some(ThirdPartyOriginInventory {
                first_party_origin: "https://example.com".to_owned(),
                origins: vec![ThirdPartyOriginObs {
                    origin: "https://cdn.analytics.example.net".to_owned(),
                    total_requests: 2,
                    script_requests: 1,
                    total_transfer_bytes: 12_400,
                    capability: ThirdPartyCapability::AnalyticsOrTagManager,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            security_posture: Some(RuntimeSecurityPosture {
                is_https: true,
                hsts_present: true,
                hsts_max_age_secs: Some(31_536_000),
                csp_header_present: true,
                csp_strength: CspDirectiveStrength::AllowsUnsafeInline,
                ..Default::default()
            }),
            security_challenge: Some(SecurityChallengeEvidence {
                challenge_detected: false,
                ..Default::default()
            }),
            performance_attribution: Some(PerformanceAttributionEvidence {
                lcp_candidate: Some(LcpCandidateObs {
                    identity: Some(sample_identity("h1", Some("sha256:lcp1"))),
                    tag: "h1".to_owned(),
                    render_time_ms: 120,
                    size_px_sq: 24_000,
                    ..Default::default()
                }),
                total_cls_milli: 12,
                ..Default::default()
            }),
            media_and_fonts: Some(MediaAndFontInventory {
                media_assets: vec![MediaElementObs {
                    node: 20,
                    kind: MediaKind::Image,
                    tag: "img".to_owned(),
                    intrinsic_width: 800,
                    intrinsic_height: 600,
                    rendered_width: 400,
                    rendered_height: 300,
                    has_explicit_dimensions: true,
                    alt_present: true,
                    in_initial_viewport: true,
                    ..Default::default()
                }],
                font_assets: vec![FontAssetObs {
                    index: 0,
                    font_family: "Inter".to_owned(),
                    font_style: "normal".to_owned(),
                    font_weight: "400".to_owned(),
                    status: "loaded".to_owned(),
                    ..Default::default()
                }],
                total_font_transfer_bytes: 22_000,
                ..Default::default()
            }),
            indexability_authority: Some(IndexabilityAuthorityInventory {
                effectively_indexable: true,
                canonical_tag_count: 1,
                rendered_canonical_origin: Some("https://example.com".to_owned()),
                rendered_canonical_path: Some("/shop".to_owned()),
                html_lang_present: true,
                html_lang_value: Some("en".to_owned()),
                ..Default::default()
            }),
            structured_data: Some(StructuredDataInventory {
                entities: vec![StructuredEntityObs {
                    entity_index: 0,
                    format: StructuredDataFormat::JsonLd,
                    schema_type: "Product".to_owned(),
                    present_properties: vec!["name".to_owned(), "offers".to_owned()],
                    required_properties_valid: true,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            responsive_comparison: Some(ResponsiveViewportComparison {
                desktop_width: 1280,
                mobile_width: 390,
                desktop_visible_blocks: 2,
                mobile_visible_blocks: 2,
                mobile_horizontal_overflow_px: 18,
                anomalies: vec![ResponsiveLayoutAnomaly {
                    node: 10,
                    identity: Some(sample_identity("div", Some("sha256:hero-card"))),
                    tag: "div".to_owned(),
                    kind: ResponsiveAnomalyKind::MobileHorizontalOverflow,
                    detail: "mobile horizontal overflow of 18px".to_owned(),
                }],
                ..Default::default()
            }),
            link_graph: Some(DocumentLinkGraph {
                links: vec![LinkTargetObs {
                    node: 30,
                    edge_kind: LinkEdgeKind::InternalPage,
                    target_origin: Some("https://example.com".to_owned()),
                    target_path: Some("/cart".to_owned()),
                    same_origin: true,
                    visible: true,
                    in_navigation_landmark: true,
                    anchor_text_present: true,
                    anchor_text_word_count: 1,
                    anchor_text_fingerprint: Some("8".repeat(64)),
                    ..Default::default()
                }],
                forms: vec![FormSecurityObs {
                    node: 31,
                    method: "POST".to_owned(),
                    action_origin: Some("https://example.com".to_owned()),
                    action_path: Some("/checkout".to_owned()),
                    same_origin_action: true,
                    secure_action_transport: true,
                    input_count: 3,
                    ..Default::default()
                }],
                cluster_summary: LinkClusterSummary {
                    internal_links: 2,
                    external_links: 1,
                    ..Default::default()
                },
                ..Default::default()
            }),
            visual_artifacts: Some(VisualArtifactEvidence {
                viewport_screenshot_sha256: Some("7".repeat(64)),
                screenshot_byte_len: 48_120,
                viewport_width: 1280,
                viewport_height: 800,
                above_fold_coverage_milli: 750,
                ..Default::default()
            }),
            service_worker: Some(ServiceWorkerLifecycleEvidence {
                registration_state: ServiceWorkerState::Activated,
                page_controlled: true,
                script_path: Some("/sw.js".to_owned()),
                scope_path: Some("/".to_owned()),
                cache_storage_bucket_count: 1,
                cache_bucket_names: vec!["v1-static".to_owned()],
                ..Default::default()
            }),
            tls_and_caa: Some(TlsAndCaaDiagnostics {
                protocol_version: Some("TLSv1.3".to_owned()),
                caa_records: vec!["0 issue \"letsencrypt.org\"".to_owned()],
                caa_query_succeeded: true,
                ..Default::default()
            }),
        },
    };

    let axe = CollectorOutcome::Captured {
        data: AxeEvidence {
            axe_version: Some("4.10.0".to_owned()),
            violations: vec![AxeViolation {
                id: "color-contrast".to_owned(),
                impact: Some("serious".to_owned()),
                description: "Elements must meet minimum colour contrast ratio thresholds"
                    .to_owned(),
                help_url: "https://dequeuniversity.com/rules/axe/4.10/color-contrast".to_owned(),
                nodes_count: 1,
                target_selectors: vec!["main > h1.hero-title".to_owned()],
            }],
            passes_count: 24,
            incomplete_count: 0,
        },
    };

    EvidenceSnapshot {
        target,
        captured_at_unix_secs: 1_700_000_000,
        http,
        tls,
        browser,
        lighthouse: CollectorOutcome::default(),
        axe,
    }
}

#[test]
fn wave_iv_all_21_offline_evidence_queries_return_captured_and_cite_valid_refs() {
    let snapshot = build_rich_wave_iv_snapshot();

    // 1. Filtered BrowserTimeline
    let timeline_page =
        query_browser_timeline_filtered(&snapshot, &BrowserTimelineFilter::default(), 0);
    assert_eq!(timeline_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(timeline_page.total_matching, 7);

    // 2. Request Chains
    let chains_page = query_request_chains(&snapshot, &RequestChainFilter::default(), 0);
    assert_eq!(chains_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(chains_page.total_matching, 2);
    assert_eq!(chains_page.chains[0].total_hops, 2);
    assert_eq!(
        chains_page.chains[0].outcome,
        RequestChainOutcome::Completed
    );

    // 3. Failed Dependencies
    let failed_page = query_failed_dependencies(&snapshot, &FailedDependencyFilter::default(), 0);
    assert_eq!(failed_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(failed_page.total_matching, 1);
    assert_eq!(
        failed_page.dependencies[0].category,
        FailedDependencyCategory::HttpError
    );

    // 4. Rendered Content
    let rendered_page = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0);
    assert_eq!(rendered_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(rendered_page.blocks.len(), 2);

    // 5. Source vs Rendered Diff
    let svr = compare_source_and_rendered(&snapshot, &SourceRenderedDiffFilter::default(), 0);
    assert_eq!(svr.status, EvidenceQueryStatus::Captured);
    assert!(!svr.drifts.is_empty());

    // 6. Interactive Elements
    let interactive_page =
        query_interactive_elements(&snapshot, &InteractiveElementFilter::default(), 0);
    assert_eq!(interactive_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(interactive_page.total_matching, 1);

    // 7. Application State
    let app_state_page = query_application_state(&snapshot);
    assert_eq!(app_state_page.status, EvidenceQueryStatus::Captured);
    assert!(app_state_page.state.is_some());

    // 8. Interaction Trace
    let trace_page = query_interaction_trace(&snapshot, &InteractionStepFilter::default(), 0);
    assert_eq!(trace_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(trace_page.total_matching, 1);

    // 9. Element Geometry
    let geo_page = query_element_geometry(&snapshot, &ElementGeometryFilter::default(), 0);
    assert_eq!(geo_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(geo_page.total_matching, 1);

    // 10. Accessibility Nodes
    let ax_page = query_accessibility_nodes(&snapshot, &AccessibilityNodeFilter::default(), 0);
    assert_eq!(ax_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(ax_page.total_matching, 1);

    // 11. Cookies and Storage
    let cookie_page = query_storage_and_cookies(&snapshot, &CookieAndStorageFilter::default(), 0);
    assert_eq!(cookie_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(cookie_page.cookies.len(), 1);

    // 12. Third-Party Origins
    let tp_page = query_third_party_origins(&snapshot, &ThirdPartyOriginFilter::default(), 0);
    assert_eq!(tp_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(tp_page.total_matching, 1);

    // 13. Security Posture
    let sec_page = query_security_posture(&snapshot);
    assert_eq!(sec_page.status, EvidenceQueryStatus::Captured);
    assert!(sec_page.posture.is_some());

    // 14. Security Challenge
    let chal_page = query_security_challenge(&snapshot);
    assert_eq!(chal_page.status, EvidenceQueryStatus::Captured);
    assert!(chal_page.challenge.is_some());

    // 15. Performance Attribution
    let perf_page = query_performance_attribution(&snapshot);
    assert_eq!(perf_page.status, EvidenceQueryStatus::Captured);
    assert!(perf_page.attribution.is_some());

    // 16. Media and Fonts
    let media_page = query_media_and_fonts(&snapshot, &MediaAndFontFilter::default(), 0);
    assert_eq!(media_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(media_page.media_assets.len(), 1);
    assert_eq!(media_page.font_assets.len(), 1);

    // 17. Indexability Authority
    let idx_page = query_indexability_authority(&snapshot);
    assert_eq!(idx_page.status, EvidenceQueryStatus::Captured);
    assert!(idx_page.authority.is_some());

    // 18. Structured Data
    let sd_page = query_structured_data(&snapshot, &StructuredDataFilter::default(), 0);
    assert_eq!(sd_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(sd_page.entities.len(), 1);

    // 19. Responsive Comparison
    let resp_page = query_responsive_comparison(&snapshot, &ResponsiveAnomalyFilter::default(), 0);
    assert_eq!(resp_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(resp_page.anomalies.len(), 1);

    // 20. Link Graph & Forms
    let link_page = query_link_graph(&snapshot, &LinkGraphFilter::default(), 0);
    assert_eq!(link_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(link_page.links.len(), 1);
    assert_eq!(link_page.forms.len(), 1);

    // 21. Visual Artifacts, Service Worker, TLS & CAA
    let vis_page = query_visual_artifacts(&snapshot);
    assert_eq!(vis_page.status, EvidenceQueryStatus::Captured);
    assert!(vis_page.artifacts.is_some());

    let sw_page = query_service_worker_lifecycle(&snapshot);
    assert_eq!(sw_page.status, EvidenceQueryStatus::Captured);
    assert!(sw_page.lifecycle.is_some());

    let tls_page = query_tls_and_caa(&snapshot);
    assert_eq!(tls_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(
        tls_page
            .handshake_tls
            .expect("handshake_tls")
            .caa_records
            .len(),
        1
    );
}

#[test]
fn wave_iv_offline_queries_preserve_skipped_and_unavailable_states() {
    let target =
        AuditTarget::parse("https://example.com", TargetPolicy::default()).expect("target");
    let snapshot = EvidenceSnapshot {
        target,
        captured_at_unix_secs: 1_700_000_000,
        http: CollectorOutcome::default(),
        tls: CollectorOutcome::default(),
        browser: CollectorOutcome::default(),
        lighthouse: CollectorOutcome::default(),
        axe: CollectorOutcome::default(),
    };

    let expected_skipped = EvidenceQueryStatus::Skipped {
        reason: "not collected".to_owned(),
    };
    assert_eq!(
        query_interactive_elements(&snapshot, &InteractiveElementFilter::default(), 0).status,
        expected_skipped
    );
    assert_eq!(query_application_state(&snapshot).status, expected_skipped);
    assert_eq!(
        query_element_geometry(&snapshot, &ElementGeometryFilter::default(), 0).status,
        expected_skipped
    );
    assert_eq!(
        query_accessibility_nodes(&snapshot, &AccessibilityNodeFilter::default(), 0).status,
        expected_skipped
    );
    assert_eq!(query_security_posture(&snapshot).status, expected_skipped);
    assert_eq!(
        query_performance_attribution(&snapshot).status,
        expected_skipped
    );
    assert_eq!(query_visual_artifacts(&snapshot).status, expected_skipped);
    assert_eq!(
        query_service_worker_lifecycle(&snapshot).status,
        expected_skipped
    );
    assert_eq!(query_tls_and_caa(&snapshot).status, expected_skipped);
}

struct PreloadedWaveIvBackend {
    snapshot: EvidenceSnapshot,
    browser_calls: Mutex<usize>,
}

impl DiagnosticBackend for PreloadedWaveIvBackend {
    fn collect_http<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _budget: ExecutionBudget,
        _policy: TargetPolicy,
    ) -> CollectFuture<'a, EvidenceSnapshot> {
        let snap = self.snapshot.clone();
        Box::pin(async move { snap })
    }

    fn collect_browser<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<BrowserEvidence>> {
        if let Ok(mut guard) = self.browser_calls.lock() {
            *guard += 1;
        }
        let outcome = self.snapshot.browser.clone();
        Box::pin(async move { outcome })
    }

    fn collect_axe<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<AxeEvidence>> {
        let outcome = self.snapshot.axe.clone();
        Box::pin(async move { outcome })
    }

    fn collect_lighthouse<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<LighthouseMetrics>> {
        let outcome = self.snapshot.lighthouse.clone();
        Box::pin(async move { outcome })
    }

    fn collect_crawl<'a>(
        &'a self,
        target: &'a AuditTarget,
        _crawl_budget: CrawlBudget,
        _exec_budget: ExecutionBudget,
        _policy: TargetPolicy,
    ) -> CollectFuture<'a, Result<CrawlSummary, String>> {
        let seed = target.clone();
        Box::pin(async move {
            Ok(CrawlSummary {
                seed,
                pages: Vec::new(),
                systemic_issues: Vec::new(),
                budget_exhausted: false,
                graph_results: Vec::new(),
            })
        })
    }
}

struct SequenceMockLlm {
    responses: Mutex<Vec<String>>,
}

impl SequenceMockLlm {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses: Mutex::new(responses),
        }
    }
}

impl LlmProvider for SequenceMockLlm {
    fn provider_name(&self) -> &'static str {
        "sequence-mock"
    }

    fn model_name(&self) -> &str {
        "mock-model"
    }

    fn complete<'a>(
        &'a self,
        _request: LlmRequest,
    ) -> LlmFuture<'a, Result<LlmResponse, LlmError>> {
        let next = self.responses.lock().ok().and_then(|mut q| {
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        });
        Box::pin(async move {
            match next {
                Some(content) => Ok(LlmResponse {
                    content,
                    model: "mock-model".to_owned(),
                    prompt_tokens: Some(50),
                    completion_tokens: Some(30),
                }),
                None => Err(LlmError::Transport("exhausted mock responses".to_owned())),
            }
        })
    }
}

#[tokio::test]
async fn kommandant_dispatches_wave_iv_offline_query_tools_with_citation_validation() {
    let snapshot = build_rich_wave_iv_snapshot();
    let target = snapshot.target.clone();
    let backend: Arc<dyn DiagnosticBackend> = Arc::new(PreloadedWaveIvBackend {
        snapshot,
        browser_calls: Mutex::new(0),
    });

    let llm = SequenceMockLlm::new(vec![
        r#"{
            "ready_to_conclude": false,
            "originating_rule": null,
            "proposed_explanation": "Inspect interactive elements inventory for state-changing CTA button",
            "requested_tool": "query_interactive_elements"
        }"#
        .to_owned(),
        r#"{
            "status": "supported",
            "interactive_element_nodes": [10],
            "evaluation_summary": "Confirmed CTA button at node 10 is visible and enabled",
            "conclusion": "Interactive CTA button verified via offline inventory"
        }"#
        .to_owned(),
        r#"{
            "ready_to_conclude": false,
            "originating_rule": null,
            "proposed_explanation": "Inspect TLS certificate SANs and DNS CAA records",
            "requested_tool": "query_tls_and_caa"
        }"#
        .to_owned(),
        r#"{
            "status": "supported",
            "cite_tls_and_caa": true,
            "evaluation_summary": "Confirmed DNS CAA record restricts issuance to letsencrypt.org",
            "conclusion": "TLS and CAA records verified"
        }"#
        .to_owned(),
        r#"{
            "ready_to_conclude": true,
            "conclusion": "Completed offline sensory verification."
        }"#
        .to_owned(),
    ]);

    let budget = InvestigationBudget {
        max_llm_turns: 4,
        ..InvestigationBudget::default()
    };

    let report = run_investigation(
        target,
        "Verify interactive controls and TLS CAA posture".to_owned(),
        TargetPolicy::default(),
        budget,
        backend,
        &llm,
    )
    .await;

    assert_eq!(report.hypotheses.len(), 2);
    assert_eq!(report.hypotheses[0].status, HypothesisStatus::Supported);
    assert!(
        report.hypotheses[0]
            .supporting_evidence
            .iter()
            .any(|r| r.detail.contains("interactive-element=10"))
    );
    assert_eq!(report.hypotheses[1].status, HypothesisStatus::Supported);
    assert!(
        report.hypotheses[1]
            .supporting_evidence
            .iter()
            .any(|r| r.source == EvidenceSource::TlsCertificate && r.detail.contains("tls-caa:"))
    );
}

#[tokio::test]
async fn kommandant_forces_inconclusive_when_wave_iv_tool_omits_required_citation() {
    let snapshot = build_rich_wave_iv_snapshot();
    let target = snapshot.target.clone();
    let backend: Arc<dyn DiagnosticBackend> = Arc::new(PreloadedWaveIvBackend {
        snapshot,
        browser_calls: Mutex::new(0),
    });

    let llm = SequenceMockLlm::new(vec![
        r#"{
            "ready_to_conclude": false,
            "originating_rule": null,
            "proposed_explanation": "Inspect visual geometry for overflow clipping",
            "requested_tool": "query_element_geometry"
        }"#
        .to_owned(),
        r#"{
            "status": "supported",
            "geometry_element_nodes": [],
            "evaluation_summary": "Claimed overflow without citing any geometry_element_nodes",
            "conclusion": "Uncited claim"
        }"#
        .to_owned(),
        r#"{
            "ready_to_conclude": true,
            "conclusion": "Done"
        }"#
        .to_owned(),
    ]);

    let budget = InvestigationBudget {
        max_llm_turns: 2,
        ..InvestigationBudget::default()
    };

    let report = run_investigation(
        target,
        "Check layout overflow".to_owned(),
        TargetPolicy::default(),
        budget,
        backend,
        &llm,
    )
    .await;

    assert_eq!(report.hypotheses.len(), 1);
    assert_eq!(report.hypotheses[0].status, HypothesisStatus::Inconclusive);
}

#[test]
fn zwergenleitstand_tui_renders_all_19_evidence_categories() {
    let snapshot = build_rich_wave_iv_snapshot();
    let report = analysis::run_all(&snapshot);

    let mut state = AppState::new(ThemeMode::StandardDark, GlyphSet::Unicode);
    state.ingest_artefacts(DiagnosticArtefacts {
        target: "https://example.com/shop".to_owned(),
        mode: DiagnosticRunMode::DeterministicCheck,
        snapshot: Some(snapshot),
        audit_report: Some(report),
        investigation_report: None,
        patrol_report: None,
        history_reports: Vec::new(),
        regression_report: None,
        elapsed_ms: 42,
    });

    let _ = reduce(
        &mut state,
        AppAction::User(UserAction::SelectView(WorkbenchView::Evidence)),
    );

    let backend = TestBackend::new(140, 42);
    let mut terminal = Terminal::new(backend).expect("test terminal");

    for category in EvidenceCategory::ALL {
        state.evidence_category = category;
        state.evidence_offset = 0;
        terminal
            .draw(|frame| render(frame, &state))
            .expect("render evidence category");

        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }
        assert!(
            rendered.contains(category.label()),
            "Expected Evidence view to render category label {}",
            category.label()
        );
        assert!(
            !rendered.contains("panic"),
            "Unexpected panic text in category {}",
            category.label()
        );
    }
}

#[test]
fn patrol_index_catalog_persists_and_queries_targets_anomalies_stale_pages_and_runs() {
    let temp_dir =
        std::env::temp_dir().join(format!("nzw-wave-iv-catalog-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let snapshot = build_rich_wave_iv_snapshot();
    let report = analysis::run_all(&snapshot);

    let mut memory = ApplicationMemory::new(&snapshot.target, 1_700_005_000);
    memory.patrol_count = 3;
    memory.latest_report = Some(report.clone());
    memory.page_records.insert(
        "https://example.com/shop".to_owned(),
        RememberedPage {
            url: "https://example.com/shop".to_owned(),
            locale: Some("en-GB".to_owned()),
            page_type: PageType::ProductListing,
            template_fingerprint: Some("tpl-shop".to_owned()),
            content_hash: Some("fnv1a-shop".to_owned()),
            etag: Some("\"v1-etag\"".to_owned()),
            last_modified: None,
            latest_report: Some(report),
            last_inspected_unix_secs: 1_700_001_000,
            open_finding_count: 2,
            healthy_streak: 0,
            freshness: EvidenceFreshness::PreviouslyVerified,
        },
    );

    save_memory(&temp_dir, &memory).expect("save memory and update catalog");

    let targets = query_catalog_targets(&temp_dir).expect("query catalog targets");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].origin, "https://example.com");

    let anomalies =
        query_catalog_anomalies(&temp_dir, &CatalogAnomalyFilter::default()).expect("anomalies");
    assert!(anomalies.is_empty());

    let stale = query_catalog_stale_pages(&temp_dir, 1_700_002_000).expect("stale pages");
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].url, "https://example.com/shop");

    let runs = query_catalog_runs(&temp_dir, None, 10).expect("runs");
    assert!(runs.is_empty());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
