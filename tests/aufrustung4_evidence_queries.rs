//! Restored Wave IV regression suite for the offline Evidence Query Engine.
//!
//! The original `aufrustung4_evidence_queries.rs` was removed because it had been
//! written against an API that never existed: it referenced types such as
//! `CookieSecurityObs`, `RuntimeSecurityPosture` and `ViewportObs`, and had never
//! compiled. This file restores the intended coverage against the contracts that
//! actually exist today.
//!
//! Every assertion here runs offline against a hand-built [`EvidenceSnapshot`]; no
//! collector, browser or network operation is performed.

#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netzzwergenwacht::brigade::DwarfId;
use netzzwergenwacht::discovery::{CrawlBudget, CrawlSummary, PageType};
use netzzwergenwacht::domain::{
    AccessibilityInventoryLimits, AccessibilityNodeInventory, AccessibilityNodeObs,
    ApplicationStateSnapshot, AuditTarget, AxNameSourceKind, AxeEvidence, BrowserEventDetail,
    BrowserEvidence, BrowserTimeline, BrowserTimelineEvent, CandidateJourneyScenario,
    CollectorOutcome, ConsoleErrorEvent, CookieAndStorageInventory, CookieSameSiteMode,
    CookieStorageLimits, CssOverflowKind, CssPositionKind, ElementBoundingBox, ElementGeometryObs,
    EvidenceSnapshot, ExecutionBudget, FontAssetObs, FontDisplayPolicy, FunctionalComponentKind,
    HttpEvidence, HttpHeader, IndexabilityAuthorityEvidence, InteractionActionKind,
    InteractionProbePolicy, InteractionSafetyClass, InteractionTraceStep,
    InteractionWindowTermination, InteractiveElementInventory, InteractiveElementObs,
    InteractiveInventoryLimits, LcpCandidateObs, LcpCandidateSource, LighthouseMetrics,
    LinkClusterSummary, LinkGraphInventory, LinkPlacementRegion, Measurement, MeasurementUnit,
    MediaAndFontInventory, MediaAssetObs, MediaFormatClass, MediaLoadingStrategy, Origin,
    PerformanceAttributionEvidence, RenderBlockingChainSummary, RenderedBlockId,
    RenderedBlockIdentity, RenderedBlockKind, RenderedContentBlock, RenderedContentLimits,
    RenderedContentSegmentation, RenderedCssVisibility, RenderedFormEndpointObs, RenderedLinkObs,
    RenderedTextFingerprint, RequestHop, ResourceTimingObs, ResponsiveAnomalyKind,
    ResponsiveAnomalyObs, ResponsiveComparisonEvidence, RuntimeCookieObs,
    SecurityChallengeEvidence, SecurityPostureSummary, ServiceWorkerLifecycleEvidence,
    ServiceWorkerRegistrationState, Severity, SocialPreviewCardCompleteness, StackingContextObs,
    StorageKeyObs, StructuredDataInventory, StructuredDataSyntax, StructuredEntitySummary,
    TargetPolicy, ThirdPartyCapabilitySummary, ThirdPartyInventory, ThirdPartyOriginObs,
    TimelineEnd, TlsAndCaaDiagnostics, TlsEvidence, UserJourneyTrace, VisualArtifactEvidence,
    VisualGeometryInventory, VisualGeometryLimits, VisualRegionLandmarkObs, WebStorageArea,
};
use netzzwergenwacht::events::DiagnosticRunMode;
use netzzwergenwacht::intelligence::{LlmBudget, LlmFuture, LlmProvider};
use netzzwergenwacht::investigation::evidence_query::{InteractionStepFilter, StorageCookieFilter};
use netzzwergenwacht::investigation::{
    AccessibilityNodeFilter, ApplicationStateQueryPage, BrowserTimelineFilter, DiagnosticBackend,
    ElementGeometryFilter, EvidenceQueryStatus, FailedDependencyFilter, HypothesisStatus,
    InteractiveElementFilter, InvestigationBudget, InvestigationReport, LinkGraphFilter,
    MediaFontFilter, NetworkResourceFilter, RenderedBlockFilter, RequestChainFilter,
    ResponsiveAnomalyFilter, RuntimeErrorFilter, StructuredDataFilter, ThirdPartyOriginFilter,
    query_accessibility_nodes, query_application_state, query_browser_timeline,
    query_browser_timeline_filtered, query_element_geometry, query_failed_dependencies,
    query_indexability_authority, query_interaction_trace, query_interactive_elements,
    query_link_graph, query_media_and_fonts, query_network_resources,
    query_performance_attribution, query_rendered_content, query_request_chains,
    query_responsive_comparison, query_runtime_errors, query_security_challenge,
    query_security_posture, query_service_worker_lifecycle, query_source_vs_rendered,
    query_storage_and_cookies, query_structured_data, query_third_party_origins, query_tls_and_caa,
    query_visual_artifacts, run_investigation,
};
use netzzwergenwacht::patrol::memory::{
    ApplicationId, ApplicationMemory, CatalogAnomalyFilter, EvidenceFreshness, RememberedPage,
    query_catalog_anomalies, query_catalog_runs, query_catalog_stale_pages, query_catalog_targets,
    record_patrol_run, save_memory,
};
use netzzwergenwacht::patrol::sampling::SamplingPlan;
use netzzwergenwacht::patrol::{
    AnomalyCategory, ApplicationMap, CoverageMatrix, PatrolAnomaly, PatrolReport,
    PatrolResourceLedger,
};
use netzzwergenwacht::tui::{
    AppState, DiagnosticArtefacts, EvidenceCategory, GlyphSet, ThemeMode, WorkbenchView, render,
};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

const SOURCE_HTML: &str = r"<!doctype html>
<html lang='en'>
  <head><title>Precision Chronometer</title></head>
  <body>
    <header>Example shop header</header>
    <nav>Home Catalogue Support</nav>
    <main>
      <h1>Precision Chronometer</h1>
      <p>Engineered for deterministic verification across desktop and mobile viewports.</p>
    </main>
    <footer>Terms and conditions apply</footer>
  </body>
</html>";

fn target() -> AuditTarget {
    AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).expect("parse target")
}

fn fingerprint(seed: u8) -> RenderedTextFingerprint {
    RenderedTextFingerprint {
        version: 1,
        digest: format!("{seed:064x}"),
    }
}

fn identity(tag: &str) -> RenderedBlockIdentity {
    RenderedBlockIdentity {
        path: Some(vec!["body".to_owned(), tag.to_owned()]),
        id: RenderedBlockId::Unique {
            key: format!("sha256:{}", "b".repeat(64)),
        },
    }
}

fn segmentation() -> RenderedContentSegmentation {
    RenderedContentSegmentation {
        viewport_width: 1280,
        viewport_height: 720,
        blocks: vec![
            RenderedContentBlock {
                node: 1,
                kind: RenderedBlockKind::Navigation,
                visibility: RenderedCssVisibility::Visible,
                visible_text: "Home Catalogue Support".to_owned(),
                text_truncated: false,
                identity: Some(identity("nav")),
                text_fingerprint: Some(fingerprint(1)),
            },
            RenderedContentBlock {
                node: 2,
                kind: RenderedBlockKind::Main,
                visibility: RenderedCssVisibility::Visible,
                visible_text: "Precision Chronometer".to_owned(),
                text_truncated: false,
                identity: Some(identity("main")),
                text_fingerprint: Some(fingerprint(2)),
            },
            RenderedContentBlock {
                node: 3,
                kind: RenderedBlockKind::Paragraph,
                visibility: RenderedCssVisibility::Visible,
                visible_text: "Engineered for deterministic verification.".to_owned(),
                text_truncated: false,
                identity: Some(identity("p")),
                text_fingerprint: Some(fingerprint(3)),
            },
        ],
        limits: RenderedContentLimits {
            nodes: false,
            depth: false,
            blocks: false,
        },
        id_census_complete: Some(true),
        page_key: Some("c".repeat(64)),
    }
}

fn timeline() -> BrowserTimeline {
    BrowserTimeline {
        events: vec![
            BrowserTimelineEvent {
                sequence: 1,
                time: None,
                request: Some(RequestHop {
                    id: "req-1".to_owned(),
                    hop: Some(1),
                }),
                frame: None,
                loader: None,
                detail: BrowserEventDetail::RequestStarted {
                    method: Some("GET".to_owned()),
                    origin: Some("https://example.org".to_owned()),
                    endpoint_path: Some("/".to_owned()),
                    resource_type: Some("document".to_owned()),
                    initiator_type: Some("other".to_owned()),
                },
            },
            BrowserTimelineEvent {
                sequence: 2,
                time: None,
                request: Some(RequestHop {
                    id: "req-1".to_owned(),
                    hop: Some(1),
                }),
                frame: None,
                loader: None,
                detail: BrowserEventDetail::Response {
                    status: Some(200),
                    origin: Some("https://example.org".to_owned()),
                    endpoint_path: Some("/".to_owned()),
                    mime_type: Some("text/html".to_owned()),
                    cache_source: None,
                    timing: None,
                },
            },
            BrowserTimelineEvent {
                sequence: 3,
                time: None,
                request: Some(RequestHop {
                    id: "req-1".to_owned(),
                    hop: Some(1),
                }),
                frame: None,
                loader: None,
                detail: BrowserEventDetail::Completed {
                    encoded_bytes: Some(2048),
                },
            },
            BrowserTimelineEvent {
                sequence: 4,
                time: None,
                request: Some(RequestHop {
                    id: "req-2".to_owned(),
                    hop: Some(1),
                }),
                frame: None,
                loader: None,
                detail: BrowserEventDetail::NetworkFailure,
            },
        ],
        truncated: false,
        end: TimelineEnd::ObservationEnded,
    }
}

fn resources() -> Vec<ResourceTimingObs> {
    vec![
        ResourceTimingObs {
            url: "https://example.org/app.js".to_owned(),
            resource_type: "script".to_owned(),
            duration_ms: Some(120),
            transfer_size: Some(512),
            status_code: Some(200),
            ..ResourceTimingObs::default()
        },
        ResourceTimingObs {
            url: "https://example.org/unknown.js".to_owned(),
            resource_type: "script".to_owned(),
            ..ResourceTimingObs::default()
        },
    ]
}

fn interactive_inventory() -> InteractiveElementInventory {
    InteractiveElementInventory {
        elements: vec![
            InteractiveElementObs {
                node: 11,
                identity: identity("button"),
                tag: "button".to_owned(),
                role: Some("button".to_owned()),
                control_type: Some("submit".to_owned()),
                name_present: true,
                accessible_name_fingerprint: Some(fingerprint(11)),
                accessible_name_char_count: 7,
                visible: true,
                enabled: true,
                disabled: false,
                expanded: None,
                selected: None,
                checked: None,
                required: false,
                invalid: false,
                keyboard_focusable: true,
                tab_index: None,
                bbox: ElementBoundingBox {
                    x: 10,
                    y: 20,
                    width: 120,
                    height: 40,
                },
                target_link: None,
                safety_class: InteractionSafetyClass::StateChangingSubmission,
                functional_kind: FunctionalComponentKind::Cta,
            },
            InteractiveElementObs {
                node: 12,
                identity: identity("summary"),
                tag: "summary".to_owned(),
                role: None,
                control_type: None,
                name_present: true,
                accessible_name_fingerprint: Some(fingerprint(12)),
                accessible_name_char_count: 23,
                visible: true,
                enabled: true,
                disabled: false,
                expanded: Some(false),
                selected: None,
                checked: None,
                required: false,
                invalid: false,
                keyboard_focusable: true,
                tab_index: None,
                bbox: ElementBoundingBox {
                    x: 0,
                    y: 200,
                    width: 320,
                    height: 24,
                },
                target_link: None,
                safety_class: InteractionSafetyClass::ReadOnlyUiToggle,
                functional_kind: FunctionalComponentKind::Accordion,
            },
        ],
        limits: InteractiveInventoryLimits {
            max_elements: 256,
            discovered_elements: 2,
            elements_truncated: false,
        },
    }
}

fn application_state() -> ApplicationStateSnapshot {
    ApplicationStateSnapshot {
        document_ready_state: "complete".to_owned(),
        location_path: "/".to_owned(),
        history_length: 1,
        required_input_count: 1,
        alert_region_count: 1,
        network_idle_reached: true,
        structural_fingerprint: Some("d".repeat(64)),
        ..ApplicationStateSnapshot::default()
    }
}

fn journey_trace() -> UserJourneyTrace {
    UserJourneyTrace {
        candidate_scenarios: vec![CandidateJourneyScenario::AccordionExpansion],
        steps: vec![InteractionTraceStep {
            step_index: 0,
            action: InteractionActionKind::DisclosureToggle,
            target_node: Some(12),
            target_identity: Some(identity("summary")),
            expanded_changed: true,
            dom_fingerprint_changed: true,
            active_tag: Some("summary".to_owned()),
            active_role: None,
            state_changed: true,
            focus_changed: false,
            dialog_changed: false,
            runtime_errors_observed_in_window: 0,
            requests_observed_in_window: 0,
            observation_started_ms: Some(120),
            observation_window_ms: Some(250),
            window_termination: InteractionWindowTermination::WindowElapsed,
            restoration_attempted: true,
            restoration_succeeded: Some(true),
        }],
        truncated: false,
        probe_policy: InteractionProbePolicy::RestrictedBehaviouralProbe,
        network_requests_suppressed: false,
    }
}

fn visual_geometry() -> VisualGeometryInventory {
    VisualGeometryInventory {
        viewport_width: 1280,
        viewport_height: 720,
        elements: vec![ElementGeometryObs {
            node: 21,
            identity: identity("div"),
            tag: "div".to_owned(),
            bbox: ElementBoundingBox {
                x: 0,
                y: 100,
                width: 620,
                height: 36,
            },
            scroll_width: 620,
            client_width: 140,
            overflow_x: CssOverflowKind::Hidden,
            horizontal_overflow_px: 480,
            clipped_by_overflow: true,
            stacking: StackingContextObs {
                position: CssPositionKind::Static,
                z_index: None,
                establishes_stacking_context: false,
            },
            ..ElementGeometryObs::default()
        }],
        limits: VisualGeometryLimits {
            dom_truncated: false,
            depth_truncated: false,
            elements_truncated: false,
        },
    }
}

fn ax_inventory() -> AccessibilityNodeInventory {
    AccessibilityNodeInventory {
        nodes: vec![AccessibilityNodeObs {
            node_index: 1,
            ax_node_id: "1".to_owned(),
            role: "button".to_owned(),
            name_present: true,
            name_length: 7,
            name_fingerprint: Some("e".repeat(64)),
            name_source: AxNameSourceKind::Contents,
            focusable: true,
            interactive: true,
            ..AccessibilityNodeObs::default()
        }],
        limits: AccessibilityInventoryLimits {
            total_cdp_nodes: 1,
            nodes_truncated: false,
        },
    }
}

fn cookie_and_storage() -> CookieAndStorageInventory {
    CookieAndStorageInventory {
        cookies: vec![
            RuntimeCookieObs {
                name: "nzw_session".to_owned(),
                domain: "example.org".to_owned(),
                path: "/".to_owned(),
                secure: true,
                http_only: true,
                same_site: CookieSameSiteMode::Lax,
                session: true,
                value_byte_len: 10,
                third_party: Some(false),
                has_security_prefix: false,
                observed_before_consent: None,
            },
            RuntimeCookieObs {
                name: "ad_id".to_owned(),
                domain: ".tracker.example".to_owned(),
                path: "/".to_owned(),
                secure: false,
                http_only: false,
                same_site: CookieSameSiteMode::Unspecified,
                session: false,
                value_byte_len: 32,
                third_party: Some(true),
                has_security_prefix: false,
                observed_before_consent: None,
            },
        ],
        storage_keys: vec![StorageKeyObs {
            area: WebStorageArea::LocalStorage,
            key: "cart".to_owned(),
            value_byte_len: 8,
        }],
        indexed_db_count: 1,
        indexed_db_databases: vec!["app".to_owned()],
        indexed_db_enumerated: true,
        cookies_enumerated: true,
        storage_enumerated: true,
        limits: CookieStorageLimits {
            max_cookies: 64,
            cookies_truncated: false,
            max_storage_keys: 64,
            storage_keys_truncated: false,
        },
    }
}

fn third_party() -> ThirdPartyInventory {
    ThirdPartyInventory {
        origins: vec![ThirdPartyOriginObs {
            origin: "https://cdn.example".to_owned(),
            total_requests: 3,
            total_transfer_bytes: 4096,
            script_requests: 2,
            xhr_fetch_beacon_requests: 1,
            iframe_requests: 0,
            http_error_response_count: 0,
            capability: ThirdPartyCapabilitySummary {
                script_element_present_in_main_frame: true,
                script_without_sri_count: 1,
                script_with_sri_count: 1,
                ..ThirdPartyCapabilitySummary::default()
            },
        }],
        truncated: false,
    }
}

fn security_posture() -> SecurityPostureSummary {
    SecurityPostureSummary {
        csp_present: true,
        csp_unsafe_inline_script: true,
        x_content_type_options_nosniff: true,
        x_frame_options_present: true,
        referrer_policy_present: true,
        ..SecurityPostureSummary::default()
    }
}

fn performance_attribution() -> PerformanceAttributionEvidence {
    PerformanceAttributionEvidence {
        lcp_candidate: Some(LcpCandidateObs {
            identity: None,
            tag: "h1".to_owned(),
            candidate_source: LcpCandidateSource::DomGeometryHeuristic,
            render_time_ms: None,
            size_px_sq: 120_000,
            bbox: ElementBoundingBox {
                x: 0,
                y: 40,
                width: 600,
                height: 200,
            },
            above_the_fold: true,
            resource_origin: None,
            resource_path: None,
        }),
        total_cls_milli: Some(0),
        cls_shift_regions: Vec::new(),
        render_blocking_chain: RenderBlockingChainSummary {
            blocking_head_scripts: 1,
            blocking_head_stylesheets: 1,
            confirmed_blocking_transfer_bytes: Some(512),
            ..RenderBlockingChainSummary::default()
        },
    }
}

fn media_and_fonts() -> MediaAndFontInventory {
    MediaAndFontInventory {
        media_assets: vec![MediaAssetObs {
            node: 31,
            identity: identity("img"),
            tag: "img".to_owned(),
            format_class: MediaFormatClass::Webp,
            loading: MediaLoadingStrategy::Lazy,
            has_alt_attribute: true,
            resource_origin: Some("https://example.org".to_owned()),
            resource_path: Some("/hero.webp".to_owned()),
            rendered_width: 600,
            rendered_height: 300,
            natural_width: 1200,
            natural_height: 600,
            oversize_ratio_milli: 1000,
            has_intrinsic_sizing: true,
            has_responsive_sources: true,
            fetch_priority: None,
            above_the_fold: true,
            is_decorative: false,
        }],
        media_truncated: false,
        font_assets: vec![FontAssetObs {
            index: 0,
            font_family: "Inter".to_owned(),
            font_style: "normal".to_owned(),
            font_weight: "400".to_owned(),
            status: "loaded".to_owned(),
            font_display: FontDisplayPolicy::Swap,
            preloaded: false,
        }],
        fonts_truncated: false,
        total_font_transfer_bytes: 2048,
    }
}

fn indexability() -> IndexabilityAuthorityEvidence {
    IndexabilityAuthorityEvidence {
        effectively_indexable: true,
        canonical_tag_count: 1,
        canonical_is_self_referential: true,
        ..IndexabilityAuthorityEvidence::default()
    }
}

fn structured_data() -> StructuredDataInventory {
    StructuredDataInventory {
        json_ld_block_count: 1,
        malformed_json_ld_count: 0,
        entities: vec![StructuredEntitySummary {
            entity_index: 0,
            syntax: StructuredDataSyntax::JsonLd,
            schema_type: "Product".to_owned(),
            is_schema_org: true,
            property_keys: vec!["name".to_owned(), "offers".to_owned()],
            missing_required_fields: Vec::new(),
            valid: true,
        }],
        entities_truncated: false,
        social_card: SocialPreviewCardCompleteness {
            og_title_present: true,
            og_complete: true,
            ..SocialPreviewCardCompleteness::default()
        },
        issues: Vec::new(),
    }
}

fn responsive() -> ResponsiveComparisonEvidence {
    ResponsiveComparisonEvidence {
        mobile_viewport_width: 390,
        mobile_scroll_width: 620,
        desktop_viewport_width: 1280,
        desktop_scroll_width: 1280,
        desktop_visible_controls: Some(12),
        mobile_visible_controls: Some(9),
        mobile_undersized_touch_targets: Some(2),
        anomalies: vec![ResponsiveAnomalyObs {
            anomaly_index: 0,
            kind: ResponsiveAnomalyKind::MobileHorizontalOverflow,
            identity: None,
            tag: "div".to_owned(),
            mobile_metric_px: 620,
            desktop_metric_px: Some(1280),
        }],
        anomalies_truncated: false,
    }
}

fn link_graph() -> LinkGraphInventory {
    LinkGraphInventory {
        cluster_summary: LinkClusterSummary {
            internal_links: 3,
            external_links: 1,
            header_nav_links: 2,
            main_content_links: 1,
            footer_links: 1,
            empty_anchor_links: 0,
        },
        links: vec![RenderedLinkObs {
            link_index: 0,
            identity: identity("a"),
            placement_region: LinkPlacementRegion::HeaderOrNav,
            target_origin: Some("https://example.org".to_owned()),
            target_path: Some("/catalog".to_owned()),
            same_origin: true,
            fragment_only: false,
            visible: true,
            anchor_word_count: 1,
            anchor_text_fingerprint: Some(fingerprint(41)),
            rel_nofollow: false,
            rel_noopener: true,
            opens_new_tab: false,
        }],
        links_truncated: false,
        forms: vec![RenderedFormEndpointObs {
            form_index: 0,
            identity: identity("form"),
            method: "POST".to_owned(),
            action_origin: Some("https://example.org".to_owned()),
            action_path: Some("/checkout".to_owned()),
            secure_same_origin_action: true,
            field_count: 2,
            required_field_count: 1,
            has_sensitive_input: false,
        }],
        forms_truncated: false,
    }
}

fn visual_artifacts() -> VisualArtifactEvidence {
    VisualArtifactEvidence {
        viewport_screenshot_sha256: Some("f".repeat(64)),
        screenshot_byte_len: Some(20_480),
        viewport_width: Some(1280),
        viewport_height: Some(720),
        above_fold_retained_element_coverage_milli: Some(640),
        coverage_grid_columns: Some(40),
        coverage_grid_rows: Some(25),
        coverage_retained_element_count: Some(12),
        coverage_retained_element_limit: Some(64),
        coverage_elements_truncated: false,
        landmarks: vec![VisualRegionLandmarkObs {
            landmark_role: "banner".to_owned(),
            bbox: ElementBoundingBox {
                x: 0,
                y: 0,
                width: 1280,
                height: 72,
            },
            viewport_coverage_milli: 100,
            above_the_fold: true,
        }],
    }
}

fn service_worker() -> ServiceWorkerLifecycleEvidence {
    ServiceWorkerLifecycleEvidence {
        registration_state: ServiceWorkerRegistrationState::Activated,
        page_controlled: true,
        script_path: Some("/sw.js".to_owned()),
        scope_path: Some("/".to_owned()),
        cache_storage_bucket_count: 1,
        cache_bucket_names: vec!["nzw".to_owned()],
        sw_served_request_count: 2,
        disk_or_prefetch_cache_request_count: 1,
        manifest_link_present: true,
    }
}

fn tls_and_caa() -> TlsAndCaaDiagnostics {
    TlsAndCaaDiagnostics {
        protocol_version: Some("TLSv1.3".to_owned()),
        cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_owned()),
        caa_records: vec!["0 issue \"letsencrypt.org\"".to_owned()],
        caa_query_succeeded: true,
        caa_lookup_outcome: netzzwergenwacht::domain::CaaLookupOutcome::NotAttempted,
        ..TlsAndCaaDiagnostics::default()
    }
}

fn tls_evidence() -> TlsEvidence {
    TlsEvidence {
        subject: "CN=example.org".to_owned(),
        issuer: "CN=Example CA".to_owned(),
        not_before_unix_secs: Some(1_690_000_000),
        not_after_unix_secs: 1_750_000_000,
        days_until_expiry: 210,
        san_entries: vec!["example.org".to_owned()],
        public_key_algorithm: Some("rsa-2048".to_owned()),
        signature_algorithm: Some("sha256WithRSAEncryption".to_owned()),
        self_signed: false,
        caa_records: vec!["0 issue \"letsencrypt.org\"".to_owned()],
        caa_query_succeeded: true,
        caa_lookup_outcome: netzzwergenwacht::domain::CaaLookupOutcome::NotAttempted,
    }
}

fn browser_evidence() -> BrowserEvidence {
    BrowserEvidence {
        final_url: "https://example.org/".to_owned(),
        browser_version: Some("Chromium 141".to_owned()),
        timeline: Some(timeline()),
        rendered_content: Some(segmentation()),
        resources: resources(),
        resources_truncated: false,
        console_errors: vec![ConsoleErrorEvent {
            level: "error".to_owned(),
            text: "Uncaught TypeError".to_owned(),
            error_kind: Some("uncaught_exception".to_owned()),
            source_url: Some("https://example.org/app.js".to_owned()),
            line_number: Some(12),
        }],
        interactive_inventory: Some(interactive_inventory()),
        application_state: Some(application_state()),
        user_journey_trace: Some(journey_trace()),
        visual_geometry: Some(visual_geometry()),
        ax_node_inventory: Some(ax_inventory()),
        cookie_and_storage: Some(cookie_and_storage()),
        third_party_inventory: Some(third_party()),
        security_posture: Some(security_posture()),
        security_challenge: Some(SecurityChallengeEvidence::default()),
        performance_attribution: Some(performance_attribution()),
        media_and_fonts: Some(media_and_fonts()),
        indexability_authority: Some(indexability()),
        structured_data: Some(structured_data()),
        responsive_comparison: Some(responsive()),
        link_graph: Some(link_graph()),
        visual_artifacts: Some(visual_artifacts()),
        service_worker: Some(service_worker()),
        tls_and_caa: Some(tls_and_caa()),
        ..BrowserEvidence::default()
    }
}

fn captured_snapshot() -> EvidenceSnapshot {
    EvidenceSnapshot {
        target: target(),
        captured_at_unix_secs: 1_700_000_000,
        http: CollectorOutcome::Captured {
            data: HttpEvidence {
                final_url: "https://example.org/".to_owned(),
                status_code: 200,
                redirect_chain: Vec::new(),
                headers: vec![HttpHeader {
                    name: "content-type".to_owned(),
                    value: "text/html; charset=utf-8".to_owned(),
                }],
                elapsed_ms: Measurement::Measured {
                    value: 42,
                    unit: MeasurementUnit::Milliseconds,
                },
                body_bytes: SOURCE_HTML.len(),
                body_truncated: false,
                body_text: SOURCE_HTML.to_owned(),
            },
        },
        tls: CollectorOutcome::Captured {
            data: tls_evidence(),
        },
        browser: CollectorOutcome::Captured {
            data: browser_evidence(),
        },
        lighthouse: CollectorOutcome::Skipped {
            reason: "not collected".to_owned(),
        },
        axe: CollectorOutcome::Skipped {
            reason: "not collected".to_owned(),
        },
    }
}

#[test]
fn every_offline_query_reports_captured_evidence_with_populated_data() {
    let snapshot = captured_snapshot();

    let rendered = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0);
    assert_eq!(rendered.status, EvidenceQueryStatus::Captured);
    assert_eq!(rendered.total_matching, 3);
    assert_eq!(rendered.blocks.len(), 3);

    let source = query_source_vs_rendered(&snapshot);
    assert_eq!(source.status, EvidenceQueryStatus::Captured);
    assert_ne!(source.roles.len(), 0, "expected source role entries");

    let network = query_network_resources(&snapshot, &NetworkResourceFilter::default(), 0);
    assert_eq!(network.status, EvidenceQueryStatus::Captured);
    assert_eq!(network.total_matching, 2);

    let runtime = query_runtime_errors(&snapshot, &RuntimeErrorFilter::default(), 0);
    assert_eq!(runtime.status, EvidenceQueryStatus::Captured);
    assert_eq!(runtime.console_errors.len(), 1);

    let interactive =
        query_interactive_elements(&snapshot, &InteractiveElementFilter::default(), 0);
    assert_eq!(interactive.status, EvidenceQueryStatus::Captured);
    assert_eq!(interactive.elements.len(), 2);

    let state: ApplicationStateQueryPage<'_> = query_application_state(&snapshot);
    assert_eq!(state.status, EvidenceQueryStatus::Captured);
    assert!(state.state.is_some());

    let trace = query_interaction_trace(&snapshot, &InteractionStepFilter::default(), 0);
    assert_eq!(trace.status, EvidenceQueryStatus::Captured);
    assert_eq!(trace.steps.len(), 1);

    let geometry = query_element_geometry(&snapshot, &ElementGeometryFilter::default(), 0);
    assert_eq!(geometry.status, EvidenceQueryStatus::Captured);
    assert_eq!(geometry.elements.len(), 1);

    let ax = query_accessibility_nodes(&snapshot, &AccessibilityNodeFilter::default(), 0);
    assert_eq!(ax.status, EvidenceQueryStatus::Captured);
    assert_eq!(ax.nodes.len(), 1);

    let storage = query_storage_and_cookies(&snapshot, &StorageCookieFilter::default(), 0);
    assert_eq!(storage.status, EvidenceQueryStatus::Captured);
    assert_eq!(storage.cookies.len(), 2);
    assert_eq!(storage.storage_keys.len(), 1);

    let third_parties = query_third_party_origins(&snapshot, &ThirdPartyOriginFilter::default(), 0);
    assert_eq!(third_parties.status, EvidenceQueryStatus::Captured);
    assert_eq!(third_parties.origins.len(), 1);

    let posture = query_security_posture(&snapshot);
    assert_eq!(posture.status, EvidenceQueryStatus::Captured);
    assert!(posture.posture.is_some());

    let challenge = query_security_challenge(&snapshot);
    assert_eq!(challenge.status, EvidenceQueryStatus::Captured);
    assert!(challenge.challenge.is_some());

    let performance = query_performance_attribution(&snapshot);
    assert_eq!(performance.status, EvidenceQueryStatus::Captured);
    assert!(performance.attribution.is_some());

    let media = query_media_and_fonts(&snapshot, &MediaFontFilter::default(), 0);
    assert_eq!(media.status, EvidenceQueryStatus::Captured);
    assert_eq!(media.media_assets.len(), 1);
    assert_eq!(media.font_assets.len(), 1);

    let indexability_page = query_indexability_authority(&snapshot);
    assert_eq!(indexability_page.status, EvidenceQueryStatus::Captured);
    assert!(indexability_page.authority.is_some());

    let structured = query_structured_data(&snapshot, &StructuredDataFilter::default(), 0);
    assert_eq!(structured.status, EvidenceQueryStatus::Captured);
    assert_eq!(structured.entities.len(), 1);

    let responsive_page =
        query_responsive_comparison(&snapshot, &ResponsiveAnomalyFilter::default(), 0);
    assert_eq!(responsive_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(responsive_page.anomalies.len(), 1);

    let links = query_link_graph(&snapshot, &LinkGraphFilter::default(), 0);
    assert_eq!(links.status, EvidenceQueryStatus::Captured);
    assert_eq!(links.links.len(), 1);
    assert_eq!(links.forms.len(), 1);

    let artifacts = query_visual_artifacts(&snapshot);
    assert_eq!(artifacts.status, EvidenceQueryStatus::Captured);
    assert!(artifacts.artifacts.is_some());

    let worker = query_service_worker_lifecycle(&snapshot);
    assert_eq!(worker.status, EvidenceQueryStatus::Captured);
    assert!(worker.lifecycle.is_some());

    let tls = query_tls_and_caa(&snapshot);
    assert_eq!(tls.status, EvidenceQueryStatus::Captured);
    assert!(tls.handshake_tls.is_some());
    assert!(tls.diagnostics.is_some());

    let events = query_browser_timeline(&snapshot, 0).expect("timeline page");
    assert_eq!(events.events.len(), 4);

    let filtered = query_browser_timeline_filtered(&snapshot, &BrowserTimelineFilter::default(), 0);
    assert_eq!(filtered.status, EvidenceQueryStatus::Captured);
    assert_eq!(filtered.total_matching, 4);

    let chains = query_request_chains(&snapshot, &RequestChainFilter::default(), 0);
    assert_eq!(chains.status, EvidenceQueryStatus::Captured);
    assert_eq!(chains.total_matching, 2);

    let failed = query_failed_dependencies(&snapshot, &FailedDependencyFilter::default(), 0);
    assert_eq!(failed.status, EvidenceQueryStatus::Captured);
    assert_eq!(failed.dependencies.len(), 1);
}

#[test]
fn unavailable_and_failed_collectors_keep_their_own_status() {
    let mut skipped = captured_snapshot();
    skipped.browser = CollectorOutcome::Skipped {
        reason: "not collected".to_owned(),
    };
    let page = query_rendered_content(&skipped, &RenderedBlockFilter::default(), 0);
    assert!(matches!(page.status, EvidenceQueryStatus::Skipped { .. }));
    assert_eq!(page.total_matching, 0);

    let mut failed = captured_snapshot();
    failed.http = CollectorOutcome::Failed {
        error: "connection reset".to_owned(),
    };
    let source = query_source_vs_rendered(&failed);
    assert!(matches!(source.status, EvidenceQueryStatus::Failed { .. }));

    let mut captured_without_segmentation = captured_snapshot();
    if let CollectorOutcome::Captured { data } = &mut captured_without_segmentation.browser {
        data.rendered_content = None;
    }
    let page = query_rendered_content(
        &captured_without_segmentation,
        &RenderedBlockFilter::default(),
        0,
    );
    assert!(matches!(
        page.status,
        EvidenceQueryStatus::Unavailable { .. }
    ));
}

#[test]
fn unknown_numeric_observations_are_not_coerced_to_zero() {
    let snapshot = captured_snapshot();
    let page = query_network_resources(&snapshot, &NetworkResourceFilter::default(), 0);
    let unknown = page
        .resources
        .iter()
        .find(|resource| resource.url.ends_with("unknown.js"))
        .expect("unknown resource retained");
    assert!(
        unknown.duration_ms.is_none(),
        "an unobserved duration must stay absent"
    );
    assert!(unknown.transfer_size.is_none());

    let filtered = query_network_resources(
        &snapshot,
        &NetworkResourceFilter {
            min_duration_ms: Some(500),
            ..NetworkResourceFilter::default()
        },
        0,
    );
    assert_eq!(filtered.total_matching, 0);
}

#[test]
fn bounded_queries_expose_pagination_without_raw_text() {
    let mut snapshot = captured_snapshot();
    if let CollectorOutcome::Captured { data } = &mut snapshot.browser {
        let mut segmentation = segmentation();
        segmentation.blocks = (1..=20)
            .map(|node| RenderedContentBlock {
                node,
                kind: RenderedBlockKind::Paragraph,
                visibility: RenderedCssVisibility::Visible,
                visible_text: format!("secret payload {node}"),
                text_truncated: false,
                identity: Some(identity("p")),
                text_fingerprint: Some(fingerprint(u8::try_from(node).expect("small node"))),
            })
            .collect();
        data.rendered_content = Some(segmentation);
    }

    let first = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0);
    assert_eq!(first.blocks.len(), 16);
    assert_eq!(first.next_offset, Some(16));

    let second = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 16);
    assert_eq!(second.blocks.len(), 4);
    assert_eq!(second.next_offset, None);

    let context = netzzwergenwacht::investigation::rendered_content_context(Some(&snapshot));
    assert!(
        !context.contains("secret payload"),
        "raw text must not be exposed"
    );
    assert!(context.contains("text_fingerprint"));
}

#[test]
fn evidence_query_citations_reject_unknown_nodes() {
    let snapshot = captured_snapshot();
    let refs = netzzwergenwacht::investigation::cited_rendered_block_refs(&snapshot, &[1, 999]);
    assert_eq!(refs.len(), 1);
    assert!(refs[0].detail.contains("rendered-block-node=1"));
}

#[derive(Clone)]
struct StaticBackend {
    snapshot: EvidenceSnapshot,
}

impl DiagnosticBackend for StaticBackend {
    fn collect_http<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _budget: ExecutionBudget,
        _policy: TargetPolicy,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, EvidenceSnapshot> {
        let snapshot = self.snapshot.clone();
        Box::pin(async move { snapshot })
    }

    fn collect_browser<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CollectorOutcome<BrowserEvidence>> {
        Box::pin(async move {
            CollectorOutcome::Skipped {
                reason: "offline suite".to_owned(),
            }
        })
    }

    fn collect_axe<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CollectorOutcome<AxeEvidence>> {
        Box::pin(async move {
            CollectorOutcome::Skipped {
                reason: "offline suite".to_owned(),
            }
        })
    }

    fn collect_lighthouse<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CollectorOutcome<LighthouseMetrics>>
    {
        Box::pin(async move {
            CollectorOutcome::Skipped {
                reason: "offline suite".to_owned(),
            }
        })
    }

    fn collect_crawl<'a>(
        &'a self,
        target: &'a AuditTarget,
        _crawl_budget: CrawlBudget,
        _exec_budget: ExecutionBudget,
        _policy: TargetPolicy,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CrawlSummary> {
        let seed = target.clone();
        Box::pin(async move {
            CrawlSummary {
                seed,
                pages: Vec::new(),
                systemic_issues: Vec::new(),
                budget_exhausted: false,
                graph_results: Vec::new(),
            }
        })
    }
}

struct ScriptedLlm {
    replies: Mutex<VecDeque<String>>,
}

impl ScriptedLlm {
    fn new(replies: impl IntoIterator<Item = String>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().collect()),
        }
    }
}

impl LlmProvider for ScriptedLlm {
    fn model_name(&self) -> &'static str {
        "scripted-kommandant"
    }

    fn complete<'a>(
        &'a self,
        _system_prompt: &'a str,
        _user_prompt: &'a str,
        _budget: LlmBudget,
    ) -> LlmFuture<'a> {
        let reply = self
            .replies
            .lock()
            .expect("scripted replies")
            .pop_front()
            .unwrap_or_else(|| "{}".to_owned());
        Box::pin(async move { Ok(reply) })
    }
}

fn hypothesis_reply() -> String {
    r#"{"ready_to_conclude":false,"originating_rule":"rule.html.missing_csp","proposed_explanation":"Interactive controls may lack accessible names.","requested_tool":"query_interactive_elements","conclusion":null}"#.to_owned()
}

fn conclusion_reply() -> String {
    r#"{"ready_to_conclude":true,"originating_rule":"rule.html.missing_csp","proposed_explanation":"Concluded.","requested_tool":"","conclusion":"Two interactive controls observed; one is a read-only disclosure toggle."}"#.to_owned()
}

async fn investigate(evaluation: String) -> InvestigationReport {
    let snapshot = captured_snapshot();
    let backend: Arc<dyn DiagnosticBackend> = Arc::new(StaticBackend { snapshot });
    let llm = ScriptedLlm::new([hypothesis_reply(), evaluation, conclusion_reply()]);
    run_investigation(
        target(),
        "Verify interactive controls".to_owned(),
        TargetPolicy::PublicOnly,
        InvestigationBudget::default(),
        backend,
        &llm,
    )
    .await
}

#[tokio::test]
async fn kommandant_cites_interactive_nodes_and_supports_the_hypothesis() {
    let evaluation = r#"{"status":"supported","interactive_element_nodes":[11],"evaluation_summary":"Two controls observed.","conclusion":"Interactive controls confirmed."}"#;
    let report = investigate(evaluation.to_owned()).await;

    assert!(
        report
            .tool_trace
            .iter()
            .any(|record| record.tool_id == "query_interactive_elements"),
        "expected the offline query tool to be dispatched"
    );
    let hypothesis = report.hypotheses.first().expect("hypothesis recorded");
    assert_eq!(hypothesis.status, HypothesisStatus::Supported);
    assert!(
        !hypothesis.supporting_evidence.is_empty(),
        "supported hypothesis must carry validated citations"
    );
}

#[tokio::test]
async fn kommandant_without_citation_forces_inconclusive() {
    let evaluation = r#"{"status":"supported","evaluation_summary":"No citation supplied.","conclusion":"Claimed without evidence."}"#;
    let report = investigate(evaluation.to_owned()).await;

    let hypothesis = report.hypotheses.first().expect("hypothesis recorded");
    assert_eq!(
        hypothesis.status,
        HypothesisStatus::Inconclusive,
        "a query without citations must never support a hypothesis"
    );
}

#[tokio::test]
async fn retained_evidence_survives_saving_and_offline_reload() {
    let evaluation = r#"{"status":"supported","interactive_element_nodes":[11],"evaluation_summary":"Two controls observed.","conclusion":"Interactive controls confirmed."}"#;
    let report = investigate(evaluation.to_owned()).await;

    let retained = report
        .snapshot
        .as_ref()
        .expect("the investigation must retain its authoritative snapshot");
    let live_page = query_interactive_elements(retained, &InteractiveElementFilter::default(), 0);
    assert_eq!(live_page.status, EvidenceQueryStatus::Captured);

    let json = serde_json::to_string(&report).expect("serialise investigation report");
    let reloaded: InvestigationReport =
        serde_json::from_str(&json).expect("deserialise investigation report");
    let restored = reloaded
        .snapshot
        .as_ref()
        .expect("retained evidence must survive serialisation");
    let offline_page =
        query_interactive_elements(restored, &InteractiveElementFilter::default(), 0);
    assert_eq!(offline_page.status, EvidenceQueryStatus::Captured);
    assert_eq!(offline_page.total_matching, live_page.total_matching);

    let mut omitted = reloaded;
    omitted.snapshot = None;
    let path = std::env::temp_dir().join(format!(
        "nzw-evidence-retention-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        serde_json::to_string(&omitted).expect("serialise omitted report"),
    )
    .expect("write report without retained evidence");
    let artefacts = netzzwergenwacht::tui::load_offline_report(&path).expect("load offline report");
    assert!(
        artefacts.snapshot.is_none(),
        "an intentionally omitted snapshot must not reappear as captured evidence"
    );
    let _ = std::fs::remove_file(&path);
}

fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    let mut text = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text.push('\n');
    }
    text
}

#[test]
fn zwergenleitstand_renders_every_evidence_category() {
    let artefacts = DiagnosticArtefacts {
        target: "https://example.org/".to_owned(),
        mode: DiagnosticRunMode::DeterministicCheck,
        snapshot: Some(captured_snapshot()),
        audit_report: None,
        investigation_report: None,
        patrol_report: None,
        history_reports: Vec::new(),
        regression_report: None,
        elapsed_ms: 1_500,
    };
    let mut state = AppState::new(ThemeMode::StandardDark, GlyphSet::Unicode);
    state.ingest_artefacts(artefacts);
    state.active_view = WorkbenchView::Evidence;

    assert_eq!(EvidenceCategory::ALL.len(), 19);
    for category in EvidenceCategory::ALL {
        state.evidence_category = category;
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &state))
            .expect("render evidence view");
        let text = buffer_text(&terminal);
        assert!(
            text.contains(category.label()),
            "category label {:?} missing from rendered buffer",
            category.label()
        );
    }
}

#[test]
fn patrol_catalog_persists_and_answers_queries() {
    let dir = std::env::temp_dir().join(format!("nzw-wave-iv-catalog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let target = target();
    let mut memory = ApplicationMemory::new(&target, 1_700_000_120);
    memory.patrol_count = 2;
    memory.page_records.insert(
        "https://example.org/pricing".to_owned(),
        RememberedPage {
            url: "https://example.org/pricing".to_owned(),
            locale: None,
            page_type: PageType::Article,
            template_fingerprint: Some("tpl-pricing".to_owned()),
            content_hash: Some("body-hash".to_owned()),
            etag: None,
            last_modified: None,
            latest_report: None,
            last_inspected_unix_secs: 1_700_000_000,
            open_finding_count: 0,
            healthy_streak: 1,
            freshness: EvidenceFreshness::CurrentlyVerified,
        },
    );
    save_memory(&dir, &memory).expect("save memory");

    let targets = query_catalog_targets(&dir).expect("catalog targets");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].page_count, 1);

    let stale = query_catalog_stale_pages(&dir, 1_700_000_100).expect("stale pages");
    assert_eq!(stale.len(), 1);

    let report = PatrolReport {
        patrol_id: "patrol-1".to_owned(),
        patrol_number: 2,
        target: target.clone(),
        execution_succeeded: true,
        application_map: ApplicationMap {
            origin: "https://example.org".to_owned(),
            discovered_urls: vec!["https://example.org/pricing".to_owned()],
            locales_observed: Vec::new(),
            page_types: BTreeMap::new(),
            template_families: BTreeMap::new(),
            last_patrolled_unix_secs: 1_700_000_120,
        },
        sampling_plan: SamplingPlan {
            selections: Vec::new(),
            reused_urls: Vec::new(),
            total_discovered: 1,
        },
        reused_page_count: 0,
        coverage_matrix: CoverageMatrix {
            discovered_urls: 1,
            inspected_urls: 1,
            deep_inspected_urls: 1,
            reused_urls: 0,
            locales_observed: Vec::new(),
            page_types_observed: 1,
            template_families_observed: 1,
            limitations: Vec::new(),
        },
        resource_ledger: PatrolResourceLedger::default(),
        anomalies: vec![PatrolAnomaly {
            id: "anomaly-1".to_owned(),
            category: AnomalyCategory::NewDefect,
            affected_url: "https://example.org/pricing".to_owned(),
            severity: Severity::High,
            summary: "Missing Content-Security-Policy".to_owned(),
            suggested_competency: DwarfId::Sicherheits,
        }],
        graph_results: Vec::new(),
        specialist_escalations: Vec::new(),
        specialist_delegations: Vec::new(),
        investigation: None,
        regression: None,
        coverage_summary: "1 inspected URL".to_owned(),
        executive_summary: "Offline catalogue fixture".to_owned(),
        is_quiet_patrol: false,
        memory_load_error: None,
        memory_save_error: None,
    };
    let app_id = ApplicationId::from_origin(&Origin::from_target(&target));
    record_patrol_run(&dir, &app_id, &report).expect("record patrol run");

    let runs = query_catalog_runs(&dir, Some(&app_id.0), 10).expect("catalog runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].anomaly_count, 1);

    let anomalies = query_catalog_anomalies(
        &dir,
        &CatalogAnomalyFilter {
            app_id: None,
            min_severity: Some(Severity::Medium),
            category: None,
        },
    )
    .expect("catalog anomalies");
    assert_eq!(anomalies.len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}
