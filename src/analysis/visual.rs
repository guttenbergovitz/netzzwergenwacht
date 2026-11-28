//! `GestaltungsZwerg` — Level 2 visual layout and asset integrity checks.
//!
//! Analyses per-viewport [`BrowserEvidence`](crate::domain::BrowserEvidence)
//! observations for horizontal overflow and broken images (`naturalWidth == 0`).

use crate::analysis::document::DocumentObservations;
use crate::analysis::skip_all;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
    RuleId, Severity,
};

const RULE_HORIZONTAL_OVERFLOW: &str = "vis.layout.horizontal_overflow";
const RULE_BROKEN_IMAGES: &str = "vis.assets.broken_images";
const RULE_VIEWPORT_META: &str = "vis.mobile.viewport_meta";
const RULE_IMAGE_DIMENSIONS: &str = "vis.layout.image_dimensions";
const RULE_MODERN_IMAGE_FORMATS: &str = "vis.images.modern_formats";
const RULE_IMAGE_SRCSET: &str = "vis.images.responsive_srcset";
const RULE_IMAGE_FILENAME: &str = "vis.images.filename_quality";
const RULE_IMAGE_HOTLINKED: &str = "vis.images.hotlinked";
const RULE_INLINE_SVG_A11Y: &str = "vis.images.inline_svg_a11y";
const RULE_OVERSIZED_IMAGES: &str = "vis.rendered.oversized_images";
const RULE_ASPECT_DISTORTION: &str = "vis.rendered.aspect_ratio_distortion";
const RULE_ABOVE_FOLD_LAZY: &str = "vis.rendered.above_fold_lazy_lcp";
const RULE_MOBILE_SMALL_FONT: &str = "vis.mobile.small_font_size";
const RULE_MOBILE_TAP_TARGETS: &str = "vis.mobile.small_tap_targets";
const RULE_INLINE_DATA_URI: &str = "vis.images.inline_data_uri";
const RULE_VIDEO_CONTROLS_POSTER: &str = "vis.media.video_controls_or_poster";
const RULE_OFFSCREEN_CONTROL: &str = "vis.layout.offscreen_control";
const RULE_STICKY_HEADER_OBSTRUCTION: &str = "vis.layout.sticky_header_obstruction";
const RULE_IMAGE_PIXELATION: &str = "vis.images.pixelation_candidate";
const RULE_HIDDEN_DOWNLOADED_IMAGES: &str = "vis.rendered.hidden_downloaded_images";
const RULE_VIEWPORT_ZOOM_LOCKED: &str = "vis.mobile.viewport_zoom_locked";

/// All Level 2 rules owned by `GestaltungsZwerg`.
pub const ALL_RULES: &[&str] = &[RULE_HORIZONTAL_OVERFLOW, RULE_BROKEN_IMAGES];

/// All Level 1 source-document rules owned by `GestaltungsZwerg`.
pub const ALL_SOURCE_RULES: &[&str] = &[
    RULE_VIEWPORT_META,
    RULE_IMAGE_DIMENSIONS,
    RULE_MODERN_IMAGE_FORMATS,
    RULE_IMAGE_SRCSET,
    RULE_IMAGE_FILENAME,
    RULE_IMAGE_HOTLINKED,
    RULE_INLINE_SVG_A11Y,
    RULE_INLINE_DATA_URI,
    RULE_VIDEO_CONTROLS_POSTER,
    RULE_VIEWPORT_ZOOM_LOCKED,
];

/// Evaluates rendered viewport layout and image integrity observations.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    analyse_with_document(snapshot, None)
}

/// Evaluates `GestaltungsZwerg` when complete HTML document observations are unavailable.
#[must_use]
pub fn analyse_without_document(snapshot: &EvidenceSnapshot, reason: &str) -> AnalyserResult {
    let mut res = skip_all(
        DwarfId::Gestaltungs,
        ALL_SOURCE_RULES,
        EvidenceLevel::Source,
        reason,
    );
    let mut rendered = analyse(snapshot);
    res.findings.append(&mut rendered.findings);
    res.checks.append(&mut rendered.checks);
    res
}

/// Evaluates rendered viewport layout/images plus optional source-DOM layout checks.
#[must_use]
pub fn analyse_with_document(
    snapshot: &EvidenceSnapshot,
    obs: Option<&DocumentObservations>,
) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    if let Some(doc) = obs {
        check_viewport_meta(doc, &mut findings, &mut checks);
        check_image_dimensions(doc, &mut findings, &mut checks);
        check_modern_image_formats(doc, &mut findings, &mut checks);
        check_image_srcset(doc, &mut findings, &mut checks);
        check_image_filename_quality(doc, &mut findings, &mut checks);
        check_hotlinked_images(snapshot, doc, &mut findings, &mut checks);
        check_inline_svg_a11y(doc, &mut findings, &mut checks);
        check_inline_data_uri_images(doc, &mut findings, &mut checks);
        check_video_controls_or_poster(doc, &mut findings, &mut checks);
        check_viewport_zoom_locked(doc, &mut findings, &mut checks);
    }

    let browser = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { reason } => {
            let mut res = skip_all(
                DwarfId::Gestaltungs,
                ALL_RULES,
                EvidenceLevel::Rendered,
                reason,
            );
            findings.extend(res.findings);
            checks.append(&mut res.checks);
            return AnalyserResult {
                dwarf_id: DwarfId::Gestaltungs,
                findings,
                checks,
            };
        }
        CollectorOutcome::Failed { error } => {
            let mut res = skip_all(
                DwarfId::Gestaltungs,
                ALL_RULES,
                EvidenceLevel::Rendered,
                error,
            );
            findings.extend(res.findings);
            checks.append(&mut res.checks);
            return AnalyserResult {
                dwarf_id: DwarfId::Gestaltungs,
                findings,
                checks,
            };
        }
    };

    if browser.viewports.is_empty() {
        let mut res = skip_all(
            DwarfId::Gestaltungs,
            ALL_RULES,
            EvidenceLevel::Rendered,
            "no browser viewport observations captured",
        );
        findings.extend(res.findings);
        checks.append(&mut res.checks);
        return AnalyserResult {
            dwarf_id: DwarfId::Gestaltungs,
            findings,
            checks,
        };
    }

    check_horizontal_overflow(browser, &mut findings, &mut checks);
    check_broken_images(browser, &mut findings, &mut checks);
    check_rendered_image_geometry(browser, &mut findings, &mut checks);
    check_mobile_readability_and_tap_targets(browser, &mut findings, &mut checks);
    check_layout_obstructions_and_pixelation(browser, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Gestaltungs,
        findings,
        checks,
    }
}

fn check_horizontal_overflow(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let overflowing: Vec<_> = browser
        .viewports
        .iter()
        .filter(|vp| vp.has_horizontal_overflow)
        .collect();

    if overflowing.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HORIZONTAL_OVERFLOW.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    let evidence_refs = overflowing
        .iter()
        .map(|vp| {
            EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!(
                    "viewport '{}' ({}x{}) reported horizontal overflow",
                    vp.viewport_name, vp.width, vp.height
                ),
            )
        })
        .collect();
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_HORIZONTAL_OVERFLOW.to_owned()),
        category: FindingCategory::Visual,
        evidence_level: EvidenceLevel::Rendered,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!(
            "Horizontal layout overflow detected in {} viewport(s)",
            overflowing.len()
        ),
        summary: format!(
            "Rendered document scrollWidth exceeded viewport innerWidth in {} viewport(s).",
            overflowing.len()
        ),
        evidence_refs,
        remediation: Some(
            "Constrained wide elements with responsive CSS (for example max-width: 100% or overflow-x handling)."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_HORIZONTAL_OVERFLOW.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

fn check_broken_images(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let broken: Vec<_> = browser
        .viewports
        .iter()
        .flat_map(|vp| {
            vp.broken_images
                .iter()
                .filter(|img| img.natural_width == 0)
                .map(move |img| (vp.viewport_name.as_str(), img.src.as_str()))
        })
        .collect();

    if broken.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_BROKEN_IMAGES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    let evidence_refs = broken
        .iter()
        .take(5)
        .map(|(vp_name, src)| {
            EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("viewport '{vp_name}': broken image '{src}' (naturalWidth = 0)"),
            )
        })
        .collect();
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_BROKEN_IMAGES.to_owned()),
        category: FindingCategory::Visual,
        evidence_level: EvidenceLevel::Rendered,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!("{} broken rendered image(s) detected", broken.len()),
        summary: format!(
            "Rendered DOM reported {} image(s) with naturalWidth == 0.",
            broken.len()
        ),
        evidence_refs,
        remediation: Some(
            "Verify image URLs, MIME types, and responsive srcset candidates resolve cleanly."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_BROKEN_IMAGES.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

fn check_viewport_meta(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(vp) = obs.viewport_meta.as_deref() else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_VIEWPORT_META.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing mobile viewport meta tag".to_owned(),
            summary: "Document lacks `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "meta.viewport=absent",
            )],
            remediation: Some(
                "Add `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_VIEWPORT_META.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    let lower = vp.to_ascii_lowercase();
    if lower.contains("user-scalable=no") || lower.contains("user-scalable=0") {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_VIEWPORT_META.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Viewport meta disables user pinch-zoom".to_owned(),
            summary: format!("Viewport directive `{vp}` disables zoom (`user-scalable=no`)."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("meta.viewport={vp}"),
            )],
            remediation: Some(
                "Remove `user-scalable=no` so users can zoom freely on mobile devices.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_VIEWPORT_META.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_VIEWPORT_META.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_image_dimensions(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.images.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_IMAGE_DIMENSIONS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no <img> elements present".to_owned(),
        });
        return;
    }

    let missing_dims = obs
        .images
        .iter()
        .filter(|img| img.width.is_none() || img.height.is_none())
        .count();

    if missing_dims == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IMAGE_DIMENSIONS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IMAGE_DIMENSIONS.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Images missing explicit width/height ({missing_dims})"),
            summary: format!(
                "{missing_dims} of {} `<img>` element(s) lack explicit `width` or `height` attributes, risking layout shifts (CLS).",
                obs.images.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("missing_dimensions={missing_dims}/{}", obs.images.len()),
            )],
            remediation: Some(
                "Specify intrinsic `width` and `height` attributes on `<img>` elements."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IMAGE_DIMENSIONS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_modern_image_formats(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut legacy_count = 0usize;
    let mut modern_count = 0usize;

    for img in &obs.images {
        let Some(src) = img.src.as_deref() else {
            continue;
        };
        let path_part = src.split(['?', '#']).next().unwrap_or(src);
        let ext = std::path::Path::new(path_part)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        match ext.as_deref() {
            Some("webp" | "avif" | "svg") => modern_count += 1,
            Some("jpg" | "jpeg" | "png" | "bmp") => legacy_count += 1,
            _ => {}
        }
    }

    if legacy_count == 0 && modern_count == 0 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_MODERN_IMAGE_FORMATS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no raster/vector image extensions observed".to_owned(),
        });
        return;
    }

    if legacy_count >= 3 && modern_count == 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MODERN_IMAGE_FORMATS.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Only legacy raster image formats detected ({legacy_count})"),
            summary: format!(
                "Found {legacy_count} JPEG/PNG/BMP image(s) and 0 WebP/AVIF/SVG assets."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("legacy_images={legacy_count};modern_images=0"),
            )],
            remediation: Some(
                "Serve WebP or AVIF variants via `<picture>` or content negotiation.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MODERN_IMAGE_FORMATS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MODERN_IMAGE_FORMATS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_image_srcset(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let raster_images: Vec<_> = obs
        .images
        .iter()
        .filter(|img| {
            img.src.as_deref().is_some_and(|s| {
                !s.to_ascii_lowercase().ends_with(".svg") && !s.starts_with("data:")
            })
        })
        .collect();

    if raster_images.len() < 3 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_IMAGE_SRCSET.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "fewer than 3 non-SVG images".to_owned(),
        });
        return;
    }

    let missing_srcset = raster_images.iter().filter(|img| !img.has_srcset).count();
    if missing_srcset == raster_images.len() {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IMAGE_SRCSET.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: format!("Images lack responsive `srcset` ({missing_srcset})"),
            summary: format!(
                "None of the {missing_srcset} raster `<img>` elements declare `srcset` or `<picture><source srcset>`."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("missing_srcset={missing_srcset}"),
            )],
            remediation: Some(
                "Provide responsive `srcset` + `sizes` descriptors for multi-viewport delivery."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IMAGE_SRCSET.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IMAGE_SRCSET.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_image_filename_quality(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.images.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_IMAGE_FILENAME.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no <img> elements present".to_owned(),
        });
        return;
    }

    let poor_names = obs
        .images
        .iter()
        .filter(|img| {
            img.src.as_deref().is_some_and(|raw| {
                if raw.starts_with("data:") {
                    return false;
                }
                let file = raw
                    .split(['?', '#'])
                    .next()
                    .unwrap_or(raw)
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                file.contains("%20")
                    || file.contains(' ')
                    || file.starts_with("img_")
                    || file.starts_with("dsc_")
                    || file.starts_with("screenshot")
                    || file.starts_with("untitled")
            })
        })
        .count();

    if poor_names == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IMAGE_FILENAME.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IMAGE_FILENAME.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: format!("Generic or unencoded image filenames ({poor_names})"),
            summary: format!(
                "{poor_names} image(s) use generic camera/screenshot names or whitespace in filenames."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("poor_image_filenames={poor_names}"),
            )],
            remediation: Some(
                "Use descriptive, hyphenated, lowercase image filenames.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IMAGE_FILENAME.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_hotlinked_images(
    snapshot: &EvidenceSnapshot,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.images.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_IMAGE_HOTLINKED.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no <img> elements present".to_owned(),
        });
        return;
    }

    let page_url = match &snapshot.http {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            &data.final_url
        }
        _ => snapshot.target.as_str(),
    };
    let page_origin = url::Url::parse(page_url).ok().map(|u| u.origin());

    let external = obs
        .images
        .iter()
        .filter(|img| {
            img.src.as_deref().is_some_and(|raw| {
                url::Url::parse(raw)
                    .is_ok_and(|u| page_origin.as_ref().is_some_and(|o| u.origin() != *o))
            })
        })
        .count();

    if external == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IMAGE_HOTLINKED.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IMAGE_HOTLINKED.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: format!("External/cross-origin image dependencies ({external})"),
            summary: format!(
                "{external} `<img>` element(s) load from external origins rather than the page's own origin."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("external_images={external}"),
            )],
            remediation: Some(
                "Host critical visual assets on your own origin or controlled CDN.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IMAGE_HOTLINKED.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_inline_svg_a11y(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.inline_svg_without_a11y == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INLINE_SVG_A11Y.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INLINE_SVG_A11Y.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Inline <svg> elements without aria-hidden or label ({})",
                obs.inline_svg_without_a11y
            ),
            summary: format!(
                "Found {} inline `<svg>` element(s) lacking `aria-hidden=\"true\"`, `aria-label`, or `<title>`.",
                obs.inline_svg_without_a11y
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("inline_svg_without_a11y={}", obs.inline_svg_without_a11y),
            )],
            remediation: Some(
                "Add `aria-hidden=\"true\"` to decorative SVGs or `<title>`/`aria-label` to meaningful graphics."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INLINE_SVG_A11Y.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_rendered_image_geometry(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if browser.rendered_images.is_empty() {
        return;
    }

    let oversized: Vec<&str> = browser
        .rendered_images
        .iter()
        .filter(|img| {
            img.rendered_width > 0
                && img.natural_width > 200
                && img.natural_width > img.rendered_width.saturating_mul(2)
        })
        .map(|img| img.src.as_str())
        .collect();
    if oversized.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_OVERSIZED_IMAGES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_OVERSIZED_IMAGES.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Oversized rendered images (>2x natural width) ({})",
                oversized.len()
            ),
            summary: format!(
                "{} image(s) serve intrinsic widths more than double their rendered CSS width.",
                oversized.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("oversized_images={}", oversized.len()),
            )],
            remediation: Some(
                "Serve appropriately sized responsive image variants via `srcset` and `sizes`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_OVERSIZED_IMAGES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    check_rendered_image_distortion_and_lazy(browser, findings, checks);
}

fn check_rendered_image_distortion_and_lazy(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let distorted: Vec<&str> = browser
        .rendered_images
        .iter()
        .filter(|img| {
            if img.natural_width == 0
                || img.natural_height == 0
                || img.rendered_width == 0
                || img.rendered_height == 0
            {
                return false;
            }
            let lhs = u128::from(img.natural_width) * u128::from(img.rendered_height);
            let rhs = u128::from(img.rendered_width) * u128::from(img.natural_height);
            let diff = lhs.abs_diff(rhs);
            let max_val = lhs.max(rhs);
            diff.saturating_mul(4) > max_val
        })
        .map(|img| img.src.as_str())
        .collect();
    if distorted.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ASPECT_DISTORTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ASPECT_DISTORTION.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Rendered image aspect-ratio distortion ({})", distorted.len()),
            summary: format!(
                "{} image(s) render with >25% aspect ratio mismatch relative to intrinsic dimensions.",
                distorted.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("aspect_distorted_images={}", distorted.len()),
            )],
            remediation: Some(
                "Use `object-fit: cover` / `contain` or match CSS box dimensions to intrinsic aspect ratio."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ASPECT_DISTORTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    let above_fold_lazy: Vec<&str> = browser
        .rendered_images
        .iter()
        .filter(|img| {
            img.in_initial_viewport
                && img
                    .loading
                    .as_deref()
                    .is_some_and(|l| l.eq_ignore_ascii_case("lazy"))
        })
        .map(|img| img.src.as_str())
        .collect();
    if above_fold_lazy.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ABOVE_FOLD_LAZY.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ABOVE_FOLD_LAZY.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Above-the-fold images marked loading=\"lazy\" ({})",
                above_fold_lazy.len()
            ),
            summary: format!(
                "{} image(s) intersecting the initial viewport use `loading=\"lazy\"`, delaying LCP.",
                above_fold_lazy.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("above_fold_lazy_images={}", above_fold_lazy.len()),
            )],
            remediation: Some(
                "Remove `loading=\"lazy\"` from above-the-fold hero/LCP images.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ABOVE_FOLD_LAZY.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_mobile_readability_and_tap_targets(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(mobile) = browser
        .viewports
        .iter()
        .find(|vp| vp.viewport_name == "mobile")
    else {
        return;
    };

    if mobile.small_text_nodes > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MOBILE_SMALL_FONT.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Small mobile font sizes (<12px) ({})", mobile.small_text_nodes),
            summary: format!(
                "Mobile viewport measured {} visible text element(s) with computed font-size < 12px.",
                mobile.small_text_nodes
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("mobile_small_text_nodes={}", mobile.small_text_nodes),
            )],
            remediation: Some(
                "Use a legible base font size (>= 14–16px body, >= 12px captions) on mobile viewports."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MOBILE_SMALL_FONT.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MOBILE_SMALL_FONT.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    if mobile.small_tap_targets > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MOBILE_TAP_TARGETS.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Small mobile tap targets (<24x24px, WCAG 2.2 SC 2.5.8) ({})",
                mobile.small_tap_targets
            ),
            summary: format!(
                "Mobile viewport measured {} non-inline interactive element(s) smaller than 24x24 CSS px without 24px spacing clearance.",
                mobile.small_tap_targets
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("mobile_small_tap_targets={}", mobile.small_tap_targets),
            )],
            remediation: Some(
                "Ensure interactive targets meet at least 24x24 CSS px or maintain 24 CSS px spacing clearance (WCAG 2.2 SC 2.5.8)."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MOBILE_TAP_TARGETS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MOBILE_TAP_TARGETS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

/// Rendered bounding box of an interactive control used to evaluate WCAG 2.2 SC 2.5.8.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TapTargetRect {
    /// Left coordinate in CSS px.
    pub left: f64,
    /// Top coordinate in CSS px.
    pub top: f64,
    /// Width in CSS px.
    pub width: f64,
    /// Height in CSS px.
    pub height: f64,
    /// Whether the target is an inline link inside a block of running text.
    pub inline_in_text: bool,
}

/// Counts interactive controls violating WCAG 2.2 SC 2.5.8 (24x24 CSS px minimum,
/// with spacing clearance and inline-in-text exemptions).
#[must_use]
pub fn count_wcag_258_violations(targets: &[TapTargetRect]) -> usize {
    const MIN_SIZE: f64 = 24.0;
    const RADIUS: f64 = 12.0;
    const EPS: f64 = 0.01;

    let mut violations = 0usize;
    for (i, c) in targets.iter().enumerate() {
        if (c.width >= MIN_SIZE && c.height >= MIN_SIZE) || c.inline_in_text {
            continue;
        }
        let cx = c.left + c.width / 2.0;
        let cy = c.top + c.height / 2.0;

        let intersects = targets.iter().enumerate().any(|(j, o)| {
            if i == j {
                return false;
            }
            let o_right = o.left + o.width;
            let o_bottom = o.top + o.height;
            let nearest_x = cx.clamp(o.left, o_right);
            let nearest_y = cy.clamp(o.top, o_bottom);
            let dist_to_box = (cx - nearest_x).hypot(cy - nearest_y);
            if dist_to_box < RADIUS - EPS {
                return true;
            }
            if o.width < MIN_SIZE || o.height < MIN_SIZE {
                let ox = o.left + o.width / 2.0;
                let oy = o.top + o.height / 2.0;
                if (cx - ox).hypot(cy - oy) < MIN_SIZE - EPS {
                    return true;
                }
            }
            false
        });

        if intersects {
            violations += 1;
        }
    }
    violations
}

fn check_inline_data_uri_images(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let bloated = obs
        .images
        .iter()
        .filter(|img| {
            img.src
                .as_deref()
                .is_some_and(|s| s.starts_with("data:image/") && s.len() > 4096)
        })
        .count();

    if bloated == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INLINE_DATA_URI.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INLINE_DATA_URI.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Large inline data:image URI(s) ({bloated})"),
            summary: format!(
                "{bloated} <img> element(s) inline > 4 KiB base64/data URIs, inflating HTML and preventing caching."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("large_data_uri_images={bloated}"),
            )],
            remediation: Some(
                "Serve large images as external cacheable assets (AVIF/WebP/SVG) instead of data URIs."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INLINE_DATA_URI.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_video_controls_or_poster(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.videos_without_controls_or_poster == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_VIDEO_CONTROLS_POSTER.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_VIDEO_CONTROLS_POSTER.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "<video> elements missing controls or poster ({})",
                obs.videos_without_controls_or_poster
            ),
            summary: format!(
                "{} non-background <video> element(s) lack `controls` or a `poster` image.",
                obs.videos_without_controls_or_poster
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!(
                    "videos_without_controls_or_poster={}",
                    obs.videos_without_controls_or_poster
                ),
            )],
            remediation: Some(
                "Add `controls` and a `poster` attribute on interactive `<video>` elements."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_VIDEO_CONTROLS_POSTER.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_layout_obstructions_and_pixelation(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let offscreen_total: usize = browser.viewports.iter().map(|v| v.offscreen_controls).sum();
    if offscreen_total == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_OFFSCREEN_CONTROL.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_OFFSCREEN_CONTROL.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Offscreen interactive controls ({offscreen_total})"),
            summary: format!(
                "{offscreen_total} visible interactive control(s) sit outside the horizontal viewport bounds."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("offscreen_controls={offscreen_total}"),
            )],
            remediation: Some(
                "Ensure interactive controls stay within responsive viewport bounds without horizontal clipping."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_OFFSCREEN_CONTROL.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    let max_fixed_pct = browser
        .viewports
        .iter()
        .map(|v| v.fixed_header_height_pct)
        .max()
        .unwrap_or(0);
    if max_fixed_pct > 25 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_STICKY_HEADER_OBSTRUCTION.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Oversized sticky/fixed header ({max_fixed_pct}% of viewport)"),
            summary: format!(
                "A top fixed/sticky bar covers {max_fixed_pct}% of viewport height (> 25%), risking content and focus obstruction."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("fixed_header_height_pct={max_fixed_pct}"),
            )],
            remediation: Some(
                "Keep sticky headers compact (<= 15–20% of mobile viewport height) or unpin on scroll."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_STICKY_HEADER_OBSTRUCTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_STICKY_HEADER_OBSTRUCTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    check_image_pixelation(browser, findings, checks);
}

fn check_image_pixelation(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let pixelated = browser
        .rendered_images
        .iter()
        .filter(|img| {
            img.natural_width > 0 && img.rendered_width > img.natural_width.saturating_mul(2)
        })
        .count();
    if pixelated == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IMAGE_PIXELATION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IMAGE_PIXELATION.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Upscaled / pixelated rendered images ({pixelated})"),
            summary: format!(
                "{pixelated} rendered image(s) are displayed at more than 2x their intrinsic natural width."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("pixelated_images={pixelated}"),
            )],
            remediation: Some(
                "Provide higher-resolution image candidates via `srcset` so rendered dimensions do not exceed 2x natural width."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IMAGE_PIXELATION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    let hidden_downloaded = browser
        .rendered_images
        .iter()
        .filter(|img| {
            img.natural_width >= 200 && img.rendered_width == 0 && img.rendered_height == 0
        })
        .count();
    if hidden_downloaded == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HIDDEN_DOWNLOADED_IMAGES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HIDDEN_DOWNLOADED_IMAGES.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Hidden full-resolution images downloaded ({hidden_downloaded})"),
            summary: format!(
                "{hidden_downloaded} image(s) with naturalWidth >= 200px rendered at 0x0 CSS dimensions."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("hidden_downloaded_images={hidden_downloaded}"),
            )],
            remediation: Some(
                "Avoid loading hidden full-resolution images; use CSS media queries, `<picture>`, or lazy loading."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HIDDEN_DOWNLOADED_IMAGES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_viewport_zoom_locked(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(vp) = obs.viewport_meta.as_deref() else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_VIEWPORT_ZOOM_LOCKED.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "viewport meta tag absent".to_owned(),
        });
        return;
    };

    let locked = vp.split(',').any(|part| {
        let Some((k, v)) = part.trim().split_once('=') else {
            return false;
        };
        k.trim().eq_ignore_ascii_case("maximum-scale")
            && v.trim().parse::<f64>().is_ok_and(|scale| scale <= 1.0)
    });

    if locked {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_VIEWPORT_ZOOM_LOCKED.to_owned()),
            category: FindingCategory::Visual,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Viewport maximum-scale<=1.0 locks user zoom".to_owned(),
            summary: format!(
                "Viewport meta `{vp}` sets `maximum-scale <= 1.0`, preventing pinch-to-zoom."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("meta.viewport={vp}"),
            )],
            remediation: Some(
                "Remove `maximum-scale=1` or raise it to at least `5.0` to preserve zoom."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_VIEWPORT_ZOOM_LOCKED.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_VIEWPORT_ZOOM_LOCKED.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, BrokenImageObs, BrowserEvidence, TargetPolicy, ViewportLayoutObs,
    };

    fn base_snapshot(browser: CollectorOutcome<BrowserEvidence>) -> EvidenceSnapshot {
        EvidenceSnapshot {
            target: AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser,
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        }
    }

    #[test]
    fn skips_when_browser_evidence_missing() {
        let snap = base_snapshot(CollectorOutcome::default());
        let res = analyse(&snap);
        assert_eq!(res.dwarf_id, DwarfId::Gestaltungs);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), ALL_RULES.len());
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Skipped { .. }))
        );
    }

    #[test]
    fn passes_when_viewports_are_clean() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                browser_version: None,
                console_errors: Vec::new(),
                failed_requests: Vec::new(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    has_horizontal_overflow: false,
                    broken_images: Vec::new(),
                    small_text_nodes: 0,
                    small_tap_targets: 0,
                    screenshot_path: None,
                    ..ViewportLayoutObs::default()
                }],
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), 8);
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Passed { .. }))
        );
    }

    #[test]
    fn detects_horizontal_overflow_and_broken_images() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                browser_version: None,
                console_errors: Vec::new(),
                failed_requests: Vec::new(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    has_horizontal_overflow: true,
                    broken_images: vec![BrokenImageObs {
                        src: "https://example.com/hero.webp".to_owned(),
                        natural_width: 0,
                    }],
                    small_text_nodes: 0,
                    small_tap_targets: 0,
                    screenshot_path: None,
                    ..ViewportLayoutObs::default()
                }],
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 2);
        assert!(res.findings.iter().all(|f| !f.evidence_refs.is_empty()));
    }

    #[test]
    fn flags_missing_viewport_and_image_dimensions() {
        let snap = base_snapshot(CollectorOutcome::default());
        let obs = DocumentObservations::from_html(
            r#"<html><head><meta name="viewport" content="width=device-width, user-scalable=no"></head>
            <body><img src="/a.png" alt="A"></body></html>"#,
        );
        let res = analyse_with_document(&snap, Some(&obs));
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_VIEWPORT_META)
        );
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_IMAGE_DIMENSIONS)
        );
    }

    #[test]
    fn flags_legacy_formats_missing_srcset_poor_filenames_hotlink_and_svg_a11y() {
        let snap = base_snapshot(CollectorOutcome::default());
        let obs = DocumentObservations::from_html(
            r#"<html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
            <body>
                <img src="https://other.example.org/IMG_001.jpg" alt="One">
                <img src="/a.png" alt="Two">
                <img src="/b.jpeg" alt="Three">
                <svg viewBox="0 0 10 10"></svg>
            </body></html>"#,
        );
        let res = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_MODERN_IMAGE_FORMATS));
        assert!(ids.contains(&RULE_IMAGE_SRCSET));
        assert!(ids.contains(&RULE_IMAGE_FILENAME));
        assert!(ids.contains(&RULE_IMAGE_HOTLINKED));
        assert!(ids.contains(&RULE_INLINE_SVG_A11Y));
    }

    #[test]
    fn flags_oversized_distorted_and_above_fold_lazy_rendered_images() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "desktop".to_owned(),
                    width: 1280,
                    height: 720,
                    has_horizontal_overflow: false,
                    broken_images: Vec::new(),
                    small_text_nodes: 0,
                    small_tap_targets: 0,
                    screenshot_path: None,
                    ..ViewportLayoutObs::default()
                }],
                rendered_images: vec![crate::domain::RenderedImageObs {
                    src: "https://example.com/hero.webp".to_owned(),
                    natural_width: 1600,
                    natural_height: 800,
                    rendered_width: 400,
                    rendered_height: 400,
                    in_initial_viewport: true,
                    loading: Some("lazy".to_owned()),
                }],
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_OVERSIZED_IMAGES));
        assert!(ids.contains(&RULE_ASPECT_DISTORTION));
        assert!(ids.contains(&RULE_ABOVE_FOLD_LAZY));
    }

    #[test]
    fn flags_small_mobile_font_and_tap_targets() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    has_horizontal_overflow: false,
                    broken_images: Vec::new(),
                    small_text_nodes: 4,
                    small_tap_targets: 3,
                    screenshot_path: None,
                    ..ViewportLayoutObs::default()
                }],
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_MOBILE_SMALL_FONT));
        assert!(ids.contains(&RULE_MOBILE_TAP_TARGETS));
    }

    #[test]
    fn flags_large_data_uri_images_and_video_without_controls_or_poster() {
        let big_data = format!("data:image/png;base64,{}", "A".repeat(4200));
        let html = format!(
            r#"<html><body><img src="{big_data}" alt="Big"><video src="/clip.mp4"></video></body></html>"#
        );
        let obs = DocumentObservations::from_html(&html);
        let snap = base_snapshot(CollectorOutcome::Skipped {
            reason: "no browser".to_owned(),
        });
        let res = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_INLINE_DATA_URI));
        assert!(ids.contains(&RULE_VIDEO_CONTROLS_POSTER));
    }

    #[test]
    fn flags_offscreen_controls_sticky_header_and_pixelated_images() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    offscreen_controls: 2,
                    fixed_header_height_pct: 32,
                    ..ViewportLayoutObs::default()
                }],
                rendered_images: vec![crate::domain::RenderedImageObs {
                    src: "https://example.com/thumb.jpg".to_owned(),
                    natural_width: 100,
                    natural_height: 100,
                    rendered_width: 300,
                    rendered_height: 300,
                    in_initial_viewport: true,
                    loading: None,
                }],
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_OFFSCREEN_CONTROL));
        assert!(ids.contains(&RULE_STICKY_HEADER_OBSTRUCTION));
        assert!(ids.contains(&RULE_IMAGE_PIXELATION));
    }

    #[test]
    fn flags_hidden_downloaded_images_and_locked_maximum_scale() {
        let html = r#"<html><head><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"></head><body></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    ..ViewportLayoutObs::default()
                }],
                rendered_images: vec![crate::domain::RenderedImageObs {
                    src: "https://example.com/hidden-banner.jpg".to_owned(),
                    natural_width: 1200,
                    natural_height: 600,
                    rendered_width: 0,
                    rendered_height: 0,
                    in_initial_viewport: false,
                    loading: None,
                }],
                ..BrowserEvidence::default()
            },
        });
        let res = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_HIDDEN_DOWNLOADED_IMAGES));
        assert!(ids.contains(&RULE_VIEWPORT_ZOOM_LOCKED));
    }

    #[test]
    fn wcag_258_respects_24px_spacing_and_inline_exemption() {
        // 24x24px meets minimum directly.
        assert_eq!(
            count_wcag_258_violations(&[TapTargetRect {
                left: 0.0,
                top: 0.0,
                width: 24.0,
                height: 24.0,
                inline_in_text: false,
            }]),
            0
        );

        // Inline link in running text is exempt even when crowded.
        assert_eq!(
            count_wcag_258_violations(&[
                TapTargetRect {
                    left: 0.0,
                    top: 0.0,
                    width: 16.0,
                    height: 16.0,
                    inline_in_text: true,
                },
                TapTargetRect {
                    left: 18.0,
                    top: 0.0,
                    width: 16.0,
                    height: 16.0,
                    inline_in_text: true,
                },
            ]),
            0
        );

        // Isolated 16x16px targets >= 24px centre-to-centre apart pass spacing exemption.
        assert_eq!(
            count_wcag_258_violations(&[
                TapTargetRect {
                    left: 0.0,
                    top: 0.0,
                    width: 16.0,
                    height: 16.0,
                    inline_in_text: false,
                },
                TapTargetRect {
                    left: 24.0,
                    top: 0.0,
                    width: 16.0,
                    height: 16.0,
                    inline_in_text: false,
                },
            ]),
            0
        );

        // Crowded 16x16px targets (<24px centre-to-centre) both violate WCAG 2.2 SC 2.5.8.
        assert_eq!(
            count_wcag_258_violations(&[
                TapTargetRect {
                    left: 0.0,
                    top: 0.0,
                    width: 16.0,
                    height: 16.0,
                    inline_in_text: false,
                },
                TapTargetRect {
                    left: 18.0,
                    top: 0.0,
                    width: 16.0,
                    height: 16.0,
                    inline_in_text: false,
                },
            ]),
            2
        );
    }
}
