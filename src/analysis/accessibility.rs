//! `ZugänglichkeitsZwerg` — Phase 1 source-level accessibility checks.
//!
//! Evaluates statically verifiable accessibility requirements over
//! [`DocumentObservations`] and explicitly marks checks that require Level 2
//! (Rendered DOM / accessibility tree) or Level 3 (Behavioural) evidence as
//! unavailable. Automated checks are never presented as proof of WCAG or legal
//! compliance.

use crate::analysis::document::DocumentObservations;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, AxeEvidence, BrowserEvidence, CheckStatus, CollectorOutcome, Confidence,
    EvidenceLevel, EvidenceRef, EvidenceSource, Finding, FindingCategory, FindingFingerprint,
    FindingKind, RuleId, Severity,
};

const RULE_DOC_LANG: &str = "a11y.doc.lang";
const RULE_IMAGE_ALT: &str = "a11y.images.alt";
const RULE_FORM_LABELS: &str = "a11y.forms.labels";
const RULE_ARIA_REFS: &str = "a11y.aria.broken_references";
const RULE_INTERACTIVE_NAMES: &str = "a11y.interactive.accessible_name";
const RULE_TABLE_HEADERS: &str = "a11y.tables.headers";
const RULE_IFRAME_TITLE: &str = "a11y.iframes.title";
const RULE_POSITIVE_TABINDEX: &str = "a11y.focus.positive_tabindex";
const RULE_AUTOPLAY_MEDIA: &str = "a11y.media.autoplay_unmuted";
const RULE_MEDIA_CAPTIONS: &str = "a11y.media.missing_caption_track";
const RULE_SUSPICIOUS_ALT: &str = "a11y.images.suspicious_alternative_text";
const RULE_AMBIGUOUS_LINKS: &str = "a11y.links.ambiguous_accessible_name";
const RULE_RENDERED_AXE: &str = "a11y.rendered.contrast_and_axe";
const RULE_AX_MISSING_NAME: &str = "a11y.ax.missing_accessible_name";
const RULE_AX_HIDDEN_FOCUSABLE: &str = "a11y.ax.hidden_focusable_element";
const RULE_BEHAVIOURAL: &str = "a11y.behavioural.keyboard_and_focus";
const RULE_DOC_TITLE_PRESENCE: &str = "a11y.doc.title_presence";
const RULE_GENERIC_PAGE_TITLE: &str = "a11y.doc.generic_page_title";
const RULE_AX_HIGH_IGNORED_RATIO: &str = "a11y.ax.high_ignored_ratio";
const RULE_BEHAVIOURAL_FOCUS_TRAP: &str = "a11y.behavioural.focus_trap";
const RULE_BEHAVIOURAL_FOCUS_INDICATOR: &str = "a11y.behavioural.missing_focus_indicator";
const RULE_BEHAVIOURAL_UNREACHED_CONTROLS: &str = "a11y.behavioural.unreached_interactive_controls";
const RULE_BEHAVIOURAL_MODAL_CONTAINMENT: &str = "a11y.behavioural.modal_focus_containment";
const RULE_BEHAVIOURAL_OBSCURED_FOCUS: &str = "a11y.behavioural.obscured_focus";
const RULE_BEHAVIOURAL_FOCUS_RESTORATION: &str = "a11y.behavioural.focus_restoration";
const RULE_BEHAVIOURAL_SKIP_LINK_EFFECTIVE: &str = "a11y.behavioural.skip_link_effectiveness";
const RULE_BEHAVIOURAL_KEYBOARD_ACTIVATION: &str = "a11y.behavioural.keyboard_activation";

/// Source-level rule identifiers owned by `ZugänglichkeitsZwerg`.
pub const SOURCE_RULES: &[&str] = &[
    RULE_DOC_LANG,
    RULE_IMAGE_ALT,
    RULE_FORM_LABELS,
    RULE_ARIA_REFS,
    RULE_INTERACTIVE_NAMES,
    RULE_TABLE_HEADERS,
    RULE_IFRAME_TITLE,
    RULE_POSITIVE_TABINDEX,
    RULE_AUTOPLAY_MEDIA,
    RULE_MEDIA_CAPTIONS,
    RULE_SUSPICIOUS_ALT,
    RULE_AMBIGUOUS_LINKS,
    RULE_DOC_TITLE_PRESENCE,
    RULE_GENERIC_PAGE_TITLE,
];

/// Evaluates source-level accessibility checks and records higher-level gaps.
#[must_use]
pub fn analyse(obs: &DocumentObservations) -> AnalyserResult {
    analyse_with_axe(obs, &CollectorOutcome::default())
}

/// Evaluates source-level accessibility checks together with optional Level 2
/// `axe-core` evidence, while explicitly marking Level 3 behavioural checks
/// as unavailable.
#[must_use]
pub fn analyse_with_axe(
    obs: &DocumentObservations,
    axe: &CollectorOutcome<AxeEvidence>,
) -> AnalyserResult {
    analyse_with_browser(obs, axe, &CollectorOutcome::default())
}

/// Evaluates source-level accessibility checks together with optional Level 2
/// `axe-core` and Chromium Accessibility Tree evidence, while explicitly marking
/// Level 3 behavioural checks as unavailable.
#[must_use]
pub fn analyse_with_browser(
    obs: &DocumentObservations,
    axe: &CollectorOutcome<AxeEvidence>,
    browser: &CollectorOutcome<BrowserEvidence>,
) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_doc_lang(obs, &mut findings, &mut checks);
    check_image_alt(obs, &mut findings, &mut checks);
    check_form_labels(obs, &mut findings, &mut checks);
    check_aria_references(obs, &mut findings, &mut checks);
    check_interactive_names(obs, &mut findings, &mut checks);
    check_table_headers(obs, &mut findings, &mut checks);
    check_iframe_titles(obs, &mut findings, &mut checks);
    check_positive_tabindex(obs, &mut findings, &mut checks);
    check_autoplay_media(obs, &mut findings, &mut checks);
    check_media_captions(obs, &mut findings, &mut checks);
    check_suspicious_alt_text(obs, &mut findings, &mut checks);
    check_ambiguous_links(obs, &mut findings, &mut checks);
    check_doc_title_accessibility(obs, &mut findings, &mut checks);

    check_axe_violations(axe, &mut findings, &mut checks);
    check_ax_tree(browser, &mut findings, &mut checks);
    check_behavioural_a11y(browser, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Zugaenglichkeits,
        findings,
        checks,
    }
}

fn check_ax_tree(
    browser: &CollectorOutcome<BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let ax = match browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            data.ax_tree.as_ref()
        }
        CollectorOutcome::Skipped { .. } | CollectorOutcome::Failed { .. } => None,
    };

    let Some(tree) = ax else {
        for rule in [
            RULE_AX_MISSING_NAME,
            RULE_AX_HIDDEN_FOCUSABLE,
            RULE_AX_HIGH_IGNORED_RATIO,
        ] {
            checks.push(CheckStatus::Unavailable {
                rule_id: RuleId(rule.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
                reason: "Level 2 Chromium Accessibility Tree unavailable".to_owned(),
            });
        }
        return;
    };

    if tree.interactive_without_name == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_AX_MISSING_NAME.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_AX_MISSING_NAME.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!(
                "Interactive AX nodes missing accessible name ({})",
                tree.interactive_without_name
            ),
            summary: format!(
                "Chromium Accessibility Tree reported {} interactive node(s) without a computed accessible name.",
                tree.interactive_without_name
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("ax_interactive_without_name={}", tree.interactive_without_name),
            )],
            remediation: Some(
                "Ensure every interactive control has a visible label, `aria-label`, or `aria-labelledby`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_AX_MISSING_NAME.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    if tree.hidden_focusable_count == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_AX_HIDDEN_FOCUSABLE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_AX_HIDDEN_FOCUSABLE.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!(
                "Focusable elements inside ignored/aria-hidden subtrees ({})",
                tree.hidden_focusable_count
            ),
            summary: format!(
                "Chromium Accessibility Tree found {} focusable node(s) inside ignored/`aria-hidden` containers.",
                tree.hidden_focusable_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("ax_hidden_focusable={}", tree.hidden_focusable_count),
            )],
            remediation: Some(
                "Set `tabindex=\"-1\"` or `inert` on hidden containers so keyboard users cannot focus invisible controls."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_AX_HIDDEN_FOCUSABLE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    check_ax_ignored_ratio(tree, findings, checks);
}

fn check_behavioural_a11y(
    browser: &CollectorOutcome<BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let beh = match browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            data.behavioural_a11y.as_ref()
        }
        CollectorOutcome::Skipped { .. } | CollectorOutcome::Failed { .. } => None,
    };

    let Some(obs) = beh else {
        for rule in [
            RULE_BEHAVIOURAL,
            RULE_BEHAVIOURAL_FOCUS_TRAP,
            RULE_BEHAVIOURAL_FOCUS_INDICATOR,
            RULE_BEHAVIOURAL_UNREACHED_CONTROLS,
            RULE_BEHAVIOURAL_MODAL_CONTAINMENT,
            RULE_BEHAVIOURAL_OBSCURED_FOCUS,
            RULE_BEHAVIOURAL_FOCUS_RESTORATION,
            RULE_BEHAVIOURAL_SKIP_LINK_EFFECTIVE,
            RULE_BEHAVIOURAL_KEYBOARD_ACTIVATION,
        ] {
            checks.push(CheckStatus::Unavailable {
                rule_id: RuleId(rule.to_owned()),
                evidence_level: EvidenceLevel::Behavioural,
                reason: "Level 3 behavioural keyboard/focus probe unavailable".to_owned(),
            });
        }
        return;
    };

    emit_behavioural_check(
        RULE_BEHAVIOURAL_FOCUS_TRAP,
        obs.focus_trap_detected,
        Severity::High,
        "Keyboard focus trap detected during Tab traversal".to_owned(),
        format!(
            "Sequential `Tab` navigation became trapped after {} distinct stop(s).",
            obs.tab_stops_observed
        ),
        format!(
            "focus_trap_detected=true;tab_stops={}",
            obs.tab_stops_observed
        ),
        "Ensure keyboard focus can move freely past all widgets or exit modals via `Escape`.",
        findings,
        checks,
    );

    emit_behavioural_check(
        RULE_BEHAVIOURAL_FOCUS_INDICATOR,
        obs.missing_focus_indicator_count > 0,
        Severity::Medium,
        format!(
            "Focused controls without visible focus indicator ({})",
            obs.missing_focus_indicator_count
        ),
        format!(
            "{} control(s) matched `:focus-visible` with `outline: none` and no `box-shadow`.",
            obs.missing_focus_indicator_count
        ),
        format!(
            "missing_focus_indicator_count={}",
            obs.missing_focus_indicator_count
        ),
        "Preserve or style a high-contrast `:focus-visible` outline on all interactive elements.",
        findings,
        checks,
    );

    let unreached = obs.tabbable_candidates > 0
        && (obs.tab_stops_observed == 0
            || (!obs.tab_budget_exhausted
                && obs.tab_stops_observed.saturating_mul(2) < obs.tabbable_candidates));
    emit_behavioural_check(
        RULE_BEHAVIOURAL_UNREACHED_CONTROLS,
        unreached,
        if obs.tab_stops_observed == 0 {
            Severity::High
        } else {
            Severity::Medium
        },
        if obs.tab_stops_observed == 0 {
            "No tabbable controls reached during Tab traversal".to_owned()
        } else {
            format!(
                "Many interactive controls unreached during Tab traversal ({} of {})",
                obs.tabbable_candidates
                    .saturating_sub(obs.tab_stops_observed),
                obs.tabbable_candidates
            )
        },
        format!(
            "Detected {} visible interactive candidate(s), but `Tab` traversal reached {} control(s).",
            obs.tabbable_candidates, obs.tab_stops_observed
        ),
        format!(
            "tabbable_candidates={};tab_stops_observed={};budget_exhausted={}",
            obs.tabbable_candidates, obs.tab_stops_observed, obs.tab_budget_exhausted
        ),
        "Ensure interactive elements are keyboard-focusable and not blocked by `inert` or `tabindex=\"-1\"`.",
        findings,
        checks,
    );

    check_modal_and_obscured_focus(obs, findings, checks);
    emit_behavioural_summary(obs, unreached, findings, checks);
}

fn check_modal_and_obscured_focus(
    obs: &crate::domain::BehaviouralA11yObs,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.open_dialogs_count == 0 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_BEHAVIOURAL_MODAL_CONTAINMENT.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
            reason: "no open modal/dialog detected on initial load".to_owned(),
        });
    } else {
        emit_behavioural_check(
            RULE_BEHAVIOURAL_MODAL_CONTAINMENT,
            obs.modal_focus_escaped,
            Severity::High,
            "Keyboard focus escaped open modal dialog".to_owned(),
            format!(
                "With {} open dialog(s), `Tab` traversal moved focus outside the modal container.",
                obs.open_dialogs_count
            ),
            format!(
                "open_dialogs={};modal_focus_escaped={}",
                obs.open_dialogs_count, obs.modal_focus_escaped
            ),
            "Trap Tab/Shift+Tab focus inside open modal dialogs and mark background content `inert`.",
            findings,
            checks,
        );
    }

    emit_behavioural_check(
        RULE_BEHAVIOURAL_OBSCURED_FOCUS,
        obs.obscured_focus_count > 0,
        Severity::Medium,
        format!(
            "Focused controls obscured by overlapping elements ({})",
            obs.obscured_focus_count
        ),
        format!(
            "{} focused control(s) had another element (such as a sticky header or overlay) covering their center point.",
            obs.obscured_focus_count
        ),
        format!("obscured_focus_count={}", obs.obscured_focus_count),
        "Add `scroll-margin-top` / `scroll-padding-top` or dismiss overlays so focused controls remain visible.",
        findings,
        checks,
    );

    if obs.dialog_escape_closed == Some(true) {
        emit_behavioural_check(
            RULE_BEHAVIOURAL_FOCUS_RESTORATION,
            obs.focus_lost_after_dialog_close == Some(true),
            Severity::Medium,
            "Focus lost to document body after dismissing modal".to_owned(),
            "Closing the open modal with `Escape` left `document.activeElement` on `<body>`/`<html>` instead of restoring focus.".to_owned(),
            "focus_lost_after_dialog_close=true".to_owned(),
            "Restore focus to the triggering control when a modal dialog closes.",
            findings,
            checks,
        );
    } else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_BEHAVIOURAL_FOCUS_RESTORATION.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
            reason: "no modal dialog was dismissed via Escape".to_owned(),
        });
    }

    match obs.skip_link_effective {
        Some(effective) => emit_behavioural_check(
            RULE_BEHAVIOURAL_SKIP_LINK_EFFECTIVE,
            !effective,
            Severity::Medium,
            "Skip-to-content link did not move focus or scroll".to_owned(),
            "Activating the skip-navigation link failed to move focus or viewport scroll to its target.".to_owned(),
            "skip_link_effective=false".to_owned(),
            "Ensure the skip link `href` matches an existing landmark `id` with `tabindex=\"-1\"` if non-interactive.",
            findings,
            checks,
        ),
        None => checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_BEHAVIOURAL_SKIP_LINK_EFFECTIVE.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
            reason: "no skip-navigation link detected in DOM".to_owned(),
        }),
    }

    emit_behavioural_check(
        RULE_BEHAVIOURAL_KEYBOARD_ACTIVATION,
        obs.unfocusable_aria_controls_count > 0,
        Severity::High,
        format!(
            "Custom ARIA button/link controls not keyboard-focusable ({})",
            obs.unfocusable_aria_controls_count
        ),
        format!(
            "{} visible `[role=\"button\"]` or `[role=\"link\"]` element(s) lack `tabindex >= 0`.",
            obs.unfocusable_aria_controls_count
        ),
        format!(
            "unfocusable_aria_controls_count={}",
            obs.unfocusable_aria_controls_count
        ),
        "Use native `<button>`/`<a href>` elements or add `tabindex=\"0\"` with Enter/Space key handlers.",
        findings,
        checks,
    );
}

fn emit_behavioural_summary(
    obs: &crate::domain::BehaviouralA11yObs,
    unreached: bool,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let dialog_stuck = obs.dialog_escape_closed == Some(false);
    emit_behavioural_check(
        RULE_BEHAVIOURAL,
        obs.focus_trap_detected
            || obs.missing_focus_indicator_count > 0
            || unreached
            || dialog_stuck,
        Severity::Medium,
        "Keyboard and focus management defects observed".to_owned(),
        format!(
            "Behavioural probe observed tab_stops={}, candidates={}, focus_trap={}, missing_indicators={}, dialog_escape_closed={:?}.",
            obs.tab_stops_observed,
            obs.tabbable_candidates,
            obs.focus_trap_detected,
            obs.missing_focus_indicator_count,
            obs.dialog_escape_closed
        ),
        format!(
            "tab_stops={};candidates={}",
            obs.tab_stops_observed, obs.tabbable_candidates
        ),
        "Verify sequential keyboard traversal, visible `:focus-visible` rings, and `Escape` dismissal for dialogs.",
        findings,
        checks,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_behavioural_check(
    rule_id: &str,
    failed: bool,
    severity: Severity,
    title: String,
    summary: String,
    evidence_detail: String,
    remediation: &str,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if !failed {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(rule_id.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(rule_id.to_owned()),
        category: FindingCategory::Accessibility,
        evidence_level: EvidenceLevel::Behavioural,
        kind: FindingKind::Deterministic,
        severity,
        confidence: Confidence::Medium,
        title,
        summary,
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::BrowserRuntime,
            evidence_detail,
        )],
        remediation: Some(remediation.to_owned()),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(rule_id.to_owned()),
        evidence_level: EvidenceLevel::Behavioural,
    });
}

/// Evaluates only Level 2 `axe-core` evidence without re-running source HTML checks.
#[must_use]
pub fn analyse_axe_only(axe: &CollectorOutcome<AxeEvidence>) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();
    check_axe_violations(axe, &mut findings, &mut checks);
    AnalyserResult {
        dwarf_id: DwarfId::Zugaenglichkeits,
        findings,
        checks,
    }
}

fn check_axe_violations(
    axe: &CollectorOutcome<AxeEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let data = match axe {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { .. } | CollectorOutcome::Failed { .. } => {
            checks.push(CheckStatus::Unavailable {
                rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
                reason:
                    "Colour contrast, computed styles, and axe-core require Level 2 rendered DOM evidence"
                        .to_owned(),
            });
            return;
        }
    };

    if data.violations.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    for violation in &data.violations {
        let severity = match violation.impact.as_deref() {
            Some("critical") => Severity::High,
            Some("serious" | "moderate") => Severity::Medium,
            _ => Severity::Low,
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(format!("a11y.rendered.axe.{}", violation.id)),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity,
            confidence: Confidence::High,
            title: format!(
                "axe-core rule '{}' failed ({} node(s))",
                violation.id, violation.nodes_count
            ),
            summary: violation.description.clone(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::AxeReport,
                format!(
                    "axe-core {} rule '{}' affected {} node(s); help: {}",
                    data.axe_version, violation.id, violation.nodes_count, violation.help_url
                ),
            )],
            remediation: Some(format!("Review axe-core guidance: {}", violation.help_url)),
        });
    }

    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

/// Builds a skipped result when source HTML is absent or truncated, preserving
/// explicit `Unavailable` markers for Level 2/3 checks.
#[must_use]
pub fn skipped_source_result(reason: &str) -> AnalyserResult {
    let mut checks: Vec<CheckStatus> = SOURCE_RULES
        .iter()
        .map(|id| CheckStatus::Skipped {
            rule_id: RuleId((*id).to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: reason.to_owned(),
        })
        .collect();
    checks.push(CheckStatus::Unavailable {
        rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
        reason: "Level 2 rendered DOM evidence unavailable".to_owned(),
    });
    checks.push(CheckStatus::Unavailable {
        rule_id: RuleId(RULE_BEHAVIOURAL.to_owned()),
        evidence_level: EvidenceLevel::Behavioural,
        reason: "Level 3 behavioural evidence unavailable".to_owned(),
    });
    AnalyserResult {
        dwarf_id: DwarfId::Zugaenglichkeits,
        findings: Vec::new(),
        checks,
    }
}

fn check_doc_lang(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.html_lang.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DOC_LANG.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DOC_LANG.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing <html lang> attribute".to_owned(),
            summary: "Document root `<html>` lacks a non-empty `lang` attribute for assistive technologies.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "html.lang=absent_or_empty",
            )],
            remediation: Some("Set a valid BCP 47 language tag on `<html>`, e.g. `<html lang=\"en-GB\">`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DOC_LANG.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_image_alt(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let missing_count = obs.images.iter().filter(|img| img.alt.is_none()).count();
    if missing_count == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IMAGE_ALT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IMAGE_ALT.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Images missing alt attribute ({missing_count})"),
            summary: format!(
                "{missing_count} of {} `<img>` elements lack an `alt` attribute (use `alt=\"\"` for decorative images).",
                obs.images.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("images_missing_alt={missing_count}"),
            )],
            remediation: Some(
                "Add descriptive `alt` text to informative images or `alt=\"\"` to decorative ones."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IMAGE_ALT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_form_labels(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let unlabelled = obs
        .form_controls
        .iter()
        .filter(|ctrl| {
            let has_for_label = ctrl
                .id
                .as_ref()
                .is_some_and(|id| obs.label_for_ids.contains(id));
            !ctrl.has_wrapping_label
                && !has_for_label
                && ctrl.aria_label.is_none()
                && ctrl.aria_labelledby.is_none()
        })
        .count();

    if unlabelled == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FORM_LABELS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FORM_LABELS.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::High,
            confidence: Confidence::Medium,
            title: format!("Potentially unlabelled form controls ({unlabelled})"),
            summary: format!(
                "{unlabelled} form controls lack a matching `<label>`, `aria-label`, or `aria-labelledby`."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("unlabelled_controls={unlabelled}"),
            )],
            remediation: Some(
                "Associate each form control with a `<label for=\"...\">` or ARIA label."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FORM_LABELS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_aria_references(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut broken = Vec::new();
    for aria_ref in &obs.aria_refs {
        for target_id in &aria_ref.referenced_ids {
            if !obs.all_ids.contains(target_id) {
                broken.push(format!(
                    "{}[{}]={target_id}",
                    aria_ref.element_tag, aria_ref.attr_name
                ));
            }
        }
    }

    if broken.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ARIA_REFS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let sample = broken
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ARIA_REFS.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Unresolved ARIA ID references ({})", broken.len()),
            summary: format!("ARIA reference attributes point to missing IDs: {sample}."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("broken_aria_refs={sample}"),
            )],
            remediation: Some(
                "Ensure all IDs referenced by `aria-labelledby`/`aria-describedby` exist."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ARIA_REFS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_interactive_names(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let missing = obs.links_missing_accessible_name + obs.buttons_missing_accessible_name;
    if missing == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INTERACTIVE_NAMES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_NAMES.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Interactive controls potentially missing accessible names ({missing})"),
            summary: format!(
                "Observed {} `<a href>` and {} `<button>` elements without visible text or `aria-label`/`title`.",
                obs.links_missing_accessible_name, obs.buttons_missing_accessible_name
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!(
                    "empty_links={},empty_buttons={}",
                    obs.links_missing_accessible_name, obs.buttons_missing_accessible_name
                ),
            )],
            remediation: Some(
                "Provide text content, `aria-label`, or descriptive `img[alt]` inside links and buttons."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INTERACTIVE_NAMES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

struct CountRuleSpec<'a> {
    rule_id: &'a str,
    count: usize,
    severity: Severity,
    title: String,
    summary: String,
    evidence_detail: String,
    remediation: &'a str,
}

fn check_count_rule(
    spec: CountRuleSpec<'_>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if spec.count == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(spec.rule_id.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(spec.rule_id.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: spec.severity,
            confidence: Confidence::High,
            title: spec.title,
            summary: spec.summary,
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                spec.evidence_detail,
            )],
            remediation: Some(spec.remediation.to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(spec.rule_id.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_table_headers(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    check_count_rule(
        CountRuleSpec {
            rule_id: RULE_TABLE_HEADERS,
            count: obs.tables_without_headers,
            severity: Severity::Medium,
            title: format!(
                "Data tables without <th> headers ({})",
                obs.tables_without_headers
            ),
            summary: format!(
                "{} non-presentational <table> element(s) lack <th> header cells.",
                obs.tables_without_headers
            ),
            evidence_detail: format!("tables_without_headers={}", obs.tables_without_headers),
            remediation: "Add <th> header cells (with `scope`) to data tables, or `role=\"presentation\"` for layout tables.",
        },
        findings,
        checks,
    );
}

fn check_iframe_titles(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    check_count_rule(
        CountRuleSpec {
            rule_id: RULE_IFRAME_TITLE,
            count: obs.iframes_without_title,
            severity: Severity::Medium,
            title: format!(
                "<iframe> elements missing accessible title ({})",
                obs.iframes_without_title
            ),
            summary: format!(
                "{} visible <iframe> element(s) lack a `title` or `aria-label` attribute.",
                obs.iframes_without_title
            ),
            evidence_detail: format!("iframes_without_title={}", obs.iframes_without_title),
            remediation: "Provide a descriptive `title` attribute on every non-hidden <iframe>.",
        },
        findings,
        checks,
    );
}

fn check_positive_tabindex(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    check_count_rule(
        CountRuleSpec {
            rule_id: RULE_POSITIVE_TABINDEX,
            count: obs.positive_tabindex_count,
            severity: Severity::Medium,
            title: format!(
                "Positive tabindex values detected ({})",
                obs.positive_tabindex_count
            ),
            summary: format!(
                "{} element(s) use `tabindex > 0`, which disrupts natural keyboard focus order.",
                obs.positive_tabindex_count
            ),
            evidence_detail: format!("positive_tabindex_count={}", obs.positive_tabindex_count),
            remediation: "Remove positive `tabindex` values and rely on DOM order with `tabindex=\"0\"` or `-1`.",
        },
        findings,
        checks,
    );
}

fn check_autoplay_media(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    check_count_rule(
        CountRuleSpec {
            rule_id: RULE_AUTOPLAY_MEDIA,
            count: obs.autoplay_unmuted_media,
            severity: Severity::Medium,
            title: format!(
                "Unmuted autoplay media elements ({})",
                obs.autoplay_unmuted_media
            ),
            summary: format!(
                "{} <video>/<audio> element(s) declare `autoplay` without `muted`.",
                obs.autoplay_unmuted_media
            ),
            evidence_detail: format!("autoplay_unmuted_media={}", obs.autoplay_unmuted_media),
            remediation: "Avoid auto-playing unmuted audio/video; require explicit user interaction or add `muted`.",
        },
        findings,
        checks,
    );
}

fn check_media_captions(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    check_count_rule(
        CountRuleSpec {
            rule_id: RULE_MEDIA_CAPTIONS,
            count: obs.videos_without_captions,
            severity: Severity::Medium,
            title: format!(
                "<video> elements missing caption tracks ({})",
                obs.videos_without_captions
            ),
            summary: format!(
                "{} non-background <video> element(s) lack a `<track kind=\"captions\">` or `subtitles` element.",
                obs.videos_without_captions
            ),
            evidence_detail: format!("videos_without_captions={}", obs.videos_without_captions),
            remediation: "Add `<track kind=\"captions\" src=\"...\" srclang=\"...\">` to video elements.",
        },
        findings,
        checks,
    );
}

fn check_suspicious_alt_text(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const GENERIC_ALT: &[&str] = &[
        "image",
        "img",
        "photo",
        "picture",
        "graphic",
        "icon",
        "placeholder",
    ];
    let suspicious = obs
        .images
        .iter()
        .filter_map(|img| img.alt.as_deref())
        .map(|a| a.trim().to_ascii_lowercase())
        .filter(|lower| {
            !lower.is_empty()
                && (GENERIC_ALT.contains(&lower.as_str())
                    || std::path::Path::new(lower)
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| matches!(e, "jpg" | "jpeg" | "png" | "webp"))
                    || lower.starts_with("dsc_")
                    || lower.starts_with("img_"))
        })
        .count();
    check_count_rule(
        CountRuleSpec {
            rule_id: RULE_SUSPICIOUS_ALT,
            count: suspicious,
            severity: Severity::Low,
            title: format!("Suspicious or filename-like image alt text ({suspicious})"),
            summary: format!(
                "{suspicious} <img> element(s) use generic or filename-like `alt` text (for example `image`, `IMG_...`, `.jpg`)."
            ),
            evidence_detail: format!("suspicious_alt_count={suspicious}"),
            remediation: "Replace generic or filename `alt` attributes with meaningful descriptions (or `alt=\"\"` if decorative).",
        },
        findings,
        checks,
    );
}

fn check_ambiguous_links(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const AMBIGUOUS: &[&str] = &[
        "click here",
        "here",
        "read more",
        "learn more",
        "more",
        "link",
        "details",
        "więcej",
        "kliknij tutaj",
        "mehr",
        "weiterlesen",
    ];
    let ambiguous = obs
        .links
        .iter()
        .filter(|l| {
            let lower = l.text.trim().to_ascii_lowercase();
            AMBIGUOUS.contains(&lower.as_str())
        })
        .count();
    check_count_rule(
        CountRuleSpec {
            rule_id: RULE_AMBIGUOUS_LINKS,
            count: ambiguous,
            severity: Severity::Low,
            title: format!("Ambiguous generic link text ({ambiguous})"),
            summary: format!(
                "{ambiguous} link(s) use non-descriptive text such as `read more` or `click here`."
            ),
            evidence_detail: format!("ambiguous_links={ambiguous}"),
            remediation: "Use descriptive link text or provide `aria-label` so screen-reader link lists remain meaningful.",
        },
        findings,
        checks,
    );
}

fn check_doc_title_accessibility(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(title) = obs
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DOC_TITLE_PRESENCE.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Document is missing a non-empty <title>".to_owned(),
            summary: "Screen readers rely on `<title>` to announce page purpose upon navigation."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "title=absent_or_empty",
            )],
            remediation: Some(
                "Provide a descriptive, unique `<title>` element in `<head>`.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DOC_TITLE_PRESENCE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_GENERIC_PAGE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "document <title> absent".to_owned(),
        });
        return;
    };

    checks.push(CheckStatus::Passed {
        rule_id: RuleId(RULE_DOC_TITLE_PRESENCE.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });

    let lower = title.to_ascii_lowercase();
    let generic = matches!(
        lower.as_str(),
        "untitled" | "untitled document" | "home" | "index" | "document" | "page" | "welcome"
    );
    if generic {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_GENERIC_PAGE_TITLE.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Generic page <title> `{title}`"),
            summary: format!(
                "Page `<title>` (`{title}`) is generic and does not distinguish the page's specific topic or purpose."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("title={title}"),
            )],
            remediation: Some(
                "Use a specific `<title>` describing both the page topic and site name.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_GENERIC_PAGE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_GENERIC_PAGE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_ax_ignored_ratio(
    tree: &crate::domain::AccessibilityTreeSummary,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if tree.truncated || tree.total_nodes < 50 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_AX_HIGH_IGNORED_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
            reason: "AX tree too small or truncated for ignored-node ratio".to_owned(),
        });
        return;
    }

    let pct = tree.ignored_nodes.saturating_mul(100) / tree.total_nodes;
    if pct >= 92 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_AX_HIGH_IGNORED_RATIO.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: format!("High proportion of ignored AX tree nodes ({pct}%)"),
            summary: format!(
                "{} of {} Chromium AX tree nodes ({pct}%) are ignored, indicating heavy non-semantic wrapper or hidden DOM bloat.",
                tree.ignored_nodes, tree.total_nodes
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "ax_ignored_nodes={};ax_total_nodes={}",
                    tree.ignored_nodes, tree.total_nodes
                ),
            )],
            remediation: Some(
                "Reduce redundant wrapper elements and ensure meaningful content is exposed to assistive technologies."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_AX_HIGH_IGNORED_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_AX_HIGH_IGNORED_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_missing_lang_alt_label_and_broken_aria_ref() {
        let html = r#"<html><body>
            <img src="/logo.png">
            <input type="text" id="name">
            <button aria-labelledby="missing-id"></button>
            <a href="/empty"></a>
        </body></html>"#;

        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_DOC_LANG));
        assert!(ids.contains(&RULE_IMAGE_ALT));
        assert!(ids.contains(&RULE_FORM_LABELS));
        assert!(ids.contains(&RULE_ARIA_REFS));
        assert!(ids.contains(&RULE_INTERACTIVE_NAMES));
        assert!(res.checks.iter().any(|c| {
            matches!(
                c,
                CheckStatus::Unavailable {
                    evidence_level: EvidenceLevel::Rendered,
                    ..
                }
            )
        }));
    }

    #[test]
    fn allows_decorative_empty_alt() {
        let html = r#"<html lang="en"><body><img src="/dot.png" alt=""></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(!res.findings.iter().any(|f| f.rule_id.0 == RULE_IMAGE_ALT));
    }

    #[test]
    fn emits_findings_for_axe_violations_and_passes_when_clean() {
        use crate::domain::AxeViolation;
        let html = r#"<html lang="en"><body><p>Hello</p></body></html>"#;
        let obs = DocumentObservations::from_html(html);

        let clean_axe = CollectorOutcome::Captured {
            data: AxeEvidence {
                axe_version: "4.10.0".to_owned(),
                violations: Vec::new(),
                passes_count: 10,
                incomplete_count: 0,
            },
        };
        let clean_res = analyse_with_axe(&obs, &clean_axe);
        assert!(clean_res.checks.iter().any(|c| {
            matches!(c, CheckStatus::Passed { rule_id, .. } if rule_id.0 == RULE_RENDERED_AXE)
        }));

        let failing_axe = CollectorOutcome::Captured {
            data: AxeEvidence {
                axe_version: "4.10.0".to_owned(),
                violations: vec![AxeViolation {
                    id: "color-contrast".to_owned(),
                    impact: Some("serious".to_owned()),
                    description: "Elements must meet minimum color contrast ratio thresholds"
                        .to_owned(),
                    help_url: "https://dequeuniversity.com/rules/axe/4.10/color-contrast"
                        .to_owned(),
                    nodes_count: 3,
                    target_selectors: Vec::new(),
                }],
                passes_count: 9,
                incomplete_count: 0,
            },
        };
        let failing_res = analyse_with_axe(&obs, &failing_axe);
        assert!(
            failing_res
                .findings
                .iter()
                .any(|f| f.rule_id.0 == "a11y.rendered.axe.color-contrast"
                    && !f.evidence_refs.is_empty())
        );
    }

    #[test]
    fn flags_wave5_table_iframe_tabindex_and_autoplay_issues() {
        let html = r#"<html lang="en"><body>
            <table><tr><td>No header</td></tr></table>
            <iframe src="/widget"></iframe>
            <button tabindex="3">Jump</button>
            <video autoplay src="/promo.mp4"></video>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_TABLE_HEADERS));
        assert!(ids.contains(&RULE_IFRAME_TITLE));
        assert!(ids.contains(&RULE_POSITIVE_TABINDEX));
        assert!(ids.contains(&RULE_AUTOPLAY_MEDIA));
    }

    #[test]
    fn flags_ax_tree_missing_names_and_hidden_focusable() {
        let obs = DocumentObservations::from_html("<html lang=\"en\"><body></body></html>");
        let browser = CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                ax_tree: Some(crate::domain::AccessibilityTreeSummary {
                    total_nodes: 20,
                    ignored_nodes: 2,
                    interactive_without_name: 3,
                    hidden_focusable_count: 1,
                    truncated: false,
                }),
                ..BrowserEvidence::default()
            },
        };
        let res = analyse_with_browser(&obs, &CollectorOutcome::default(), &browser);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_AX_MISSING_NAME));
        assert!(ids.contains(&RULE_AX_HIDDEN_FOCUSABLE));
    }

    #[test]
    fn flags_missing_captions_suspicious_alt_and_ambiguous_links() {
        let html = r#"<html lang="en"><body>
            <video controls src="/demo.mp4"></video>
            <img src="/pic.jpg" alt="IMG_001.jpg">
            <a href="/post">Read more</a>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_MEDIA_CAPTIONS));
        assert!(ids.contains(&RULE_SUSPICIOUS_ALT));
        assert!(ids.contains(&RULE_AMBIGUOUS_LINKS));
    }

    #[test]
    fn flags_missing_or_generic_title_and_high_ax_ignored_ratio() {
        let obs = DocumentObservations::from_html(
            r#"<html lang="en"><head><title>Home</title></head><body></body></html>"#,
        );
        let browser = CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                ax_tree: Some(crate::domain::AccessibilityTreeSummary {
                    total_nodes: 100,
                    ignored_nodes: 94,
                    interactive_without_name: 0,
                    hidden_focusable_count: 0,
                    truncated: false,
                }),
                ..BrowserEvidence::default()
            },
        };
        let res = analyse_with_browser(&obs, &CollectorOutcome::default(), &browser);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_GENERIC_PAGE_TITLE));
        assert!(ids.contains(&RULE_AX_HIGH_IGNORED_RATIO));
    }

    #[test]
    fn flags_behavioural_focus_trap_missing_indicator_and_unreached_controls() {
        let obs = DocumentObservations::from_html(
            r#"<html lang="en"><head><title>Dashboard</title></head><body></body></html>"#,
        );
        let browser = CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                behavioural_a11y: Some(crate::domain::BehaviouralA11yObs {
                    tab_stops_observed: 0,
                    tabbable_candidates: 5,
                    focus_trap_detected: true,
                    missing_focus_indicator_count: 2,
                    open_dialogs_count: 1,
                    dialog_escape_closed: Some(false),
                    focus_sequence: vec!["button#trap@10,10".to_owned()],
                    tab_budget_exhausted: false,
                    modal_focus_escaped: true,
                    obscured_focus_count: 1,
                    focus_lost_after_dialog_close: Some(true),
                    skip_link_effective: Some(false),
                    unfocusable_aria_controls_count: 2,
                    escape_dismissed_modal: Some(false),
                    focus_restored_after_modal: Some(false),
                    live_region_count: 0,
                    aria_invalid_count: 0,
                }),
                ..BrowserEvidence::default()
            },
        };
        let res = analyse_with_browser(&obs, &CollectorOutcome::default(), &browser);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_BEHAVIOURAL));
        assert!(ids.contains(&RULE_BEHAVIOURAL_FOCUS_TRAP));
        assert!(ids.contains(&RULE_BEHAVIOURAL_FOCUS_INDICATOR));
        assert!(ids.contains(&RULE_BEHAVIOURAL_UNREACHED_CONTROLS));
        assert!(ids.contains(&RULE_BEHAVIOURAL_MODAL_CONTAINMENT));
        assert!(ids.contains(&RULE_BEHAVIOURAL_OBSCURED_FOCUS));
        assert!(ids.contains(&RULE_BEHAVIOURAL_SKIP_LINK_EFFECTIVE));
        assert!(ids.contains(&RULE_BEHAVIOURAL_KEYBOARD_ACTIVATION));
    }
}
