# Analytical Capabilities

Summary of NetzZwergenWacht's native Rust analytical and agentic evidence infrastructure implemented under Operation Aufrüstung III.

## 1. Statistical Intelligence (`src/analysis/stats.rs`)

- **`DistributionSummary` (`summarise_u64`)**: computes `count`, `missing_count`, `min`, `max`, `mean`, `median`, `p75`, `p95`, interquartile range (`iqr`), and median absolute deviation (`mad`) over optional numeric observations.
- **`identify_upper_iqr_outliers`**: detects upper-tail outliers beyond Tukey's `Q3 + 1.5 * IQR` fence, returning an empty list for tiny sample sizes (`count < 4`).

## 2. Application & Resource Graphs (`src/analysis/graph.rs`)

- **Application Graph**: models pages, internal links, redirect chains/loops, canonical chains/loops, `hreflang` reciprocity, sitemap coverage/indexability, crawl depth, and parameterised crawl-trap candidates.
- **Resource Graph**: correlates subresource observations across pages (`GraphResourceInput`) to identify shared failing dependencies (`graph.resources.shared_failed_dependency`) and third-party origin concentration (`graph.resources.third_party_concentration`).
- **Entity & Content Graphs**: cross-page Schema.org entity conflicts, dangling `@id` references, and duplicate title/description metadata.

## 3. Browser Sensory Completeness (`src/domain.rs`, `src/adapters/browser.rs`)

- Explicit truncation flags (`resources_truncated`, `rendered_images_truncated`, `ax_tree.truncated`) promote `CollectorOutcome::Captured` to `CollectorOutcome::Partial` with explicit warnings when sampling caps are reached.
- Network waterfall provenance (`request_id`, `initiator_type`, `initiator_url`, `start_time_ms`, `status_code`, `priority`, `duration_ms`), categorised runtime errors (`uncaught_exception`, `unhandled_rejection`, `csp_violation`, `console_error`), navigation/LCP/CLS/Long-Task telemetry (`PerformanceRuntimeObs`), and privacy storage counts (`PrivacyStorageSummary`).

## 4. Typed Rig Tools (`src/investigation/tools.rs`)

- `query_browser_evidence` (`QueryBrowserEvidenceTool`): returns bounded waterfall summaries, third-party hostnames, categorised runtime error counts, and completeness flags.
- `calculate_distribution` (`CalculateDistributionTool`): computes `DistributionSummary` and Tukey IQR outliers over labelled observations.
