# Observation Gap Analysis

Comparison between NZW's current observation model (`src/domain.rs`, `src/analysis/document.rs`) and the observations required to support broad deterministic rule coverage.

## 1. HTTP & Transport (`HttpEvidence`)

- **Currently captured:** `final_url`, `status_code`, `redirect_chain`, `headers` (all response headers), `elapsed_ms`, `body_bytes`, `body_truncated`, `body_text`.
- **Slice 1 additions:** `HttpEvidence::header_values(&self, name)` and `first_header_value(&self, name)` for multi-value headers (`Set-Cookie`, `X-Robots-Tag`, `Link`).
- **Remaining gaps:** Per-origin well-known probes (`/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/llms.txt`) surfaced into analyser context; TLS protocol/cipher details beyond leaf cert expiry.

## 2. Source Document (`DocumentObservations`)

- **Slice 1 additions (`src/analysis/document.rs`):** `LinkObs`, `HreflangObs`, `json_ld_blocks`, `SocialMetaObs` (OpenGraph + Twitter Card), `ScriptObs` (async/defer/integrity/inline bytes), `StylesheetObs`, `FormObs`, `ImageObs` (`width`, `height`, `loading`), `viewport_meta`, `charset_declared`, `has_skip_link`, `has_favicon`, `visible_text_sample` (4096-byte cap).
- **Remaining gaps:** Table header/caption structure (`<table>`/`<th>`), `<iframe>` attributes (`title`, `sandbox`), `<meta http-equiv="refresh">`, inline SVG accessibility attributes, URL path/query structural breakdown.

## 3. Rendered Document & Browser Runtime (`BrowserEvidence`, `AxeEvidence`, `LighthouseMetrics`)

- **Currently captured:** Console errors, failed subresource requests, viewport overflow, broken images, `axe-core` violations, Lighthouse CWV (`LCP`, `CLS`, `INP`/`TBT`).
- **Remaining gaps:** Computed font sizes / tap targets (mobile usability), render-blocking resource waterfall timing, client-side hydration error indicators, screenshot artefacts.

## 4. Application Topology (`discovery`)

- **Currently captured:** Discovered URLs, page-type classification, locale/template detection, systemic issue clustering.
- **Remaining gaps:** Cross-page canonical graph, `hreflang` reciprocity graph, internal PageRank/orphan-page detection, duplicate title/meta description across pages.
