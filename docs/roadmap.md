# NetzZwergenWacht Roadmap

Current state on `develop`: **235 registered diagnostic rules** across **Die Zwergenbrigade** and `ApplicationGraph`, with **161+ passing tests**.

## Completed under Operation Aufrüstung I–III

- **Browser Sensory Foundation (Wave A)**: CDP network waterfall + initiator provenance, categorised runtime errors (`uncaught_exception`, `unhandled_rejection`, `csp_violation`, `console_error`), explicit truncation flags (`resources_truncated`, `rendered_images_truncated`), and `QueryBrowserEvidenceTool`.
- **Accessibility Tree & Performance Depth (Wave B)**: `Accessibility.getFullAXTree` summary (`a11y.ax.*`), `PerformanceObserver` navigation/LCP/CLS/Long-Task telemetry, and RFC-compliant `Cache-Control` directive parsing.
- **Surface Security & Privacy (Wave C / J)**: Native CSP directive parser, `__Host-`/`__Secure-` cookie prefix validation, `Max-Age` cap checks, URL query-parameter secret redaction (`redacted_url`), and fresh-session privacy storage/tracking observations (`sec.privacy.*`).
- **Statistical Intelligence & Resource Graph (Wave E/G)**: `analysis::stats` (`DistributionSummary`, Tukey IQR outliers), `CalculateDistributionTool`, `ResourceGraph` shared-dependency and concentration rules, and crawl-trap detection.
- **Layout Geometry, Media & Content Integrity (Wave D/F/H/I)**: Offscreen controls, oversized sticky headers, pixelated images, caption tracks, suspicious alt text, ambiguous links, i18n key leakage, placeholder contacts, HTTPS downgrade redirects, ETag validation, and `Zwergenprüfstand` clean-control verification.

## Next Horizons

1. **External Instrument Integrations**: Optional `testssl.sh` TLS protocol/cipher enumeration and Nu HTML Checker (`vnu`) conformance adapter behind `CollectorOutcome`.
2. **Multi-State Consent & Interaction Matrix**: Automated 3-state browser sessions (fresh, explicit reject, explicit accept) and safe widget keyboard-navigation probes.
3. **Visual Regression & Differential Benchmarks**: Screenshot perceptual-hashing baselines and automated differential comparison runs against SquirrelScan, Lighthouse, and axe-core.
4. **Language-Aware Linguistic & Similarity Layer**: Locale-specific readability models and SimHash/MinHash near-duplicate content clustering.

## Operation Aufrüstung IV

Wave IV-A now includes source paragraph and region observations, language inheritance
and a fixture-verified text distribution for documents with one main landmark.
The registry distinguishes rendered clipping, which still requires geometry evidence,
from implemented source checks.

The first browser timeline records request hops and runtime events in receive
order and exposes bounded snapshot queries. Extend it with wire response
metadata, streaming lifecycles and detailed attribution. Use the same session
evidence for bounded journey and consent scenarios. Extend the existing
application graph and patrol history with comparable observation coverage before
adding application-wide conclusions.

Rendered DOM segmentation now captures bounded desktop paragraph and region
observations. The live fixture compares source and rendered evidence. Stable
element identity and content fingerprints are the next foundations for comparing
blocks across captures.
