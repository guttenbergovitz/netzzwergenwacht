# Diagnostic Gap Analysis (Operation Aufrüstung III)

Baseline reconciled against `develop`: **127 implemented rules** across Die Zwergenbrigade and `ApplicationGraph`.

## Implemented Coverage by Dwarf

| Dwarf / Engine | Implemented Rules |
| --- | ---: |
| LeistungsZwerg | 20 |
| SicherheitsZwerg | 18 |
| GestaltungsZwerg | 16 |
| SuchZwerg | 14 |
| InhaltsZwerg | 12 |
| ApplicationGraph | 12 |
| ZugänglichkeitsZwerg | 11 |
| StrukturZwerg | 9 |
| NetzZwerg | 8 |
| BrowserZwerg | 7 |

## Priority Wave A Gaps (Browser Sensory Foundation — P0)

1. **Collection completeness**: `BrowserEvidence.resources` (capped at 200) and `rendered_images` (capped at 100) lacked explicit truncation flags.
2. **Network waterfall & initiator provenance**: `ResourceTimingObs` lacked `request_id`, `initiator_type`, `initiator_url`, `start_time_ms`, `status_code`, and `priority`.
3. **Rich runtime errors**: `ConsoleErrorEvent` lacked `error_kind` (`uncaught_exception`, `unhandled_rejection`, `csp_violation`, `console_error`), `source_url`, and `line_number`.
4. **Browser runtime rules**: Missing dedicated classification for `browser.js.uncaught_exception`, `browser.js.unhandled_rejection`, `browser.js.csp_violation`, and `browser.network.cors_block`.
5. **Typed agent evidence query**: `InspectBrowserRuntimeTool` returned raw evidence without structured waterfall/error summary queries.
