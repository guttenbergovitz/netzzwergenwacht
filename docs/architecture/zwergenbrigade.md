# Die Zwergenbrigade

> **Kleine Zwerge. Große Sorgfalt.** (*Small dwarfs. Great diligence.*)

NetzZwergenWacht combines evidence-first auditing with a personified German-named brigade of specialists. Presentation metadata is stored centrally in `src/brigade.rs` (`ZWERGENBRIGADE`) and kept strictly separate from analytical logic.

## Registry

| Display Name | `DwarfId` | Module | Role | Responsibility | Min Evidence | Status |
|---|---|---|---|---|---|---|
| **NetzZwerg** | `netz` | `analysis::network` | Deterministic Analyser | HTTP, DNS, connectivity, redirects, and endpoint reliability | `Source` | Implemented |
| **SicherheitsZwerg** | `sicherheits` | `analysis::security` | Deterministic Analyser | TLS, security headers, cookies, and security posture | `Source` | Implemented |
| **LeistungsZwerg** | `leistungs` | `analysis::performance` | Deterministic Analyser | Performance, latency, resource efficiency, and Core Web Vitals | `Source` | Implemented (HTTP) |
| **StrukturZwerg** | `struktur` | `analysis::semantics` | Deterministic Analyser | Semantic HTML, document structure, and structural integrity | `Source` | Implemented |
| **ZugänglichkeitsZwerg** | `zugaenglichkeits` | `analysis::accessibility` | Deterministic Analyser | Accessibility, WCAG, ARIA, and inclusive interaction | `Source` | Implemented (Source) |
| **SuchZwerg** | `such` | `analysis::seo` | Deterministic Analyser | SEO, metadata, indexability, and search visibility | `Source` | Implemented |
| **InhaltsZwerg** | `inhalts` | `analysis::content` | Deterministic Analyser | Content quality, readability, and language | `Source` | Implemented |
| **GestaltungsZwerg** | `gestaltungs` | — | Deterministic Analyser | Visual integrity, responsive layouts, and presentation | `Rendered` | Planned |
| **BrowserZwerg** | `browser` | — | Deterministic Analyser | Browser runtime, JavaScript, console, and network failures | `Rendered` | Planned |
| **DokumentationsZwerg** | `dokumentations` | `main` (presentation) | Reporting | Report generation and evidence presentation | `Source` | Implemented |
| **KommandantZwerg** | `kommandant` | — | Optional Intelligence | Optional AI-assisted correlation, interpretation, and diagnostic planning | `Source` | Planned |

## Design Rules

- A Zwerg is a functional responsibility, **not** an autonomous AI agent or separate thread/process.
- Machine-readable JSON output uses stable ASCII `dwarf_id` values (`netz`, `sicherheits`, etc.) rather than German display names with umlauts.
- Humour and character taglines must never obscure severity, confidence, or execution status.
