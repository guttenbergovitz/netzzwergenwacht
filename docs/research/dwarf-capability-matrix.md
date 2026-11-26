# Dwarf Capability Matrix

Mapping of upstream SquirrelScan categories (360 rules across 23 categories) to Die Zwergenbrigade.

| Dwarf | Module | Current NZW Rules | Mapped Upstream Categories | Priority Gaps |
| --- | --- | --- | --- | --- |
| `NetzZwerg` | `analysis::network` | 2 | `crawl` (27), `links` (18), `reliability` (6) | Broken links, `robots.txt`/`sitemap.xml` findings, soft-404, redirect loops |
| `SicherheitsZwerg` | `analysis::security` | 7 | `security` (31), `integrity` (10) | `Set-Cookie` flags, mixed content, SRI, CORS, `security.txt`, CSP directive parsing |
| `LeistungsZwerg` | `analysis::performance` | 5 | `perf` (32) | Render-blocking scripts/styles, third-party script weight, font-display, image sizing |
| `StrukturZwerg` | `analysis::semantics` | 5 | `core` (doctype/charset), `a11y` (structural) | Table semantics, skip links, form structure, doctype/charset |
| `ZugänglichkeitsZwerg` | `analysis::accessibility` | 7 (+ dynamic axe) | `a11y` (63) | Static ARIA/tabindex/table-headers + reliable `axe-core` execution |
| `SuchZwerg` | `analysis::seo` | 4 | `core` (14), `i18n` (4), `schema` (26), `social` (5), `url` (10), `local` (3) | `hreflang`, JSON-LD, OpenGraph/Twitter, `X-Robots-Tag`, `H1` uniqueness, URL hygiene |
| `InhaltsZwerg` | `analysis::content` | 2 | `content` (36), `eeat` (15), `legal` (4), `ax` (21) | Placeholders, readability, text-to-HTML ratio, legal/trust links, `llms.txt` / AX |
| `GestaltungsZwerg` | `analysis::visual` | 2 | `images` (16), `mobile` (8), `video` (3) | Image `width`/`height` (CLS), `<meta name="viewport">` validation |
| `BrowserZwerg` | `analysis::browser` | 2 | `analytics` (3), `blocking` (3) | Console/API failures, third-party blocking/tracking scripts |
