# Competitor & Reference Instrument Capability Matrix

Comparison of NetzZwergenWacht's native capabilities against reference instruments documented in Operation Aufrüstung III.

| Domain | Reference Instruments | NZW Native Status | External Instrument Delegation |
| --- | --- | --- | --- |
| General & SEO Crawl | SquirrelScan, Screaming Frog, Sitebulb | `SuchZwerg`, `NetzZwerg`, `ApplicationGraph` | None required |
| HTTP Security & CSP | MDN Observatory, OWASP ZAP Passive | `SicherheitsZwerg` (CSP parser, cookie prefixes, headers, URL redaction) | Optional TLS deep enumeration (`testssl.sh`) |
| Performance & CWV | Lighthouse, WebPageTest, Chrome DevTools | `LeistungsZwerg` + CDP `PerformanceObserver` (TTFB, LCP, CLS, Long Tasks, waterfall) | `adapters::lighthouse` for full lab CWV |
| Accessibility | axe-core, W3C ACT, WAVE | `ZugänglichkeitsZwerg` (source HTML + CDP `Accessibility.getFullAXTree`) | `adapters::axe` for rendered WCAG rules |
| Runtime & Visual | Playwright, BackstopJS, DebugBear | `BrowserZwerg`, `GestaltungsZwerg` (CDP runtime errors, CSP/CORS blocks, viewport geometry) | Chromium CDP harness |
| Statistical & Graph | Custom / Sitebulb | `analysis::stats`, `ApplicationGraph`, `ResourceGraph`, Rig tools | None required |
