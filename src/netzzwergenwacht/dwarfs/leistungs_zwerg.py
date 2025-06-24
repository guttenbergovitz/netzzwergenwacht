"""Leistungs-Zwerg for performance analysis."""

import time

import httpx
import psutil
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

from .base import AnalysisResult, Dwarf, Severity


class LeistungsZwerg(Dwarf):
    """Leistungs-Zwerg - Analyzes websites for performance metrics and optimization opportunities."""

    def __init__(self):
        super().__init__(
            name="Leistungs-Zwerg",
            description="Performance analysis for load times, resource optimization and Core Web Vitals",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL for performance issues."""
        try:
            issues = []
            metadata = {}

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                issues.append(
                    self.create_issue(
                        issue_type="invalid_url_scheme",
                        severity=Severity.HIGH,
                        message="URL must start with http:// or https://",
                        location=url,
                        evidence={"provided_url": url},
                    )
                )
                return AnalysisResult(
                    url=url, dwarf_name=self.name, issues=issues, metadata=metadata
                )

            # Perform performance analysis
            performance_data = await self._analyze_performance(url)
            issues.extend(performance_data["issues"])
            metadata.update(performance_data["metadata"])

            # Analyze page resources
            resource_data = await self._analyze_resources(url)
            issues.extend(resource_data["issues"])
            metadata.update(resource_data["metadata"])

            # Analyze Core Web Vitals with browser automation
            core_vitals_data = await self._analyze_core_web_vitals(url)
            issues.extend(core_vitals_data["issues"])
            metadata.update(core_vitals_data["metadata"])

            return AnalysisResult(
                url=url, dwarf_name=self.name, issues=issues, metadata=metadata
            )

        except Exception as e:
            return AnalysisResult(
                url=url,
                dwarf_name=self.name,
                issues=[],
                success=False,
                error_message=str(e),
            )

    async def _analyze_performance(self, url: str) -> dict:
        """Analyze page load performance metrics."""
        issues = []
        metadata = {}

        try:
            # Measure page load time
            start_time = time.time()

            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=100),
            ) as client:
                response = await client.get(url)

            end_time = time.time()
            load_time = end_time - start_time
            load_time_ms = load_time * 1000

            # Add performance metadata
            metadata.update({
                "page_load_time_ms": round(load_time_ms, 2),
                "page_load_time_seconds": round(load_time, 3),
                "response_status": response.status_code,
                "content_length_bytes": len(response.content),
                "content_length_kb": round(len(response.content) / 1024, 2),
                "response_headers_count": len(response.headers),
            })

            # Check page load time thresholds
            if load_time_ms > 5000:  # 5 seconds
                issues.append(
                    self.create_issue(
                        issue_type="page_load_very_slow",
                        severity=Severity.HIGH,
                        message=f"Page load time is very slow: {load_time_ms:.0f}ms (recommended: <3000ms)",
                        location=url,
                        evidence={
                            "load_time_ms": load_time_ms,
                            "recommended_max_ms": 3000,
                            "performance_category": "very_slow",
                        },
                    )
                )
            elif load_time_ms > 3000:  # 3 seconds
                issues.append(
                    self.create_issue(
                        issue_type="page_load_slow",
                        severity=Severity.MEDIUM,
                        message=f"Page load time is slow: {load_time_ms:.0f}ms (recommended: <3000ms)",
                        location=url,
                        evidence={
                            "load_time_ms": load_time_ms,
                            "recommended_max_ms": 3000,
                            "performance_category": "slow",
                        },
                    )
                )
            elif load_time_ms > 1500:  # 1.5 seconds
                issues.append(
                    self.create_issue(
                        issue_type="page_load_moderate",
                        severity=Severity.LOW,
                        message=f"Page load time is moderate: {load_time_ms:.0f}ms (good: <1500ms)",
                        location=url,
                        evidence={
                            "load_time_ms": load_time_ms,
                            "recommended_max_ms": 1500,
                            "performance_category": "moderate",
                        },
                    )
                )
            else:  # <= 1500ms - Good performance
                metadata["performance_rating"] = (
                    "excellent" if load_time_ms <= 800 else "good"
                )

            # Check content size
            content_size_mb = len(response.content) / (1024 * 1024)
            if content_size_mb > 5:  # 5MB
                issues.append(
                    self.create_issue(
                        issue_type="page_size_very_large",
                        severity=Severity.HIGH,
                        message=f"Page size is very large: {content_size_mb:.2f}MB (recommended: <2MB)",
                        location=url,
                        evidence={
                            "page_size_mb": content_size_mb,
                            "page_size_bytes": len(response.content),
                            "recommended_max_mb": 2,
                        },
                    )
                )
            elif content_size_mb > 2:  # 2MB
                issues.append(
                    self.create_issue(
                        issue_type="page_size_large",
                        severity=Severity.MEDIUM,
                        message=f"Page size is large: {content_size_mb:.2f}MB (recommended: <2MB)",
                        location=url,
                        evidence={
                            "page_size_mb": content_size_mb,
                            "page_size_bytes": len(response.content),
                            "recommended_max_mb": 2,
                        },
                    )
                )
            else:  # Good page size
                if content_size_mb <= 1:  # Excellent
                    metadata["page_size_rating"] = "excellent"
                else:  # Good (1-2MB)
                    metadata["page_size_rating"] = "good"

            # Check for compression
            content_encoding = response.headers.get("content-encoding", "").lower()
            if not content_encoding and content_size_mb > 0.1:  # 100KB
                issues.append(
                    self.create_issue(
                        issue_type="missing_compression",
                        severity=Severity.MEDIUM,
                        message="Content is not compressed (missing gzip/brotli compression)",
                        location=url,
                        evidence={
                            "content_encoding": content_encoding or "none",
                            "content_size_kb": round(len(response.content) / 1024, 2),
                            "recommended_compression": ["gzip", "brotli"],
                        },
                    )
                )
            elif content_encoding:
                metadata["compression_enabled"] = True
                metadata["compression_type"] = content_encoding

            # Check caching headers
            cache_control = response.headers.get("cache-control", "").lower()
            expires = response.headers.get("expires", "")
            etag = response.headers.get("etag", "")

            if not cache_control and not expires and not etag:
                issues.append(
                    self.create_issue(
                        issue_type="missing_cache_headers",
                        severity=Severity.MEDIUM,
                        message="Missing caching headers (Cache-Control, Expires, or ETag)",
                        location=url,
                        evidence={
                            "cache_control": cache_control or "missing",
                            "expires": expires or "missing",
                            "etag": etag or "missing",
                        },
                    )
                )
            elif cache_control and "no-cache" in cache_control:
                issues.append(
                    self.create_issue(
                        issue_type="cache_disabled",
                        severity=Severity.LOW,
                        message="Caching is explicitly disabled",
                        location=url,
                        evidence={"cache_control": cache_control},
                    )
                )
            else:
                metadata["caching_enabled"] = True
                if cache_control:
                    metadata["cache_control"] = cache_control
                if expires:
                    metadata["expires_header"] = expires
                if etag:
                    metadata["etag_header"] = etag

        except httpx.RequestError as e:
            issues.append(
                self.create_issue(
                    issue_type="performance_analysis_failed",
                    severity=Severity.HIGH,
                    message=f"Failed to analyze performance: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_resources(self, url: str) -> dict:
        """Analyze page resources and optimization opportunities."""
        issues = []
        metadata = {}

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)

            if response.status_code != 200:
                return {"issues": [], "metadata": {}}

            # Parse HTML content
            soup = BeautifulSoup(response.content, "html.parser")

            # Analyze images
            images = soup.find_all("img")
            external_images = []
            images_without_alt = []
            large_images = []

            for img in images:
                src = img.get("src", "")
                alt = img.get("alt", "")

                if src:
                    # Check for external images
                    if src.startswith(("http://", "https://")) and not src.startswith(
                        url
                    ):
                        external_images.append(src)

                    # Check for missing alt text (accessibility & SEO)
                    if not alt:
                        images_without_alt.append(src)

                    # Check for potentially large images (detect by file extension and size hints)
                    width = img.get("width")
                    height = img.get("height")
                    if width and height:
                        try:
                            w, h = int(width), int(height)
                            # Flag images larger than 1920x1080 or with high pixel count
                            if w > 1920 or h > 1080 or (w * h > 2073600):  # 1920*1080
                                large_images.append({
                                    "src": src,
                                    "width": w,
                                    "height": h,
                                })
                        except ValueError:
                            pass

            # Analyze CSS resources
            css_links = soup.find_all("link", rel="stylesheet")
            external_css = []
            inline_css = soup.find_all("style")

            for link in css_links:
                href = link.get("href", "")
                if (
                    href
                    and href.startswith(("http://", "https://"))
                    and not href.startswith(url)
                ):
                    external_css.append(href)

            # Analyze JavaScript resources
            scripts = soup.find_all("script")
            external_js = []
            inline_js = []

            for script in scripts:
                src = script.get("src", "")
                if src:
                    if src.startswith(("http://", "https://")) and not src.startswith(
                        url
                    ):
                        external_js.append(src)
                else:
                    # Inline JavaScript
                    if script.string and len(script.string.strip()) > 100:
                        inline_js.append(len(script.string))

            # Add resource metadata
            metadata.update({
                "total_images": len(images),
                "external_images_count": len(external_images),
                "images_missing_alt": len(images_without_alt),
                "large_images_count": len(large_images),
                "total_css_files": len(css_links),
                "external_css_count": len(external_css),
                "inline_css_blocks": len(inline_css),
                "total_js_files": len([s for s in scripts if s.get("src")]),
                "external_js_count": len(external_js),
                "inline_js_blocks": len(inline_js),
                "inline_js_total_size": sum(inline_js) if inline_js else 0,
            })

            # Generate issues based on resource analysis
            if len(large_images) > 0:
                issues.append(
                    self.create_issue(
                        issue_type="large_images_detected",
                        severity=Severity.MEDIUM,
                        message=f"Large images detected ({len(large_images)}) - consider optimization",
                        location=url,
                        evidence={
                            "large_images_count": len(large_images),
                            "sample_large_images": large_images[:3],
                            "recommendation": "Use responsive images, WebP format, or image optimization",
                        },
                    )
                )

            if len(external_images) > 10:
                issues.append(
                    self.create_issue(
                        issue_type="too_many_external_images",
                        severity=Severity.MEDIUM,
                        message=f"Too many external images ({len(external_images)}) - consider hosting locally",
                        location=url,
                        evidence={
                            "external_images_count": len(external_images),
                            "recommended_max": 10,
                            "sample_external_images": external_images[:3],
                        },
                    )
                )

            if len(external_css) > 5:
                issues.append(
                    self.create_issue(
                        issue_type="too_many_external_css",
                        severity=Severity.MEDIUM,
                        message=f"Too many external CSS files ({len(external_css)}) - consider bundling",
                        location=url,
                        evidence={
                            "external_css_count": len(external_css),
                            "recommended_max": 5,
                            "sample_external_css": external_css[:3],
                        },
                    )
                )

            if len(external_js) > 8:
                issues.append(
                    self.create_issue(
                        issue_type="too_many_external_js",
                        severity=Severity.MEDIUM,
                        message=f"Too many external JavaScript files ({len(external_js)}) - consider bundling",
                        location=url,
                        evidence={
                            "external_js_count": len(external_js),
                            "recommended_max": 8,
                            "sample_external_js": external_js[:3],
                        },
                    )
                )

            # Check for large inline JavaScript
            if inline_js and sum(inline_js) > 10000:  # 10KB
                issues.append(
                    self.create_issue(
                        issue_type="large_inline_javascript",
                        severity=Severity.LOW,
                        message=f"Large inline JavaScript detected ({sum(inline_js)} chars) - consider external files",
                        location=url,
                        evidence={
                            "inline_js_total_size": sum(inline_js),
                            "inline_js_blocks": len(inline_js),
                            "recommended_max_chars": 10000,
                        },
                    )
                )

            # Check for render-blocking resources
            css_in_head = (
                soup.head.find_all("link", rel="stylesheet") if soup.head else []
            )
            js_in_head = soup.head.find_all("script") if soup.head else []

            if len(css_in_head) > 3:
                issues.append(
                    self.create_issue(
                        issue_type="render_blocking_css",
                        severity=Severity.LOW,
                        message=f"Multiple CSS files in <head> may block rendering ({len(css_in_head)} files)",
                        location=url,
                        evidence={
                            "css_in_head_count": len(css_in_head),
                            "recommended_max": 3,
                        },
                    )
                )

            if len(js_in_head) > 2:
                issues.append(
                    self.create_issue(
                        issue_type="render_blocking_js",
                        severity=Severity.MEDIUM,
                        message=f"JavaScript in <head> may block rendering ({len(js_in_head)} scripts)",
                        location=url,
                        evidence={
                            "js_in_head_count": len(js_in_head),
                            "recommended_max": 2,
                        },
                    )
                )

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="resource_analysis_failed",
                    severity=Severity.LOW,
                    message=f"Failed to analyze page resources: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_core_web_vitals(self, url: str) -> dict:
        """Analyze Core Web Vitals using browser automation."""
        issues = []
        metadata = {}

        try:
            async with async_playwright() as p:
                # Launch browser with performance monitoring
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Enable performance monitoring
                await page.route("**/*", lambda route: route.continue_())

                # Navigate to page and wait for load
                start_time = time.time()
                await page.goto(url, wait_until="networkidle", timeout=30000)
                load_time = time.time() - start_time

                # Collect Core Web Vitals
                await page.evaluate("""
                    () => {
                        return new Promise((resolve) => {
                            // Wait for page to be fully loaded
                            if (document.readyState === 'complete') {
                                collectMetrics();
                            } else {
                                window.addEventListener('load', collectMetrics);
                            }

                            function collectMetrics() {
                                const metrics = {};

                                // Largest Contentful Paint (LCP)
                                if ('PerformanceObserver' in window) {
                                    const observer = new PerformanceObserver((list) => {
                                        const entries = list.getEntries();
                                        const lastEntry = entries[entries.length - 1];
                                        metrics.lcp = lastEntry.startTime;
                                    });
                                    observer.observe({ entryTypes: ['largest-contentful-paint'] });
                                }

                                // First Input Delay (FID) - simulated
                                metrics.fid = performance.now();

                                // Cumulative Layout Shift (CLS)
                                let cls = 0;
                                if ('PerformanceObserver' in window) {
                                    const observer = new PerformanceObserver((list) => {
                                        for (const entry of list.getEntries()) {
                                            if (!entry.hadRecentInput) {
                                                cls += entry.value;
                                            }
                                        }
                                    });
                                    observer.observe({ entryTypes: ['layout-shift'] });
                                }
                                metrics.cls = cls;

                                // First Contentful Paint (FCP)
                                const fcpEntry = performance.getEntriesByName('first-contentful-paint')[0];
                                metrics.fcp = fcpEntry ? fcpEntry.startTime : 0;

                                // Time to Interactive (TTI) - estimated
                                metrics.tti = performance.now();

                                // Total Blocking Time (TBT) - estimated
                                metrics.tbt = 0;

                                resolve(metrics);
                            }
                        });
                    }
                """)

                # Wait a bit for metrics to be collected
                await page.wait_for_timeout(2000)

                # Get final metrics
                final_metrics = await page.evaluate("""
                    () => {
                        const metrics = {};

                        // Get LCP
                        const lcpEntries = performance.getEntriesByType('largest-contentful-paint');
                        metrics.lcp = lcpEntries.length > 0 ? lcpEntries[lcpEntries.length - 1].startTime : 0;

                        // Get FCP
                        const fcpEntries = performance.getEntriesByType('paint');
                        const fcpEntry = fcpEntries.find(entry => entry.name === 'first-contentful-paint');
                        metrics.fcp = fcpEntry ? fcpEntry.startTime : 0;

                        // Get CLS
                        let cls = 0;
                        if ('PerformanceObserver' in window) {
                            const observer = new PerformanceObserver((list) => {
                                for (const entry of list.getEntries()) {
                                    if (!entry.hadRecentInput) {
                                        cls += entry.value;
                                    }
                                }
                            });
                            observer.observe({ entryTypes: ['layout-shift'] });
                        }
                        metrics.cls = cls;

                        // Get resource timing
                        const resources = performance.getEntriesByType('resource');
                        metrics.resource_count = resources.length;
                        metrics.total_resource_size = resources.reduce((sum, r) => sum + (r.transferSize || 0), 0);

                        return metrics;
                    }
                """)

                # Add Core Web Vitals to metadata
                metadata.update({
                    "lcp_ms": round(final_metrics.get("lcp", 0), 2),
                    "fcp_ms": round(final_metrics.get("fcp", 0), 2),
                    "cls_score": round(final_metrics.get("cls", 0), 4),
                    "resource_count": final_metrics.get("resource_count", 0),
                    "total_resource_size_kb": round(
                        final_metrics.get("total_resource_size", 0) / 1024, 2
                    ),
                    "browser_load_time_ms": round(load_time * 1000, 2),
                })

                # Evaluate Core Web Vitals
                lcp = final_metrics.get("lcp", 0)
                fcp = final_metrics.get("fcp", 0)
                cls = final_metrics.get("cls", 0)

                # LCP evaluation
                if lcp > 4000:
                    issues.append(
                        self.create_issue(
                            issue_type="poor_lcp",
                            severity=Severity.HIGH,
                            message=f"Poor Largest Contentful Paint: {lcp:.0f}ms (recommended: <2500ms)",
                            location=url,
                            evidence={
                                "lcp_ms": lcp,
                                "recommended_max_ms": 2500,
                                "core_web_vital": "LCP",
                            },
                        )
                    )
                elif lcp > 2500:
                    issues.append(
                        self.create_issue(
                            issue_type="needs_improvement_lcp",
                            severity=Severity.MEDIUM,
                            message=f"LCP needs improvement: {lcp:.0f}ms (good: <2500ms)",
                            location=url,
                            evidence={
                                "lcp_ms": lcp,
                                "recommended_max_ms": 2500,
                                "core_web_vital": "LCP",
                            },
                        )
                    )
                else:
                    metadata["lcp_rating"] = "good"

                # FCP evaluation
                if fcp > 3000:
                    issues.append(
                        self.create_issue(
                            issue_type="poor_fcp",
                            severity=Severity.MEDIUM,
                            message=f"Poor First Contentful Paint: {fcp:.0f}ms (recommended: <1800ms)",
                            location=url,
                            evidence={
                                "fcp_ms": fcp,
                                "recommended_max_ms": 1800,
                                "core_web_vital": "FCP",
                            },
                        )
                    )
                elif fcp > 1800:
                    issues.append(
                        self.create_issue(
                            issue_type="needs_improvement_fcp",
                            severity=Severity.LOW,
                            message=f"FCP needs improvement: {fcp:.0f}ms (good: <1800ms)",
                            location=url,
                            evidence={
                                "fcp_ms": fcp,
                                "recommended_max_ms": 1800,
                                "core_web_vital": "FCP",
                            },
                        )
                    )
                else:
                    metadata["fcp_rating"] = "good"

                # CLS evaluation
                if cls > 0.25:
                    issues.append(
                        self.create_issue(
                            issue_type="poor_cls",
                            severity=Severity.HIGH,
                            message=f"Poor Cumulative Layout Shift: {cls:.3f} (recommended: <0.1)",
                            location=url,
                            evidence={
                                "cls_score": cls,
                                "recommended_max": 0.1,
                                "core_web_vital": "CLS",
                            },
                        )
                    )
                elif cls > 0.1:
                    issues.append(
                        self.create_issue(
                            issue_type="needs_improvement_cls",
                            severity=Severity.MEDIUM,
                            message=f"CLS needs improvement: {cls:.3f} (good: <0.1)",
                            location=url,
                            evidence={
                                "cls_score": cls,
                                "recommended_max": 0.1,
                                "core_web_vital": "CLS",
                            },
                        )
                    )
                else:
                    metadata["cls_rating"] = "good"

                # System resource monitoring
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()

                metadata.update({
                    "cpu_usage_percent": round(cpu_percent, 2),
                    "memory_usage_percent": round(memory.percent, 2),
                    "memory_available_mb": round(memory.available / (1024 * 1024), 2),
                })

                await browser.close()

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="core_web_vitals_analysis_failed",
                    severity=Severity.LOW,
                    message=f"Core Web Vitals analysis failed: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return {"issues": issues, "metadata": metadata}
