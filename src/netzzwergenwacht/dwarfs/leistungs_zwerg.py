"""Leistungs-Zwerg for performance analysis."""

import time
from typing import Any

import httpx
import psutil
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

from .base import (
    AnalysisResult,
    CodeLocation,
    DetailedAnalysisResult,
    DetailedIssue,
    Dwarf,
    Issue,
    PerformanceMetrics,
    Severity,
)


class LeistungsZwerg(Dwarf):
    """Leistungs-Zwerg - Analyzes websites for performance metrics and optimization opportunities."""

    def __init__(self) -> None:
        super().__init__(
            name="Leistungs-Zwerg",
            description="Performance analysis for load times, resource optimization and Core Web Vitals",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL for performance issues."""
        try:
            issues: list[Issue] = []
            metadata: dict[str, Any] = {}

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

    async def _analyze_performance(self, url: str) -> dict[str, Any]:
        """Analyze page load performance metrics."""
        issues: list[Issue] = []
        metadata: dict[str, Any] = {}

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
                src = str(img.get("src", ""))
                alt = str(img.get("alt", ""))

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
                            w, h = int(str(width)), int(str(height))
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
                href = str(link.get("href", ""))
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
                src = str(script.get("src", ""))
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

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL for performance issues with detailed context and optimization suggestions."""
        try:
            detailed_issues: list[DetailedIssue] = []
            perf_metrics = PerformanceMetrics()
            raw_data: dict[str, Any] = {}

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="invalid_url_scheme",
                        severity=Severity.HIGH,
                        message="URL must start with http:// or https://",
                        location=url,
                        category="performance",
                        subcategory="url_structure",
                        description="The provided URL does not use a valid HTTP scheme",
                        impact="Cannot perform performance analysis without valid scheme.",
                        technical_details={"provided_url": url},
                        recommendations=[
                            "Use HTTPS URLs for better performance and security."
                        ],
                        fix_suggestions=[
                            f"Change URL to 'https://{url.replace('http://', '').replace('https://', '')}'"
                        ],
                        priority_score=0.9,
                        code_location=CodeLocation(
                            resource_type="url", attribute_value=url
                        ),
                    )
                )
                return DetailedAnalysisResult(
                    url=url,
                    dwarf_name=self.name,
                    detailed_issues=detailed_issues,
                    performance_metrics=perf_metrics,
                    raw_data=raw_data,
                )

            # Perform detailed performance analysis
            performance_data = await self._analyze_performance_detailed(url)
            detailed_issues.extend(performance_data["issues"])
            perf_metrics.response_time_ms = performance_data["metrics"].get(
                "response_time_ms"
            )
            perf_metrics.page_load_time_ms = performance_data["metrics"].get(
                "page_load_time_ms"
            )
            perf_metrics.total_size_bytes = performance_data["metrics"].get(
                "total_size_bytes"
            )
            raw_data["performance"] = performance_data["raw"]

            # Analyze page resources with detailed context
            resource_data = await self._analyze_resources_detailed(url)
            detailed_issues.extend(resource_data["issues"])
            perf_metrics.image_count = resource_data["metrics"].get("image_count", 0)
            perf_metrics.css_count = resource_data["metrics"].get("css_count", 0)
            perf_metrics.js_count = resource_data["metrics"].get("js_count", 0)
            raw_data["resources"] = resource_data["raw"]

            # Analyze Core Web Vitals with browser automation
            core_vitals_data = await self._analyze_core_web_vitals_detailed(url)
            detailed_issues.extend(core_vitals_data["issues"])
            perf_metrics.lcp = core_vitals_data["metrics"].get("lcp")
            perf_metrics.fcp = core_vitals_data["metrics"].get("fcp")
            perf_metrics.cls = core_vitals_data["metrics"].get("cls")
            perf_metrics.ttfb = core_vitals_data["metrics"].get("ttfb")
            raw_data["core_web_vitals"] = core_vitals_data["raw"]

            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                detailed_issues=detailed_issues,
                performance_metrics=perf_metrics,
                raw_data=raw_data,
            )

        except Exception as e:
            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                success=False,
                error_message=str(e),
            )

    async def _analyze_performance_detailed(self, url: str) -> dict:
        """Analyze page load performance with detailed context and optimization suggestions."""
        issues = []
        metrics = {}
        raw = {}

        try:
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

            metrics.update({
                "response_time_ms": round(load_time_ms, 2),
                "page_load_time_ms": round(load_time_ms, 2),
                "total_size_bytes": len(response.content),
            })

            raw["response"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content),
            }

            # Page load time analysis
            if load_time_ms > 5000:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="page_load_very_slow",
                        severity=Severity.HIGH,
                        message=f"Page load time is very slow: {load_time_ms:.0f}ms",
                        location=url,
                        category="performance",
                        subcategory="page_load_time",
                        description="Page takes more than 5 seconds to load, which severely impacts user experience",
                        impact="Users will likely abandon the page, affecting conversion rates and SEO",
                        technical_details={
                            "load_time_ms": load_time_ms,
                            "recommended_max_ms": 3000,
                            "performance_category": "very_slow",
                        },
                        recommendations=["Optimize page load performance immediately"],
                        fix_suggestions=[
                            "Enable server-side caching",
                            "Optimize and compress images",
                            "Minify CSS and JavaScript",
                            "Use CDN for static assets",
                            "Implement lazy loading",
                        ],
                        code_location=CodeLocation(
                            resource_type="http", attribute_value=url
                        ),
                        affected_elements=["server_config", "assets", "caching"],
                        priority_score=0.9,
                    )
                )
            elif load_time_ms > 3000:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="page_load_slow",
                        severity=Severity.MEDIUM,
                        message=f"Page load time is slow: {load_time_ms:.0f}ms",
                        location=url,
                        category="performance",
                        subcategory="page_load_time",
                        description="Page takes more than 3 seconds to load",
                        impact="May cause user frustration and affect SEO rankings",
                        technical_details={
                            "load_time_ms": load_time_ms,
                            "recommended_max_ms": 3000,
                            "performance_category": "slow",
                        },
                        recommendations=["Optimize page load performance"],
                        fix_suggestions=[
                            "Enable gzip compression",
                            "Optimize images (WebP format)",
                            "Reduce HTTP requests",
                            "Use browser caching",
                        ],
                        code_location=CodeLocation(
                            resource_type="http", attribute_value=url
                        ),
                        affected_elements=["compression", "images", "caching"],
                        priority_score=0.7,
                    )
                )

            # Content size analysis
            content_size_mb = len(response.content) / (1024 * 1024)
            if content_size_mb > 5:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="page_size_very_large",
                        severity=Severity.HIGH,
                        message=f"Page size is very large: {content_size_mb:.2f}MB",
                        location=url,
                        category="performance",
                        subcategory="page_size",
                        description="Page content is extremely large, causing slow downloads",
                        impact="Slow downloads on mobile networks and high bandwidth costs",
                        technical_details={
                            "page_size_mb": content_size_mb,
                            "page_size_bytes": len(response.content),
                            "recommended_max_mb": 2,
                        },
                        recommendations=["Reduce page size significantly"],
                        fix_suggestions=[
                            "Compress and optimize images",
                            "Remove unnecessary content",
                            "Split large pages into smaller ones",
                            "Use lazy loading for images",
                            "Enable gzip/brotli compression",
                        ],
                        code_location=CodeLocation(
                            resource_type="http", attribute_value=url
                        ),
                        affected_elements=["images", "content", "compression"],
                        priority_score=0.8,
                    )
                )

            # Compression analysis
            content_encoding = response.headers.get("content-encoding", "").lower()
            if not content_encoding and content_size_mb > 0.1:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="missing_compression",
                        severity=Severity.MEDIUM,
                        message="Content is not compressed",
                        location=url,
                        category="performance",
                        subcategory="compression",
                        description="Server is not using gzip or brotli compression",
                        impact="Larger file sizes and slower downloads",
                        technical_details={
                            "content_encoding": content_encoding or "none",
                            "content_size_kb": round(len(response.content) / 1024, 2),
                            "recommended_compression": ["gzip", "brotli"],
                        },
                        recommendations=["Enable server-side compression"],
                        fix_suggestions=[
                            'Add "Content-Encoding: gzip" header',
                            "Configure web server for gzip compression",
                            "Consider brotli compression for better ratios",
                        ],
                        code_location=CodeLocation(
                            resource_type="http_headers",
                            attribute_name="content-encoding",
                            url_path=url,
                        ),
                        affected_elements=["server_config", "http_headers"],
                        priority_score=0.6,
                    )
                )

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="performance_analysis_failed",
                    severity=Severity.HIGH,
                    message=f"Failed to analyze performance: {str(e)}",
                    location=url,
                    category="performance",
                    subcategory="analysis_error",
                    description="Performance analysis failed due to connection or server error",
                    impact="Cannot determine performance issues",
                    technical_details={"error": str(e)},
                    recommendations=["Check server connectivity and try again"],
                    code_location=CodeLocation(
                        resource_type="http", attribute_value=url
                    ),
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_resources_detailed(self, url: str) -> dict:
        """Analyze page resources with detailed optimization suggestions."""
        issues = []
        metrics = {}
        raw = {}

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)

            if response.status_code != 200:
                return {"issues": [], "metrics": {}, "raw": {}}

            soup = BeautifulSoup(response.content, "html.parser")

            # Analyze images
            images = soup.find_all("img")
            external_images = []
            images_without_alt = []
            large_images = []

            for img in images:
                src = str(img.get("src", ""))
                alt = str(img.get("alt", ""))

                if src:
                    if src.startswith(("http://", "https://")) and not src.startswith(
                        url
                    ):
                        external_images.append(src)

                    if not alt:
                        images_without_alt.append(src)

                    width = img.get("width")
                    height = img.get("height")
                    if width and height:
                        try:
                            w, h = int(str(width)), int(str(height))
                            if w > 1920 or h > 1080 or (w * h > 2073600):
                                large_images.append({
                                    "src": src,
                                    "width": w,
                                    "height": h,
                                })
                        except ValueError:
                            pass

            metrics.update({
                "image_count": len(images),
                "external_images_count": len(external_images),
                "images_missing_alt": len(images_without_alt),
                "large_images_count": len(large_images),
            })

            raw["images"] = {
                "total": len(images),
                "external": external_images,
                "missing_alt": images_without_alt,
                "large": large_images,
            }

            # Large images issue
            if len(large_images) > 0:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="large_images_detected",
                        severity=Severity.MEDIUM,
                        message=f"Large images detected ({len(large_images)})",
                        location=url,
                        category="performance",
                        subcategory="image_optimization",
                        description="Images are larger than recommended dimensions",
                        impact="Slow page loading and high bandwidth usage",
                        technical_details={
                            "large_images_count": len(large_images),
                            "sample_large_images": large_images[:3],
                        },
                        recommendations=["Optimize large images for web"],
                        fix_suggestions=[
                            "Resize images to appropriate dimensions",
                            "Use WebP format for better compression",
                            "Implement responsive images with srcset",
                            "Enable lazy loading for images",
                        ],
                        code_location=CodeLocation(
                            element_selector="img",
                            element_tag="img",
                            resource_type="html",
                        ),
                        affected_elements=["img"],
                        priority_score=0.6,
                    )
                )

            # External images issue
            if len(external_images) > 10:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="too_many_external_images",
                        severity=Severity.MEDIUM,
                        message=f"Too many external images ({len(external_images)})",
                        location=url,
                        category="performance",
                        subcategory="resource_optimization",
                        description="Page relies heavily on external image sources",
                        impact="Dependency on external servers and potential loading delays",
                        technical_details={
                            "external_images_count": len(external_images),
                            "recommended_max": 10,
                            "sample_external_images": external_images[:3],
                        },
                        recommendations=["Consider hosting images locally"],
                        fix_suggestions=[
                            "Download and host critical images locally",
                            "Use CDN for better performance",
                            "Implement image optimization pipeline",
                        ],
                        code_location=CodeLocation(
                            element_selector="img[src^='http']",
                            element_tag="img",
                            resource_type="html",
                        ),
                        affected_elements=["img"],
                        priority_score=0.5,
                    )
                )

            # Analyze CSS and JS resources
            css_links = soup.find_all("link", rel="stylesheet")
            external_css = []
            for link in css_links:
                href = str(link.get("href", ""))
                if (
                    href
                    and href.startswith(("http://", "https://"))
                    and not href.startswith(url)
                ):
                    external_css.append(href)

            scripts = soup.find_all("script")
            external_js = []
            for script in scripts:
                src = str(script.get("src", ""))
                if (
                    src
                    and src.startswith(("http://", "https://"))
                    and not src.startswith(url)
                ):
                    external_js.append(src)

            metrics.update({
                "css_count": len(css_links),
                "external_css_count": len(external_css),
                "js_count": len([s for s in scripts if s.get("src")]),
                "external_js_count": len(external_js),
            })

            raw["resources"] = {
                "css": {"total": len(css_links), "external": external_css},
                "js": {
                    "total": len([s for s in scripts if s.get("src")]),
                    "external": external_js,
                },
            }

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="resource_analysis_failed",
                    severity=Severity.MEDIUM,
                    message=f"Failed to analyze resources: {str(e)}",
                    location=url,
                    category="performance",
                    subcategory="analysis_error",
                    description="Resource analysis failed",
                    impact="Cannot identify resource optimization opportunities",
                    technical_details={"error": str(e)},
                    recommendations=["Check page accessibility and try again"],
                    code_location=CodeLocation(
                        resource_type="html", attribute_value=url
                    ),
                    priority_score=0.4,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_core_web_vitals_detailed(self, url: str) -> dict:
        """Analyze Core Web Vitals with detailed context and optimization suggestions."""
        issues = []
        metrics = {}
        raw = {}

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Navigate to page
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)

                # Wait for page to stabilize
                await page.wait_for_timeout(2000)

                # Measure Core Web Vitals
                vitals = await page.evaluate("""
                    () => {
                        return new Promise((resolve) => {
                            if ('PerformanceObserver' in window) {
                                let lcp = 0;
                                let fcp = 0;
                                let cls = 0;

                                // LCP
                                new PerformanceObserver((list) => {
                                    const entries = list.getEntries();
                                    const lastEntry = entries[entries.length - 1];
                                    lcp = lastEntry.startTime;
                                }).observe({entryTypes: ['largest-contentful-paint']});

                                // FCP
                                new PerformanceObserver((list) => {
                                    const entries = list.getEntries();
                                    fcp = entries[0].startTime;
                                }).observe({entryTypes: ['first-contentful-paint']});

                                // CLS
                                new PerformanceObserver((list) => {
                                    for (const entry of list.getEntries()) {
                                        cls += entry.value;
                                    }
                                }).observe({entryTypes: ['layout-shift']});

                                setTimeout(() => resolve({lcp, fcp, cls}), 3000);
                            } else {
                                resolve({lcp: 0, fcp: 0, cls: 0});
                            }
                        });
                    }
                """)

                metrics.update({
                    "lcp": vitals.get("lcp", 0),
                    "fcp": vitals.get("fcp", 0),
                    "cls": vitals.get("cls", 0),
                })

                raw["core_web_vitals"] = vitals

                # Analyze LCP
                lcp = vitals.get("lcp", 0)
                if lcp > 4000:
                    issues.append(
                        self.create_detailed_issue(
                            issue_type="poor_lcp",
                            severity=Severity.HIGH,
                            message=f"Poor Largest Contentful Paint: {lcp:.0f}ms",
                            location=url,
                            category="performance",
                            subcategory="core_web_vitals",
                            description="LCP is above the recommended threshold of 2.5 seconds",
                            impact="Users perceive the page as slow to load",
                            technical_details={
                                "lcp_ms": lcp,
                                "recommended_max_ms": 2500,
                                "threshold": "poor",
                            },
                            recommendations=[
                                "Optimize LCP by improving largest content element loading"
                            ],
                            fix_suggestions=[
                                "Optimize hero image loading",
                                "Use preload for critical resources",
                                "Implement server-side rendering",
                                "Optimize server response times",
                            ],
                            code_location=CodeLocation(
                                resource_type="performance", attribute_value=url
                            ),
                            affected_elements=[
                                "images",
                                "server",
                                "critical_resources",
                            ],
                            priority_score=0.8,
                        )
                    )

                # Analyze CLS
                cls = vitals.get("cls", 0)
                if cls > 0.1:
                    issues.append(
                        self.create_detailed_issue(
                            issue_type="poor_cls",
                            severity=Severity.MEDIUM,
                            message=f"Poor Cumulative Layout Shift: {cls:.3f}",
                            location=url,
                            category="performance",
                            subcategory="core_web_vitals",
                            description="CLS is above the recommended threshold of 0.1",
                            impact="Page content shifts during loading, causing poor user experience",
                            technical_details={
                                "cls_value": cls,
                                "recommended_max": 0.1,
                                "threshold": "poor",
                            },
                            recommendations=[
                                "Fix layout shifts by reserving space for dynamic content"
                            ],
                            fix_suggestions=[
                                "Set explicit width and height for images",
                                "Reserve space for dynamic content",
                                "Avoid inserting content above existing content",
                                "Use CSS transforms instead of changing layout properties",
                            ],
                            code_location=CodeLocation(
                                resource_type="performance", attribute_value=url
                            ),
                            affected_elements=["images", "dynamic_content", "css"],
                            priority_score=0.7,
                        )
                    )

                await browser.close()

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="core_web_vitals_analysis_failed",
                    severity=Severity.MEDIUM,
                    message=f"Core Web Vitals analysis failed: {str(e)}",
                    location=url,
                    category="performance",
                    subcategory="analysis_error",
                    description="Could not measure Core Web Vitals",
                    impact="Cannot determine user experience metrics",
                    technical_details={"error": str(e)},
                    recommendations=["Check browser automation setup"],
                    code_location=CodeLocation(
                        resource_type="browser", attribute_value=url
                    ),
                    priority_score=0.4,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}
