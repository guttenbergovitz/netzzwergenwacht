"""Leistungs-Zwerg for performance analysis."""

import time

import httpx
from bs4 import BeautifulSoup

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
