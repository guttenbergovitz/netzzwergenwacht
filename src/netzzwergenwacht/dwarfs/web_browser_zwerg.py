"""Web-Browser-Zwerg for web page analysis."""

import time

import httpx
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

from .base import (
    AnalysisResult,
    CodeLocation,
    DetailedAnalysisResult,
    Dwarf,
    Issue,
    PerformanceMetrics,
    Severity,
)


class WebBrowserZwerg(Dwarf):
    """Web-Browser-Zwerg - Analyzes websites for HTTP status, performance and basic structure."""

    def __init__(self):
        super().__init__(
            name="Web-Browser-Zwerg",
            description="HTTP-based web page analysis for quality and accessibility checks",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL using HTTP requests and HTML parsing."""
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

            # Perform HTTP request and analysis
            start_time = time.time()

            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    response = await client.get(url, follow_redirects=True)
                    response_time = time.time() - start_time

                    # Add response metadata
                    metadata.update({
                        "status_code": response.status_code,
                        "response_time_ms": round(response_time * 1000, 2),
                        "content_type": response.headers.get("content-type", "unknown"),
                        "content_length": len(response.content),
                        "final_url": str(response.url),
                        "redirected": str(response.url) != url,
                    })

                    # Check HTTP status
                    issues.extend(await self._check_http_status(response, url))

                    # Check response time
                    issues.extend(await self._check_response_time(response_time, url))

                    # Parse HTML and perform content checks
                    if "text/html" in response.headers.get("content-type", ""):
                        soup = BeautifulSoup(response.content, "lxml")
                        metadata["title"] = (
                            soup.title.string.strip() if soup.title else None
                        )

                        issues.extend(await self._check_html_structure(soup, url))
                        issues.extend(await self._check_seo_basics(soup, url))
                        issues.extend(await self._check_accessibility_basics(soup, url))

                        # Perform browser-based analysis with Playwright
                        (
                            browser_issues,
                            browser_metadata,
                        ) = await self._analyze_with_playwright(url)
                        issues.extend(browser_issues)
                        metadata.update(browser_metadata)

                except httpx.RequestError as e:
                    issues.append(
                        self.create_issue(
                            issue_type="request_failed",
                            severity=Severity.CRITICAL,
                            message=f"Failed to connect to website: {str(e)}",
                            location=url,
                            evidence={"error": str(e)},
                        )
                    )

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

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL using HTTP requests, HTML parsing, and browser automation with detailed context."""
        try:
            detailed_issues = []
            perf_metrics = PerformanceMetrics()
            raw_data = {}

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
                        impact="Cannot analyze website without valid scheme.",
                        technical_details={"provided_url": url},
                        recommendations=[
                            "Use HTTPS URLs for better security and compatibility."
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

            # Perform HTTP request and analysis
            start_time = time.time()
            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    response = await client.get(url, follow_redirects=True)
                    response_time = time.time() - start_time

                    # Performance metrics
                    perf_metrics.response_time_ms = round(response_time * 1000, 2)
                    perf_metrics.page_load_time_ms = round(response_time * 1000, 2)
                    perf_metrics.total_size_bytes = len(response.content)
                    perf_metrics.performance_score = None  # Placeholder

                    # Raw data
                    raw_data["http_status_code"] = response.status_code
                    raw_data["headers"] = dict(response.headers)
                    raw_data["content_length"] = len(response.content)
                    raw_data["final_url"] = str(response.url)

                    # HTTP status issue
                    if response.status_code >= 400:
                        detailed_issues.append(
                            self.create_detailed_issue(
                                issue_type="http_error_status",
                                severity=Severity.CRITICAL,
                                message=f"HTTP error status: {response.status_code}",
                                location=url,
                                category="performance",
                                subcategory="http_status",
                                description=f"The server returned HTTP status {response.status_code}",
                                impact="Page is not accessible to users or bots.",
                                technical_details={"status_code": response.status_code},
                                recommendations=[
                                    "Fix the server error or misconfiguration."
                                ],
                                code_location=CodeLocation(
                                    resource_type="http",
                                    attribute_value=str(response.status_code),
                                ),
                                priority_score=1.0,
                            )
                        )

                    # Response time issue
                    if response_time > 5:
                        detailed_issues.append(
                            self.create_detailed_issue(
                                issue_type="slow_response_time",
                                severity=Severity.HIGH,
                                message=f"Slow response time: {response_time:.2f}s",
                                location=url,
                                category="performance",
                                subcategory="response_time",
                                description="The server responded slowly.",
                                impact="Slow pages reduce user satisfaction and SEO ranking.",
                                technical_details={
                                    "response_time_seconds": response_time
                                },
                                recommendations=[
                                    "Optimize server performance or use CDN."
                                ],
                                code_location=CodeLocation(
                                    resource_type="http", attribute_value=url
                                ),
                                priority_score=0.8,
                            )
                        )

                    # Parse HTML and perform content checks
                    if "text/html" in response.headers.get("content-type", ""):
                        soup = BeautifulSoup(response.content, "lxml")
                        title = soup.title.string.strip() if soup.title else None
                        perf_metrics.image_count = len(soup.find_all("img"))
                        perf_metrics.css_count = len(
                            soup.find_all("link", rel="stylesheet")
                        )
                        perf_metrics.js_count = len(soup.find_all("script"))
                        raw_data["html_title"] = title

                        # Title missing
                        if not title:
                            detailed_issues.append(
                                self.create_detailed_issue(
                                    issue_type="missing_title_tag",
                                    severity=Severity.HIGH,
                                    message="Missing <title> tag in HTML.",
                                    location=url,
                                    category="performance",
                                    subcategory="html_structure",
                                    description="No <title> tag found in the HTML head.",
                                    impact="SEO and usability are negatively affected.",
                                    technical_details={},
                                    recommendations=[
                                        "Add a <title> tag to the <head> section."
                                    ],
                                    code_location=CodeLocation(
                                        element_selector="head",
                                        element_tag="head",
                                        resource_type="html",
                                    ),
                                    priority_score=0.9,
                                )
                            )

                        # Meta description missing
                        meta_desc = soup.find("meta", attrs={"name": "description"})
                        if not meta_desc:
                            detailed_issues.append(
                                self.create_detailed_issue(
                                    issue_type="missing_meta_description",
                                    severity=Severity.MEDIUM,
                                    message="Missing meta description tag.",
                                    location=url,
                                    category="performance",
                                    subcategory="html_structure",
                                    description="No meta description tag found in the HTML head.",
                                    impact="SEO and search result appearance are negatively affected.",
                                    technical_details={},
                                    recommendations=[
                                        "Add a <meta name='description'> tag to the <head> section."
                                    ],
                                    code_location=CodeLocation(
                                        element_selector="head",
                                        element_tag="head",
                                        resource_type="html",
                                    ),
                                    priority_score=0.7,
                                )
                            )

                        # TODO: Add more detailed HTML checks as needed

                        # Browser-based analysis with Playwright
                        (
                            browser_issues,
                            browser_metadata,
                            browser_raw,
                        ) = await self._analyze_with_playwright_detailed(url)
                        detailed_issues.extend(browser_issues)
                        raw_data["browser"] = browser_raw
                        for k, v in browser_metadata.items():
                            setattr(perf_metrics, k, v)

                except httpx.RequestError as e:
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="request_failed",
                            severity=Severity.CRITICAL,
                            message=f"Failed to connect to website: {str(e)}",
                            location=url,
                            category="performance",
                            subcategory="http_request",
                            description="HTTP request failed.",
                            impact="Page could not be analyzed.",
                            technical_details={"error": str(e)},
                            recommendations=[
                                "Check network connectivity and server status."
                            ],
                            code_location=CodeLocation(
                                resource_type="http", attribute_value=url
                            ),
                            priority_score=1.0,
                        )
                    )

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

    async def _analyze_with_playwright(self, url: str) -> tuple[list[Issue], dict]:
        """Analyze page using real browser automation with Playwright."""
        issues = []
        metadata = {}

        try:
            async with async_playwright() as p:
                # Launch browser (headless for automation)
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Set user agent
                await page.set_extra_http_headers({
                    "User-Agent": "NetzZwergenWacht Browser Dwarf v0.1.0"
                })

                # Navigate to page and wait for load
                start_time = time.time()
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=30000
                )
                load_time = time.time() - start_time

                # Add browser metadata
                metadata.update({
                    "browser_load_time_ms": round(load_time * 1000, 2),
                    "browser_status_code": response.status if response else None,
                    "browser_final_url": page.url,
                })

                # Check for JavaScript console errors
                console_errors = []
                page.on(
                    "console",
                    lambda msg: console_errors.append(msg.text)
                    if msg.type == "error"
                    else None,
                )

                # Wait a bit for any delayed JavaScript errors
                await page.wait_for_timeout(2000)

                if console_errors:
                    issues.append(
                        self.create_issue(
                            issue_type="javascript_console_errors",
                            severity=Severity.MEDIUM,
                            message=f"JavaScript console errors detected: {len(console_errors)} errors",
                            location=url,
                            evidence={
                                "console_error_count": len(console_errors),
                                "sample_errors": console_errors[
                                    :3
                                ],  # Show first 3 errors
                            },
                        )
                    )

                # Check for network errors
                failed_requests = []
                page.on(
                    "requestfailed", lambda request: failed_requests.append(request.url)
                )

                if failed_requests:
                    issues.append(
                        self.create_issue(
                            issue_type="failed_network_requests",
                            severity=Severity.MEDIUM,
                            message=f"Failed network requests detected: {len(failed_requests)} requests",
                            location=url,
                            evidence={
                                "failed_request_count": len(failed_requests),
                                "sample_failed_requests": failed_requests[:3],
                            },
                        )
                    )

                # Check for render-blocking resources
                performance_entries = await page.evaluate("""
                    () => {
                        const entries = performance.getEntriesByType('resource');
                        return entries.filter(entry =>
                            entry.initiatorType === 'link' ||
                            entry.initiatorType === 'script'
                        ).map(entry => ({
                            name: entry.name,
                            type: entry.initiatorType,
                            duration: entry.duration
                        }));
                    }
                """)

                # Add performance metadata
                metadata["performance_entries"] = performance_entries

                # Perform mobile and responsive testing
                mobile_issues, mobile_metadata = await self._test_mobile_responsive(
                    page, url
                )
                issues.extend(mobile_issues)
                metadata.update(mobile_metadata)

                # Take screenshots for different viewports
                screenshot_metadata = await self._take_responsive_screenshots(page, url)
                metadata.update(screenshot_metadata)

                await browser.close()

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="browser_analysis_failed",
                    severity=Severity.MEDIUM,
                    message=f"Browser analysis failed: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def _analyze_with_playwright_detailed(self, url: str):
        """Analyze page using Playwright and return detailed issues, metrics, and raw data."""
        issues = []
        metadata = {}
        raw = {}
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.set_extra_http_headers({
                    "User-Agent": "NetzZwergenWacht Browser Dwarf v0.1.0"
                })
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=30000
                )
                load_time = await page.evaluate(
                    "performance.timing.loadEventEnd - performance.timing.navigationStart"
                )
                metadata["browser_load_time_ms"] = load_time
                metadata["browser_status_code"] = response.status if response else None
                metadata["browser_final_url"] = page.url
                raw["browser_final_url"] = page.url

                # JS console errors
                console_errors = []
                page.on(
                    "console",
                    lambda msg: console_errors.append(msg.text)
                    if msg.type == "error"
                    else None,
                )
                await page.wait_for_timeout(2000)
                if console_errors:
                    issues.append(
                        self.create_detailed_issue(
                            issue_type="javascript_console_errors",
                            severity=Severity.MEDIUM,
                            message=f"JavaScript console errors detected: {len(console_errors)} errors",
                            location=url,
                            category="performance",
                            subcategory="javascript",
                            description="JavaScript errors were detected in the browser console.",
                            impact="May break functionality or UX.",
                            technical_details={
                                "console_error_count": len(console_errors),
                                "sample_errors": console_errors[:3],
                            },
                            recommendations=[
                                "Fix JavaScript errors in the browser console."
                            ],
                            code_location=CodeLocation(
                                resource_type="js", url_path=url
                            ),
                            browser_console_errors=console_errors,
                            priority_score=0.7,
                        )
                    )
                raw["console_errors"] = console_errors

                # Network errors
                failed_requests = []
                page.on(
                    "requestfailed", lambda request: failed_requests.append(request.url)
                )
                if failed_requests:
                    issues.append(
                        self.create_detailed_issue(
                            issue_type="failed_network_requests",
                            severity=Severity.MEDIUM,
                            message=f"Failed network requests detected: {len(failed_requests)} requests",
                            location=url,
                            category="performance",
                            subcategory="network",
                            description="Some network requests failed during page load.",
                            impact="Missing resources may break page functionality or appearance.",
                            technical_details={
                                "failed_request_count": len(failed_requests),
                                "sample_failed_requests": failed_requests[:3],
                            },
                            recommendations=[
                                "Check resource URLs and server availability."
                            ],
                            code_location=CodeLocation(
                                resource_type="network", url_path=url
                            ),
                            network_errors=failed_requests,
                            priority_score=0.6,
                        )
                    )
                raw["failed_requests"] = failed_requests

                # TODO: Add more browser-based checks (viewport, screenshots, etc.)

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="browser_analysis_failed",
                    severity=Severity.MEDIUM,
                    message=f"Browser-based analysis failed: {str(e)}",
                    location=url,
                    category="performance",
                    subcategory="browser",
                    description="Browser automation failed.",
                    impact="Some dynamic issues may not be detected.",
                    technical_details={"error": str(e)},
                    recommendations=["Check Playwright setup and page compatibility."],
                    code_location=CodeLocation(resource_type="browser", url_path=url),
                    priority_score=0.5,
                )
            )
        return issues, metadata, raw

    async def _test_mobile_responsive(self, page, url: str) -> tuple[list[Issue], dict]:
        """Test mobile and responsive design features."""
        issues = []
        metadata = {}

        # Test different viewport sizes
        viewports = {
            "mobile": {"width": 375, "height": 667},
            "tablet": {"width": 768, "height": 1024},
            "desktop": {"width": 1920, "height": 1080},
        }

        viewport_results = {}

        for device, viewport in viewports.items():
            await page.set_viewport_size(viewport)
            await page.wait_for_timeout(1000)  # Wait for layout to settle

            # Check for horizontal scrolling
            has_horizontal_scroll = await page.evaluate("""
                () => {
                    return document.documentElement.scrollWidth > document.documentElement.clientWidth;
                }
            """)

            # Check for touch target sizes
            small_touch_targets = await page.evaluate("""
                () => {
                    const touchElements = document.querySelectorAll('button, a, input, select, [role="button"]');
                    const smallTargets = [];

                    touchElements.forEach(element => {
                        const rect = element.getBoundingClientRect();
                        if (rect.width < 44 || rect.height < 44) {
                            smallTargets.push({
                                tag: element.tagName,
                                text: element.textContent?.substring(0, 50) || '',
                                size: `${rect.width}x${rect.height}`
                            });
                        }
                    });

                    return smallTargets;
                }
            """)

            # Check for font sizes
            small_fonts = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    const smallFontElements = [];

                    elements.forEach(element => {
                        const style = window.getComputedStyle(element);
                        const fontSize = parseFloat(style.fontSize);
                        if (fontSize < 16) {
                            smallFontElements.push({
                                tag: element.tagName,
                                text: element.textContent?.substring(0, 30) || '',
                                fontSize: fontSize
                            });
                        }
                    });

                    return smallFontElements.slice(0, 10); // Limit results
                }
            """)

            viewport_results[device] = {
                "has_horizontal_scroll": has_horizontal_scroll,
                "small_touch_targets": small_touch_targets,
                "small_fonts": small_fonts,
            }

            # Create issues for this viewport
            if has_horizontal_scroll:
                issues.append(
                    self.create_issue(
                        issue_type=f"mobile_horizontal_scroll_{device}",
                        severity=Severity.MEDIUM,
                        message=f"Mobile accessibility: Horizontal scrolling detected on {device} viewport",
                        location=url,
                        evidence={
                            "viewport": viewport,
                            "device": device,
                            "recommendation": "Ensure content fits within viewport width",
                        },
                    )
                )

            if small_touch_targets:
                issues.append(
                    self.create_issue(
                        issue_type=f"mobile_small_touch_targets_{device}",
                        severity=Severity.MEDIUM,
                        message=f"Mobile accessibility: {len(small_touch_targets)} small touch targets on {device}",
                        location=url,
                        evidence={
                            "viewport": viewport,
                            "device": device,
                            "small_targets_count": len(small_touch_targets),
                            "sample_targets": small_touch_targets[:3],
                            "recommendation": "Ensure touch targets are at least 44x44px",
                        },
                    )
                )

            if small_fonts:
                issues.append(
                    self.create_issue(
                        issue_type=f"mobile_small_fonts_{device}",
                        severity=Severity.LOW,
                        message=f"Mobile accessibility: {len(small_fonts)} elements with small fonts on {device}",
                        location=url,
                        evidence={
                            "viewport": viewport,
                            "device": device,
                            "small_fonts_count": len(small_fonts),
                            "sample_fonts": small_fonts[:3],
                            "recommendation": "Use at least 16px font size for mobile readability",
                        },
                    )
                )

        metadata["viewport_testing"] = viewport_results

        return issues, metadata

    async def _take_responsive_screenshots(self, page, url: str) -> dict:
        """Take screenshots for different viewport sizes and save to output directory."""
        import os
        from datetime import datetime

        metadata = {}
        screenshots_taken = []

        # Create output directory if it doesn't exist
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Generate timestamp for unique filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Clean URL for filename
        safe_url = url.replace("://", "_").replace("/", "_").replace(".", "_")[:50]

        viewports = {
            "mobile": {"width": 375, "height": 667},
            "tablet": {"width": 768, "height": 1024},
            "desktop": {"width": 1920, "height": 1080},
        }

        for device, viewport in viewports.items():
            try:
                await page.set_viewport_size(viewport)
                await page.wait_for_timeout(1000)  # Wait for layout to settle

                # Take screenshot
                filename = f"{output_dir}/{safe_url}_{device}_{timestamp}.png"
                await page.screenshot(path=filename, full_page=True)

                screenshots_taken.append({
                    "device": device,
                    "viewport": viewport,
                    "filename": filename,
                })

            except Exception as e:
                # Log error but continue with other viewports
                screenshots_taken.append({
                    "device": device,
                    "viewport": viewport,
                    "error": str(e),
                })

        metadata["screenshots"] = screenshots_taken
        metadata["screenshots_directory"] = output_dir

        return metadata

    async def _check_browser_accessibility(self, page, url: str) -> list[Issue]:
        """Check accessibility issues using browser automation."""
        issues = []

        try:
            # Check for focusable elements without proper labels
            focusable_elements = await page.evaluate("""
                () => {
                    const focusable = document.querySelectorAll(
                        'button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])'
                    );
                    const unlabeled = Array.from(focusable).filter(el => {
                        const hasLabel = el.getAttribute('aria-label') ||
                                       el.getAttribute('title') ||
                                       el.textContent.trim() ||
                                       el.querySelector('img[alt]');
                        return !hasLabel;
                    });
                    return unlabeled.map(el => ({
                        tagName: el.tagName.toLowerCase(),
                        id: el.id || 'no-id',
                        className: el.className || 'no-class'
                    }));
                }
            """)

            if focusable_elements:
                issues.append(
                    self.create_issue(
                        issue_type="unlabeled_focusable_elements",
                        severity=Severity.MEDIUM,
                        message=f"Focusable elements without proper labels: {len(focusable_elements)} elements",
                        location=url,
                        evidence={
                            "unlabeled_count": len(focusable_elements),
                            "sample_elements": focusable_elements[:3],
                        },
                    )
                )

        except Exception as e:
            # Browser accessibility check failed, but don't fail the entire analysis
            # Log the exception for debugging purposes
            print(f"Browser accessibility check failed for {url}: {e}")

        return issues

    async def _check_http_status(
        self, response: httpx.Response, url: str
    ) -> list[Issue]:
        """Check HTTP status code for issues."""
        issues = []

        if response.status_code >= 400:
            severity = (
                Severity.CRITICAL if response.status_code >= 500 else Severity.HIGH
            )
            issues.append(
                self.create_issue(
                    issue_type="http_error",
                    severity=severity,
                    message=f"HTTP {response.status_code} error",
                    location=url,
                    evidence={
                        "status_code": response.status_code,
                        "reason_phrase": response.reason_phrase,
                    },
                )
            )
        elif response.status_code >= 300:
            issues.append(
                self.create_issue(
                    issue_type="http_redirect",
                    severity=Severity.LOW,
                    message=f"HTTP {response.status_code} redirect",
                    location=url,
                    evidence={
                        "status_code": response.status_code,
                        "final_url": str(response.url),
                    },
                )
            )

        return issues

    async def _check_response_time(self, response_time: float, url: str) -> list[Issue]:
        """Check response time performance."""
        issues = []

        if response_time > 5.0:
            issues.append(
                self.create_issue(
                    issue_type="slow_response",
                    severity=Severity.HIGH,
                    message=f"Slow response time: {response_time:.2f}s",
                    location=url,
                    evidence={"response_time_seconds": response_time},
                )
            )
        elif response_time > 2.0:
            issues.append(
                self.create_issue(
                    issue_type="slow_response",
                    severity=Severity.MEDIUM,
                    message=f"Moderate response time: {response_time:.2f}s",
                    location=url,
                    evidence={"response_time_seconds": response_time},
                )
            )

        return issues

    async def _check_html_structure(self, soup: BeautifulSoup, url: str) -> list[Issue]:
        """Check basic HTML structure issues."""
        issues = []

        # Check for missing title
        if not soup.title or not soup.title.string.strip():
            issues.append(
                self.create_issue(
                    issue_type="missing_title",
                    severity=Severity.HIGH,
                    message="Page is missing a title tag",
                    location=url,
                    evidence={"title_tag_exists": bool(soup.title)},
                )
            )

        # Check for missing meta description
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if not meta_desc or not meta_desc.get("content", "").strip():
            issues.append(
                self.create_issue(
                    issue_type="missing_meta_description",
                    severity=Severity.MEDIUM,
                    message="Page is missing meta description",
                    location=url,
                    evidence={"meta_description_exists": bool(meta_desc)},
                )
            )

        return issues

    async def _check_seo_basics(self, soup: BeautifulSoup, url: str) -> list[Issue]:
        """Check basic SEO requirements."""
        issues = []

        # Check title length
        if soup.title and soup.title.string:
            title_length = len(soup.title.string.strip())
            if title_length > 60:
                issues.append(
                    self.create_issue(
                        issue_type="title_too_long",
                        severity=Severity.MEDIUM,
                        message=f"Title is too long ({title_length} chars, recommended <60)",
                        location=url,
                        evidence={
                            "title_length": title_length,
                            "title": soup.title.string.strip(),
                        },
                    )
                )

        # Check for H1 tags
        h1_tags = soup.find_all("h1")
        if len(h1_tags) == 0:
            issues.append(
                self.create_issue(
                    issue_type="missing_h1",
                    severity=Severity.MEDIUM,
                    message="Page is missing H1 heading",
                    location=url,
                    evidence={"h1_count": 0},
                )
            )
        elif len(h1_tags) > 1:
            issues.append(
                self.create_issue(
                    issue_type="multiple_h1",
                    severity=Severity.LOW,
                    message=f"Page has multiple H1 headings ({len(h1_tags)})",
                    location=url,
                    evidence={"h1_count": len(h1_tags)},
                )
            )

        return issues

    async def _check_accessibility_basics(
        self, soup: BeautifulSoup, url: str
    ) -> list[Issue]:
        """Check basic accessibility requirements."""
        issues = []

        # Check for images without alt text
        images = soup.find_all("img")
        images_without_alt = [img for img in images if not img.get("alt")]

        if images_without_alt:
            issues.append(
                self.create_issue(
                    issue_type="images_missing_alt",
                    severity=Severity.MEDIUM,
                    message=f"{len(images_without_alt)} images missing alt text",
                    location=url,
                    evidence={
                        "total_images": len(images),
                        "images_without_alt": len(images_without_alt),
                    },
                )
            )

        # Check for missing language attribute
        html_tag = soup.find("html")
        if not html_tag or not html_tag.get("lang"):
            issues.append(
                self.create_issue(
                    issue_type="missing_lang_attribute",
                    severity=Severity.MEDIUM,
                    message="HTML tag is missing lang attribute",
                    location=url,
                    evidence={
                        "lang_attribute_exists": bool(html_tag and html_tag.get("lang"))
                    },
                )
            )

        return issues
