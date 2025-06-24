"""Web-Browser-Zwerg for web page analysis."""

import time

import httpx
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

from .base import AnalysisResult, Dwarf, Issue, Severity


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

                if performance_entries:
                    metadata["resource_count"] = len(performance_entries)
                    slow_resources = [
                        r for r in performance_entries if r["duration"] > 1000
                    ]

                    if slow_resources:
                        issues.append(
                            self.create_issue(
                                issue_type="slow_loading_resources",
                                severity=Severity.LOW,
                                message=f"Slow loading resources detected: {len(slow_resources)} resources",
                                location=url,
                                evidence={
                                    "slow_resource_count": len(slow_resources),
                                    "sample_slow_resources": slow_resources[:3],
                                },
                            )
                        )

                # Check for accessibility issues using browser
                accessibility_issues = await self._check_browser_accessibility(
                    page, url
                )
                issues.extend(accessibility_issues)

                await browser.close()

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="browser_analysis_failed",
                    severity=Severity.LOW,
                    message=f"Browser analysis failed: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

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
