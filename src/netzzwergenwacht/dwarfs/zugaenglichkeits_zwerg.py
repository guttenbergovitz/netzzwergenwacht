"""Zugaenglichkeits-Zwerg for EU Accessibility Act (EAA) compliance analysis."""

import re

import httpx
from bs4 import BeautifulSoup

from .base import (
    AccessibilityMetrics,
    AnalysisResult,
    CodeLocation,
    DetailedAnalysisResult,
    Dwarf,
    Severity,
)


class ZugaenglichkeitsZwerg(Dwarf):
    """Zugaenglichkeits-Zwerg - Analyzes websites for EU Accessibility Act compliance and WCAG 2.1 AA requirements."""

    def __init__(self):
        super().__init__(
            name="Zugaenglichkeits-Zwerg",
            description="EU Accessibility Act compliance analysis for WCAG 2.1 AA requirements",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL for accessibility compliance."""
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

            # Perform accessibility analysis
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                try:
                    response = await client.get(url)

                    if response.status_code != 200:
                        issues.append(
                            self.create_issue(
                                issue_type="page_not_accessible",
                                severity=Severity.HIGH,
                                message=f"Page returned status code {response.status_code}",
                                location=url,
                                evidence={"status_code": response.status_code},
                            )
                        )
                        return AnalysisResult(
                            url=url,
                            dwarf_name=self.name,
                            issues=issues,
                            metadata=metadata,
                        )

                    # Parse HTML content
                    soup = BeautifulSoup(response.content, "html.parser")

                    # WCAG 2.1 AA Compliance Checks

                    # 1. Perceivable
                    text_alternatives = await self._check_text_alternatives(soup, url)
                    issues.extend(text_alternatives["issues"])
                    metadata.update(text_alternatives["metadata"])

                    color_contrast = await self._check_color_contrast(soup, url)
                    issues.extend(color_contrast["issues"])
                    metadata.update(color_contrast["metadata"])

                    # 2. Operable
                    keyboard_access = await self._check_keyboard_accessibility(
                        soup, url
                    )
                    issues.extend(keyboard_access["issues"])
                    metadata.update(keyboard_access["metadata"])

                    focus_management = await self._check_focus_management(soup, url)
                    issues.extend(focus_management["issues"])
                    metadata.update(focus_management["metadata"])

                    # 3. Understandable
                    language_identification = await self._check_language_identification(
                        soup, url
                    )
                    issues.extend(language_identification["issues"])
                    metadata.update(language_identification["metadata"])

                    forms_labels = await self._check_forms_and_labels(soup, url)
                    issues.extend(forms_labels["issues"])
                    metadata.update(forms_labels["metadata"])

                    # 4. Robust
                    semantic_structure = await self._check_semantic_structure(soup, url)
                    issues.extend(semantic_structure["issues"])
                    metadata.update(semantic_structure["metadata"])

                    aria_compliance = await self._check_aria_compliance(soup, url)
                    issues.extend(aria_compliance["issues"])
                    metadata.update(aria_compliance["metadata"])

                    # EAA-specific requirements
                    eaa_compliance = await self._check_eaa_specific_requirements(
                        soup, url
                    )
                    issues.extend(eaa_compliance["issues"])
                    metadata.update(eaa_compliance["metadata"])

                    # Mobile and responsive accessibility testing
                    mobile_responsive = (
                        await self._check_mobile_responsive_accessibility(soup, url)
                    )
                    issues.extend(mobile_responsive["issues"])
                    metadata.update(mobile_responsive["metadata"])

                    responsive_breakpoints = await self._check_responsive_breakpoints(
                        soup, url
                    )
                    issues.extend(responsive_breakpoints["issues"])
                    metadata.update(responsive_breakpoints["metadata"])

                    mobile_performance = (
                        await self._check_mobile_performance_accessibility(soup, url)
                    )
                    issues.extend(mobile_performance["issues"])
                    metadata.update(mobile_performance["metadata"])

                except httpx.RequestError as e:
                    issues.append(
                        self.create_issue(
                            issue_type="accessibility_analysis_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to analyze accessibility: {str(e)}",
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
        """Analyze a URL for accessibility compliance with detailed context and improvement suggestions."""
        try:
            detailed_issues = []
            accessibility_metrics = AccessibilityMetrics()
            raw_data = {}

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="invalid_url_scheme",
                        severity=Severity.HIGH,
                        message="URL must start with http:// or https://",
                        location=url,
                        category="accessibility",
                        subcategory="url_structure",
                        description="The provided URL does not use a valid HTTP scheme",
                        impact="Cannot perform accessibility analysis without valid scheme.",
                        technical_details={"provided_url": url},
                        recommendations=[
                            "Use HTTPS URLs for better security and accessibility."
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
                    accessibility_metrics=accessibility_metrics,
                    raw_data=raw_data,
                )

            # Perform detailed accessibility analysis
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                try:
                    response = await client.get(url)

                    if response.status_code != 200:
                        detailed_issues.append(
                            self.create_detailed_issue(
                                issue_type="page_not_accessible",
                                severity=Severity.HIGH,
                                message=f"Page returned status code {response.status_code}",
                                location=url,
                                category="accessibility",
                                subcategory="page_accessibility",
                                description="Page is not accessible due to HTTP error",
                                impact="Users cannot access the page content",
                                technical_details={"status_code": response.status_code},
                                recommendations=[
                                    "Fix server configuration to return 200 status"
                                ],
                                fix_suggestions=[
                                    "Check server configuration",
                                    "Verify URL is correct",
                                    "Ensure server is running",
                                ],
                                code_location=CodeLocation(
                                    resource_type="http", attribute_value=url
                                ),
                                priority_score=0.9,
                            )
                        )
                        return DetailedAnalysisResult(
                            url=url,
                            dwarf_name=self.name,
                            detailed_issues=detailed_issues,
                            accessibility_metrics=accessibility_metrics,
                            raw_data=raw_data,
                        )

                    # Parse HTML content
                    soup = BeautifulSoup(response.content, "html.parser")
                    raw_data["html_structure"] = {
                        "title": soup.title.string if soup.title else None,
                        "headings": [
                            h.get_text()
                            for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
                        ],
                        "forms_count": len(soup.find_all("form")),
                        "images_count": len(soup.find_all("img")),
                        "links_count": len(soup.find_all("a")),
                    }

                    # WCAG 2.1 AA Compliance Checks with detailed context

                    # 1. Perceivable
                    text_alternatives = await self._check_text_alternatives_detailed(
                        soup, url
                    )
                    detailed_issues.extend(text_alternatives["issues"])
                    accessibility_metrics.images_without_alt = text_alternatives[
                        "metrics"
                    ].get("images_without_alt", 0)
                    accessibility_metrics.total_images = text_alternatives[
                        "metrics"
                    ].get("total_images", 0)
                    raw_data["text_alternatives"] = text_alternatives["raw"]

                    color_contrast = await self._check_color_contrast_detailed(
                        soup, url
                    )
                    detailed_issues.extend(color_contrast["issues"])
                    accessibility_metrics.low_contrast_elements = color_contrast[
                        "metrics"
                    ].get("low_contrast_elements", 0)
                    raw_data["color_contrast"] = color_contrast["raw"]

                    # 2. Operable
                    keyboard_access = await self._check_keyboard_accessibility_detailed(
                        soup, url
                    )
                    detailed_issues.extend(keyboard_access["issues"])
                    accessibility_metrics.keyboard_inaccessible = keyboard_access[
                        "metrics"
                    ].get("keyboard_inaccessible", 0)
                    raw_data["keyboard_accessibility"] = keyboard_access["raw"]

                    focus_management = await self._check_focus_management_detailed(
                        soup, url
                    )
                    detailed_issues.extend(focus_management["issues"])
                    accessibility_metrics.focus_issues = focus_management[
                        "metrics"
                    ].get("focus_issues", 0)
                    raw_data["focus_management"] = focus_management["raw"]

                    # 3. Understandable
                    language_identification = (
                        await self._check_language_identification_detailed(soup, url)
                    )
                    detailed_issues.extend(language_identification["issues"])
                    accessibility_metrics.language_issues = language_identification[
                        "metrics"
                    ].get("language_issues", 0)
                    raw_data["language_identification"] = language_identification["raw"]

                    forms_labels = await self._check_forms_and_labels_detailed(
                        soup, url
                    )
                    detailed_issues.extend(forms_labels["issues"])
                    accessibility_metrics.form_issues = forms_labels["metrics"].get(
                        "form_issues", 0
                    )
                    raw_data["forms_and_labels"] = forms_labels["raw"]

                    # 4. Robust
                    semantic_structure = await self._check_semantic_structure_detailed(
                        soup, url
                    )
                    detailed_issues.extend(semantic_structure["issues"])
                    accessibility_metrics.semantic_issues = semantic_structure[
                        "metrics"
                    ].get("semantic_issues", 0)
                    raw_data["semantic_structure"] = semantic_structure["raw"]

                    aria_compliance = await self._check_aria_compliance_detailed(
                        soup, url
                    )
                    detailed_issues.extend(aria_compliance["issues"])
                    accessibility_metrics.aria_issues = aria_compliance["metrics"].get(
                        "aria_issues", 0
                    )
                    raw_data["aria_compliance"] = aria_compliance["raw"]

                    # EAA-specific requirements
                    eaa_compliance = (
                        await self._check_eaa_specific_requirements_detailed(soup, url)
                    )
                    detailed_issues.extend(eaa_compliance["issues"])
                    accessibility_metrics.eaa_issues = eaa_compliance["metrics"].get(
                        "eaa_issues", 0
                    )
                    raw_data["eaa_compliance"] = eaa_compliance["raw"]

                    # Mobile and responsive accessibility testing
                    mobile_responsive = (
                        await self._check_mobile_responsive_accessibility_detailed(
                            soup, url
                        )
                    )
                    detailed_issues.extend(mobile_responsive["issues"])
                    accessibility_metrics.mobile_issues = mobile_responsive[
                        "metrics"
                    ].get("mobile_issues", 0)
                    raw_data["mobile_responsive"] = mobile_responsive["raw"]

                except httpx.RequestError as e:
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="accessibility_analysis_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to analyze accessibility: {str(e)}",
                            location=url,
                            category="accessibility",
                            subcategory="analysis_error",
                            description="Accessibility analysis failed due to connection error",
                            impact="Cannot determine accessibility compliance",
                            technical_details={"error": str(e)},
                            recommendations=[
                                "Check network connectivity and try again"
                            ],
                            code_location=CodeLocation(
                                resource_type="http", attribute_value=url
                            ),
                            priority_score=0.5,
                        )
                    )

            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                detailed_issues=detailed_issues,
                accessibility_metrics=accessibility_metrics,
                raw_data=raw_data,
            )

        except Exception as e:
            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                success=False,
                error_message=str(e),
            )

    async def _check_text_alternatives(self, soup: BeautifulSoup, url: str) -> dict:
        """Check WCAG 1.1.1 - Text Alternatives for non-text content."""
        issues = []
        metadata = {}

        # Check images for alt text
        images = soup.find_all("img")
        images_without_alt = []
        decorative_images = []
        complex_images = []

        for img in images:
            src = img.get("src", "")
            alt = img.get("alt")

            if src:
                if alt is None:
                    images_without_alt.append(src)
                elif alt == "":
                    decorative_images.append(src)
                elif len(alt) > 150:
                    complex_images.append({"src": src, "alt_length": len(alt)})

        metadata.update({
            "total_images": len(images),
            "images_without_alt": len(images_without_alt),
            "decorative_images": len(decorative_images),
            "complex_images": len(complex_images),
        })

        if images_without_alt:
            issues.append(
                self.create_issue(
                    issue_type="wcag_1_1_1_missing_alt_text",
                    severity=Severity.HIGH,
                    message=f"WCAG 1.1.1: {len(images_without_alt)} images missing alt text",
                    location=url,
                    evidence={
                        "missing_alt_count": len(images_without_alt),
                        "sample_images": images_without_alt[:5],
                        "wcag_guideline": "1.1.1 Non-text Content (Level A)",
                    },
                )
            )

        # Check for complex images that may need long descriptions
        if complex_images:
            issues.append(
                self.create_issue(
                    issue_type="wcag_1_1_1_complex_images_need_longdesc",
                    severity=Severity.MEDIUM,
                    message=f"WCAG 1.1.1: {len(complex_images)} complex images may need detailed descriptions",
                    location=url,
                    evidence={
                        "complex_images_count": len(complex_images),
                        "sample_complex": complex_images[:3],
                        "recommendation": "Consider using longdesc or detailed captions for complex images",
                    },
                )
            )

        # Check audio/video elements
        media_elements = soup.find_all(["audio", "video"])
        media_without_alternatives = []

        for media in media_elements:
            # Check for captions, transcripts, or audio descriptions
            has_track = media.find("track")
            has_captions = has_track and "captions" in str(has_track)
            has_transcript = "transcript" in media.get("aria-describedby", "").lower()

            if not (has_captions or has_transcript):
                media_without_alternatives.append({
                    "tag": media.name,
                    "src": media.get("src", "embedded"),
                })

        if media_without_alternatives:
            issues.append(
                self.create_issue(
                    issue_type="wcag_1_2_media_missing_alternatives",
                    severity=Severity.HIGH,
                    message=f"WCAG 1.2: {len(media_without_alternatives)} media elements missing captions/transcripts",
                    location=url,
                    evidence={
                        "media_without_alternatives": media_without_alternatives,
                        "wcag_guideline": "1.2 Time-based Media",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_color_contrast(self, soup: BeautifulSoup, url: str) -> dict:
        """Check WCAG 1.4.3 & 1.4.6 - Color Contrast requirements."""
        issues = []
        metadata = {}

        # Extract CSS and inline styles for contrast analysis
        style_elements = soup.find_all("style")
        inline_styles = soup.find_all(attrs={"style": True})

        contrast_issues = []
        potential_issues = 0

        # Basic color analysis - look for common problematic patterns
        for element in inline_styles:
            style = element.get("style", "").lower()
            if "color:" in style and "background" in style:
                potential_issues += 1
                # Simple heuristic for potential contrast issues
                if any(
                    low_contrast in style
                    for low_contrast in ["#999", "#ccc", "#ddd", "gray", "lightgray"]
                ):
                    contrast_issues.append({
                        "element": element.name,
                        "style": style[:100],  # Truncate for evidence
                    })

        metadata.update({
            "elements_with_inline_styles": len(inline_styles),
            "potential_contrast_issues": potential_issues,
            "style_elements_count": len(style_elements),
        })

        if contrast_issues:
            issues.append(
                self.create_issue(
                    issue_type="wcag_1_4_3_potential_contrast_issues",
                    severity=Severity.MEDIUM,
                    message=f"WCAG 1.4.3: {len(contrast_issues)} elements with potential contrast issues detected",
                    location=url,
                    evidence={
                        "contrast_issues": contrast_issues[:5],
                        "wcag_guideline": "1.4.3 Contrast (Minimum) (Level AA)",
                        "recommendation": "Ensure 4.5:1 contrast ratio for normal text, 3:1 for large text",
                    },
                )
            )

        # Check for color-only information
        elements_with_color_info = soup.find_all(
            attrs={"style": re.compile(r"color\s*:", re.I)}
        )
        color_only_indicators = []

        for element in elements_with_color_info:
            text = element.get_text(strip=True)
            # Look for potential color-only information (status indicators, etc.)
            if any(
                indicator in text.lower()
                for indicator in ["error", "success", "warning", "required", "invalid"]
            ):
                if not element.find(["strong", "em", "b", "i"]) and not element.get(
                    "aria-label"
                ):
                    color_only_indicators.append({
                        "text": text[:50],
                        "element": element.name,
                    })

        if color_only_indicators:
            issues.append(
                self.create_issue(
                    issue_type="wcag_1_4_1_color_only_information",
                    severity=Severity.MEDIUM,
                    message=f"WCAG 1.4.1: {len(color_only_indicators)} elements may rely on color alone for information",
                    location=url,
                    evidence={
                        "color_only_indicators": color_only_indicators[:3],
                        "wcag_guideline": "1.4.1 Use of Color (Level A)",
                        "recommendation": "Ensure information is not conveyed by color alone",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_keyboard_accessibility(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check WCAG 2.1.1 & 2.1.2 - Keyboard accessibility."""
        issues = []
        metadata = {}

        # Check for interactive elements that may not be keyboard accessible
        interactive_elements = soup.find_all([
            "a",
            "button",
            "input",
            "select",
            "textarea",
        ])
        non_focusable_interactive = []

        for element in interactive_elements:
            tabindex = element.get("tabindex")
            if tabindex == "-1":
                non_focusable_interactive.append({
                    "tag": element.name,
                    "text": element.get_text(strip=True)[:50],
                    "id": element.get("id", "no-id"),
                })

        # Check for custom interactive elements (divs, spans with click handlers)
        potential_interactive = soup.find_all(attrs={"onclick": True})
        potential_interactive.extend(
            soup.find_all(
                ["div", "span"], attrs={"role": ["button", "link", "menuitem"]}
            )
        )

        inaccessible_custom_controls = []
        for element in potential_interactive:
            if not element.get("tabindex") and element.get("tabindex") != "0":
                if element.name not in ["a", "button", "input", "select", "textarea"]:
                    inaccessible_custom_controls.append({
                        "tag": element.name,
                        "text": element.get_text(strip=True)[:50],
                        "role": element.get("role", "none"),
                    })

        metadata.update({
            "interactive_elements_count": len(interactive_elements),
            "non_focusable_interactive": len(non_focusable_interactive),
            "custom_interactive_elements": len(potential_interactive),
            "inaccessible_custom_controls": len(inaccessible_custom_controls),
        })

        if non_focusable_interactive:
            issues.append(
                self.create_issue(
                    issue_type="wcag_2_1_1_non_focusable_interactive",
                    severity=Severity.HIGH,
                    message=f"WCAG 2.1.1: {len(non_focusable_interactive)} interactive elements not keyboard focusable",
                    location=url,
                    evidence={
                        "non_focusable_elements": non_focusable_interactive[:5],
                        "wcag_guideline": "2.1.1 Keyboard (Level A)",
                    },
                )
            )

        if inaccessible_custom_controls:
            issues.append(
                self.create_issue(
                    issue_type="wcag_2_1_1_custom_controls_not_keyboard_accessible",
                    severity=Severity.HIGH,
                    message=f"WCAG 2.1.1: {len(inaccessible_custom_controls)} custom controls not keyboard accessible",
                    location=url,
                    evidence={
                        "inaccessible_controls": inaccessible_custom_controls[:5],
                        "wcag_guideline": "2.1.1 Keyboard (Level A)",
                        "recommendation": "Add tabindex='0' and keyboard event handlers",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_focus_management(self, soup: BeautifulSoup, url: str) -> dict:
        """Check WCAG 2.4.3 & 2.4.7 - Focus Order and Focus Visible."""
        issues = []
        metadata = {}

        # Check for skip links
        skip_links = soup.find_all("a", href=re.compile(r"^#"))
        skip_to_content = [
            link
            for link in skip_links
            if "skip" in link.get_text().lower() or "main" in link.get("href", "")
        ]

        if not skip_to_content:
            issues.append(
                self.create_issue(
                    issue_type="wcag_2_4_1_missing_skip_links",
                    severity=Severity.MEDIUM,
                    message="WCAG 2.4.1: No skip links found for bypassing repetitive content",
                    location=url,
                    evidence={
                        "wcag_guideline": "2.4.1 Bypass Blocks (Level A)",
                        "recommendation": "Add skip links to main content and navigation",
                    },
                )
            )

        # Check for proper heading hierarchy
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        heading_levels = [int(h.name[1]) for h in headings]

        hierarchy_issues = []
        for i, level in enumerate(heading_levels[1:], 1):
            prev_level = heading_levels[i - 1]
            if level > prev_level + 1:
                hierarchy_issues.append({
                    "position": i,
                    "jumped_from": f"h{prev_level}",
                    "jumped_to": f"h{level}",
                })

        if hierarchy_issues:
            issues.append(
                self.create_issue(
                    issue_type="wcag_2_4_6_incorrect_heading_hierarchy",
                    severity=Severity.MEDIUM,
                    message=f"WCAG 2.4.6: {len(hierarchy_issues)} heading hierarchy violations found",
                    location=url,
                    evidence={
                        "hierarchy_issues": hierarchy_issues,
                        "wcag_guideline": "2.4.6 Headings and Labels (Level AA)",
                        "recommendation": "Maintain logical heading hierarchy (don't skip levels)",
                    },
                )
            )

        # Check for focus traps in modals/dialogs
        modals = soup.find_all(attrs={"role": "dialog"})
        modals.extend(soup.find_all(attrs={"aria-modal": "true"}))

        focus_trap_issues = []
        for modal in modals:
            focusable_elements = modal.find_all([
                "a",
                "button",
                "input",
                "select",
                "textarea",
            ])
            focusable_elements.extend(modal.find_all(attrs={"tabindex": "0"}))

            if (
                len(focusable_elements) < 2
            ):  # Should have at least close button and one other element
                focus_trap_issues.append({
                    "modal_id": modal.get("id", "no-id"),
                    "focusable_count": len(focusable_elements),
                })

        metadata.update({
            "skip_links_count": len(skip_to_content),
            "heading_hierarchy_issues": len(hierarchy_issues),
            "modal_count": len(modals),
            "focus_trap_issues": len(focus_trap_issues),
        })

        return {"issues": issues, "metadata": metadata}

    async def _check_language_identification(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check WCAG 3.1.1 & 3.1.2 - Language identification."""
        issues = []
        metadata = {}

        # Check for lang attribute on html element
        html_element = soup.find("html")
        page_lang = html_element.get("lang") if html_element else None

        metadata["page_language"] = page_lang

        if not page_lang:
            issues.append(
                self.create_issue(
                    issue_type="wcag_3_1_1_missing_page_language",
                    severity=Severity.HIGH,
                    message="WCAG 3.1.1: Page language not specified in html lang attribute",
                    location=url,
                    evidence={
                        "wcag_guideline": "3.1.1 Language of Page (Level A)",
                        "recommendation": "Add lang attribute to html element (e.g., <html lang='en'>)",
                    },
                )
            )

        # Check for language changes within content
        elements_with_lang = soup.find_all(attrs={"lang": True})
        metadata["elements_with_lang_changes"] = len(elements_with_lang)

        # Simple heuristic for detecting potential language changes without lang attributes
        text_elements = soup.find_all(["p", "span", "div"], string=True)
        potential_lang_changes = []

        for element in text_elements:
            text = element.get_text(strip=True)
            # Very basic detection of non-English characters (this would need more sophisticated NLP)
            if text and any(ord(char) > 127 for char in text if char.isalpha()):
                if not element.get("lang") and not any(
                    parent.get("lang") for parent in element.parents
                ):
                    potential_lang_changes.append({
                        "text": text[:50],
                        "element": element.name,
                    })

        if (
            potential_lang_changes and len(potential_lang_changes) > 5
        ):  # Only flag if significant
            issues.append(
                self.create_issue(
                    issue_type="wcag_3_1_2_potential_unlabeled_language_changes",
                    severity=Severity.LOW,
                    message=f"WCAG 3.1.2: {len(potential_lang_changes)} elements with potential language changes",
                    location=url,
                    evidence={
                        "potential_changes": potential_lang_changes[:3],
                        "wcag_guideline": "3.1.2 Language of Parts (Level AA)",
                        "recommendation": "Add lang attributes for content in different languages",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_forms_and_labels(self, soup: BeautifulSoup, url: str) -> dict:
        """Check WCAG 3.3.2 & 4.1.2 - Forms and Labels."""
        issues = []
        metadata = {}

        # Check form inputs for proper labeling
        form_inputs = soup.find_all(["input", "select", "textarea"])
        unlabeled_inputs = []
        inputs_with_labels = []

        for input_elem in form_inputs:
            input_type = input_elem.get("type", "text")
            if input_type in ["hidden", "submit", "button"]:
                continue

            input_id = input_elem.get("id")
            aria_label = input_elem.get("aria-label")
            aria_labelledby = input_elem.get("aria-labelledby")

            # Check for associated label
            label_found = False
            if input_id:
                label = soup.find("label", attrs={"for": input_id})
                if label:
                    label_found = True
                    inputs_with_labels.append(input_id)

            if not label_found and not aria_label and not aria_labelledby:
                unlabeled_inputs.append({
                    "type": input_type,
                    "id": input_id or "no-id",
                    "name": input_elem.get("name", "no-name"),
                })

        metadata.update({
            "total_form_inputs": len(form_inputs),
            "unlabeled_inputs": len(unlabeled_inputs),
            "properly_labeled_inputs": len(inputs_with_labels),
        })

        if unlabeled_inputs:
            issues.append(
                self.create_issue(
                    issue_type="wcag_3_3_2_unlabeled_form_inputs",
                    severity=Severity.HIGH,
                    message=f"WCAG 3.3.2: {len(unlabeled_inputs)} form inputs without proper labels",
                    location=url,
                    evidence={
                        "unlabeled_inputs": unlabeled_inputs[:5],
                        "wcag_guideline": "3.3.2 Labels or Instructions (Level A)",
                        "recommendation": "Add <label> elements or aria-label attributes",
                    },
                )
            )

        # Check for required field indicators
        required_inputs = soup.find_all(
            ["input", "select", "textarea"], attrs={"required": True}
        )
        required_inputs.extend(
            soup.find_all(
                ["input", "select", "textarea"], attrs={"aria-required": "true"}
            )
        )

        required_without_indication = []
        for required in required_inputs:
            # Check if requirement is clearly indicated
            has_asterisk = "*" in str(required.parent) if required.parent else False
            has_aria_label = "required" in (required.get("aria-label") or "").lower()
            has_aria_describedby = required.get("aria-describedby")

            if not (has_asterisk or has_aria_label or has_aria_describedby):
                required_without_indication.append({
                    "type": required.get("type", "unknown"),
                    "id": required.get("id", "no-id"),
                })

        if required_without_indication:
            issues.append(
                self.create_issue(
                    issue_type="wcag_3_3_2_required_fields_not_indicated",
                    severity=Severity.MEDIUM,
                    message=f"WCAG 3.3.2: {len(required_without_indication)} required fields without clear indication",
                    location=url,
                    evidence={
                        "required_without_indication": required_without_indication,
                        "wcag_guideline": "3.3.2 Labels or Instructions (Level A)",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_semantic_structure(self, soup: BeautifulSoup, url: str) -> dict:
        """Check WCAG 4.1.1 & 4.1.2 - Semantic structure and valid markup."""
        issues = []
        metadata = {}

        # Check for semantic HTML5 elements
        semantic_elements = soup.find_all([
            "main",
            "nav",
            "header",
            "footer",
            "aside",
            "section",
            "article",
        ])
        metadata["semantic_elements_count"] = len(semantic_elements)

        # Check for main landmark
        main_elements = soup.find_all("main")
        main_with_role = soup.find_all(attrs={"role": "main"})

        if not main_elements and not main_with_role:
            issues.append(
                self.create_issue(
                    issue_type="wcag_4_1_2_missing_main_landmark",
                    severity=Severity.MEDIUM,
                    message="WCAG 4.1.2: No main landmark found for primary content",
                    location=url,
                    evidence={
                        "wcag_guideline": "4.1.2 Name, Role, Value (Level A)",
                        "recommendation": "Add <main> element or role='main' to primary content",
                    },
                )
            )
        elif len(main_elements) + len(main_with_role) > 1:
            issues.append(
                self.create_issue(
                    issue_type="wcag_4_1_2_multiple_main_landmarks",
                    severity=Severity.MEDIUM,
                    message="WCAG 4.1.2: Multiple main landmarks found - should be unique",
                    location=url,
                    evidence={
                        "main_count": len(main_elements) + len(main_with_role),
                        "wcag_guideline": "4.1.2 Name, Role, Value (Level A)",
                    },
                )
            )

        # Check for navigation landmarks
        nav_elements = soup.find_all("nav")
        nav_with_role = soup.find_all(attrs={"role": "navigation"})
        total_nav = len(nav_elements) + len(nav_with_role)

        metadata["navigation_landmarks"] = total_nav

        if total_nav == 0:
            issues.append(
                self.create_issue(
                    issue_type="wcag_4_1_2_missing_navigation_landmark",
                    severity=Severity.LOW,
                    message="WCAG 4.1.2: No navigation landmarks found",
                    location=url,
                    evidence={
                        "wcag_guideline": "4.1.2 Name, Role, Value (Level A)",
                        "recommendation": "Add <nav> elements or role='navigation' to navigation areas",
                    },
                )
            )

        # Check for duplicate IDs
        elements_with_id = soup.find_all(attrs={"id": True})
        id_counts = {}
        duplicate_ids = []

        for element in elements_with_id:
            element_id = element.get("id")
            id_counts[element_id] = id_counts.get(element_id, 0) + 1
            if id_counts[element_id] > 1:
                duplicate_ids.append(element_id)

        if duplicate_ids:
            issues.append(
                self.create_issue(
                    issue_type="wcag_4_1_1_duplicate_ids",
                    severity=Severity.HIGH,
                    message=f"WCAG 4.1.1: {len(set(duplicate_ids))} duplicate IDs found",
                    location=url,
                    evidence={
                        "duplicate_ids": list(set(duplicate_ids))[:5],
                        "wcag_guideline": "4.1.1 Parsing (Level A)",
                        "recommendation": "Ensure all IDs are unique",
                    },
                )
            )

        metadata["duplicate_ids_count"] = len(set(duplicate_ids))

        return {"issues": issues, "metadata": metadata}

    async def _check_aria_compliance(self, soup: BeautifulSoup, url: str) -> dict:
        """Check ARIA usage and compliance with EU regulations and WCAG 2.1 AA."""
        issues = []
        metadata = {}

        # Check for ARIA attributes
        aria_elements = soup.find_all(
            attrs=dict.fromkeys(
                ["aria-label", "aria-labelledby", "aria-describedby", "role"], True
            )
        )
        metadata["elements_with_aria"] = len(aria_elements)

        # Check for invalid ARIA roles
        valid_roles = {
            "alert",
            "alertdialog",
            "application",
            "article",
            "banner",
            "button",
            "cell",
            "checkbox",
            "columnheader",
            "combobox",
            "complementary",
            "contentinfo",
            "definition",
            "dialog",
            "directory",
            "document",
            "feed",
            "figure",
            "form",
            "grid",
            "gridcell",
            "group",
            "heading",
            "img",
            "link",
            "list",
            "listbox",
            "listitem",
            "log",
            "main",
            "marquee",
            "math",
            "menu",
            "menubar",
            "menuitem",
            "menuitemcheckbox",
            "menuitemradio",
            "navigation",
            "none",
            "note",
            "option",
            "presentation",
            "progressbar",
            "radio",
            "radiogroup",
            "region",
            "row",
            "rowgroup",
            "rowheader",
            "scrollbar",
            "search",
            "searchbox",
            "separator",
            "slider",
            "spinbutton",
            "status",
            "switch",
            "tab",
            "table",
            "tablist",
            "tabpanel",
            "term",
            "textbox",
            "timer",
            "toolbar",
            "tooltip",
            "tree",
            "treegrid",
            "treeitem",
        }

        invalid_roles = []
        role_elements = soup.find_all(attrs={"role": True})

        for element in role_elements:
            role = element.get("role").strip().lower()
            if role not in valid_roles:
                invalid_roles.append({
                    "element": element.name,
                    "invalid_role": role,
                    "id": element.get("id", "no-id"),
                })

        if invalid_roles:
            issues.append(
                self.create_issue(
                    issue_type="aria_invalid_roles",
                    severity=Severity.MEDIUM,
                    message=f"ARIA: {len(invalid_roles)} elements with invalid ARIA roles",
                    location=url,
                    evidence={
                        "invalid_roles": invalid_roles[:5],
                        "recommendation": "Use valid ARIA roles from the WAI-ARIA specification",
                    },
                )
            )

        # Check for aria-labelledby pointing to non-existent elements
        labelledby_issues = []
        labelledby_elements = soup.find_all(attrs={"aria-labelledby": True})

        for element in labelledby_elements:
            labelledby_ids = element.get("aria-labelledby").split()
            for ref_id in labelledby_ids:
                if not soup.find(attrs={"id": ref_id}):
                    labelledby_issues.append({
                        "element_id": element.get("id", "no-id"),
                        "missing_reference": ref_id,
                    })

        if labelledby_issues:
            issues.append(
                self.create_issue(
                    issue_type="aria_broken_labelledby_references",
                    severity=Severity.HIGH,
                    message=f"ARIA: {len(labelledby_issues)} broken aria-labelledby references",
                    location=url,
                    evidence={
                        "broken_references": labelledby_issues[:5],
                        "recommendation": "Ensure aria-labelledby references point to existing elements",
                    },
                )
            )

        # EU/EAA Standard ARIA Checks - WCAG 2.1 AA Compliance

        # 1. Form Accessibility (WCAG 3.3.2 - Labels or Instructions)
        form_aria_issues = await self._check_form_aria_accessibility(soup, url)
        issues.extend(form_aria_issues["issues"])
        metadata.update(form_aria_issues["metadata"])

        # 2. Live Regions (WCAG 4.1.3 - Status Messages)
        live_region_issues = await self._check_live_regions(soup, url)
        issues.extend(live_region_issues["issues"])
        metadata.update(live_region_issues["metadata"])

        # 3. Interactive Elements (WCAG 2.1.1 - Keyboard)
        interactive_aria_issues = await self._check_interactive_aria_elements(soup, url)
        issues.extend(interactive_aria_issues["issues"])
        metadata.update(interactive_aria_issues["metadata"])

        # 4. Navigation and Landmarks (WCAG 2.4.1 - Bypass Blocks)
        navigation_aria_issues = await self._check_navigation_aria(soup, url)
        issues.extend(navigation_aria_issues["issues"])
        metadata.update(navigation_aria_issues["metadata"])

        # 5. Error Handling (WCAG 3.3.1 - Error Identification)
        error_aria_issues = await self._check_error_aria_handling(soup, url)
        issues.extend(error_aria_issues["issues"])
        metadata.update(error_aria_issues["metadata"])

        metadata["invalid_roles_count"] = len(invalid_roles)
        metadata["broken_labelledby_count"] = len(labelledby_issues)

        return {"issues": issues, "metadata": metadata}

    async def _check_form_aria_accessibility(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check form ARIA compliance - EU/EAA standard for form accessibility."""
        issues = []
        metadata = {}

        # Check form inputs for proper ARIA attributes
        form_inputs = soup.find_all(["input", "textarea", "select"])
        inputs_without_labels = []
        required_inputs_without_aria = []

        for input_elem in form_inputs:
            input_id = input_elem.get("id")
            input_name = input_elem.get("name")
            input_type = input_elem.get("type", "text")
            is_required = input_elem.get(
                "required"
            ) is not None or "required" in input_elem.get("class", [])

            # Check for associated label
            has_label = False
            if input_id:
                label = soup.find("label", attrs={"for": input_id})
                if label:
                    has_label = True
                else:
                    # Check for aria-labelledby
                    aria_labelledby = input_elem.get("aria-labelledby")
                    if aria_labelledby:
                        has_label = True

            # Check for aria-label
            aria_label = input_elem.get("aria-label")
            if aria_label:
                has_label = True

            if not has_label:
                inputs_without_labels.append({
                    "type": input_type,
                    "id": input_id,
                    "name": input_name,
                })

            # Check for required ARIA attributes on required fields
            if is_required:
                aria_required = input_elem.get("aria-required")
                if aria_required != "true":
                    required_inputs_without_aria.append({
                        "type": input_type,
                        "id": input_id,
                        "name": input_name,
                    })

        metadata.update({
            "total_form_inputs": len(form_inputs),
            "inputs_without_labels": len(inputs_without_labels),
            "required_inputs_without_aria": len(required_inputs_without_aria),
        })

        if inputs_without_labels:
            issues.append(
                self.create_issue(
                    issue_type="aria_form_missing_labels",
                    severity=Severity.HIGH,
                    message=f"ARIA Form: {len(inputs_without_labels)} form inputs missing proper labels",
                    location=url,
                    evidence={
                        "missing_labels_count": len(inputs_without_labels),
                        "sample_inputs": inputs_without_labels[:5],
                        "wcag_guideline": "3.3.2 Labels or Instructions (Level A)",
                        "eaa_requirement": "Form accessibility compliance",
                        "recommendation": "Use <label>, aria-label, or aria-labelledby for all form inputs",
                    },
                )
            )

        if required_inputs_without_aria:
            issues.append(
                self.create_issue(
                    issue_type="aria_required_fields_missing_aria",
                    severity=Severity.MEDIUM,
                    message=f"ARIA Form: {len(required_inputs_without_aria)} required fields missing aria-required",
                    location=url,
                    evidence={
                        "required_fields_count": len(required_inputs_without_aria),
                        "sample_fields": required_inputs_without_aria[:5],
                        "wcag_guideline": "3.3.2 Labels or Instructions (Level A)",
                        "recommendation": "Add aria-required='true' to required form fields",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_live_regions(self, soup: BeautifulSoup, url: str) -> dict:
        """Check live regions for dynamic content - EU/EAA standard for status messages."""
        issues = []
        metadata = {}

        # Check for live regions
        live_regions = soup.find_all(attrs={"aria-live": True})
        live_region_types = {}

        for region in live_regions:
            live_type = region.get("aria-live", "off")
            live_region_types[live_type] = live_region_types.get(live_type, 0) + 1

        metadata["live_regions_count"] = len(live_regions)
        metadata["live_region_types"] = live_region_types

        # Check for appropriate live region usage
        inappropriate_live_regions = []
        for region in live_regions:
            live_type = region.get("aria-live")
            # Check if live region is used appropriately
            if live_type == "assertive" and not region.get_text(strip=True):
                inappropriate_live_regions.append({
                    "type": live_type,
                    "id": region.get("id", "no-id"),
                })

        if inappropriate_live_regions:
            issues.append(
                self.create_issue(
                    issue_type="aria_inappropriate_live_regions",
                    severity=Severity.MEDIUM,
                    message=f"ARIA Live: {len(inappropriate_live_regions)} inappropriate live region usage",
                    location=url,
                    evidence={
                        "inappropriate_regions": inappropriate_live_regions[:5],
                        "wcag_guideline": "4.1.3 Status Messages (Level AA)",
                        "eaa_requirement": "Dynamic content accessibility",
                        "recommendation": "Use aria-live appropriately for status messages and updates",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_interactive_aria_elements(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check interactive ARIA elements for proper keyboard accessibility - EU/EAA standard."""
        issues = []
        metadata = {}

        # Check interactive elements with ARIA roles
        interactive_roles = {
            "button",
            "link",
            "menuitem",
            "tab",
            "checkbox",
            "radio",
            "combobox",
            "listbox",
            "slider",
            "spinbutton",
            "switch",
        }

        interactive_elements = []
        for role in interactive_roles:
            elements = soup.find_all(attrs={"role": role})
            interactive_elements.extend(elements)

        metadata["interactive_aria_elements"] = len(interactive_elements)

        # Check for proper keyboard accessibility
        non_keyboard_accessible = []
        for element in interactive_elements:
            # Check if element has tabindex or is naturally focusable
            tabindex = element.get("tabindex")
            tag_name = element.name.lower()

            # Elements that should be naturally focusable
            naturally_focusable = tag_name in [
                "a",
                "button",
                "input",
                "select",
                "textarea",
            ]

            if not naturally_focusable and tabindex is None:
                non_keyboard_accessible.append({
                    "role": element.get("role"),
                    "tag": tag_name,
                    "id": element.get("id", "no-id"),
                })

        if non_keyboard_accessible:
            issues.append(
                self.create_issue(
                    issue_type="aria_non_keyboard_accessible",
                    severity=Severity.HIGH,
                    message=f"ARIA Interactive: {len(non_keyboard_accessible)} interactive elements not keyboard accessible",
                    location=url,
                    evidence={
                        "non_accessible_elements": non_keyboard_accessible[:5],
                        "wcag_guideline": "2.1.1 Keyboard (Level A)",
                        "eaa_requirement": "Keyboard accessibility for all interactive elements",
                        "recommendation": "Add tabindex='0' to interactive elements or use naturally focusable elements",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_navigation_aria(self, soup: BeautifulSoup, url: str) -> dict:
        """Check navigation ARIA for proper landmark structure - EU/EAA standard."""
        issues = []
        metadata = {}

        # Check for skip links (WCAG 2.4.1 - Bypass Blocks)
        skip_links = soup.find_all(
            "a", href=re.compile(r"#(main|content|navigation)", re.I)
        )
        skip_links.extend(soup.find_all("a", string=re.compile(r"skip|jump to", re.I)))

        metadata["skip_links_count"] = len(skip_links)

        if not skip_links:
            issues.append(
                self.create_issue(
                    issue_type="aria_missing_skip_links",
                    severity=Severity.MEDIUM,
                    message="ARIA Navigation: No skip links found for bypassing navigation",
                    location=url,
                    evidence={
                        "wcag_guideline": "2.4.1 Bypass Blocks (Level A)",
                        "eaa_requirement": "Navigation accessibility",
                        "recommendation": "Add skip links to main content and navigation",
                    },
                )
            )

        # Check for proper heading structure
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        heading_structure = []
        heading_issues = []

        for heading in headings:
            level = int(heading.name[1])
            heading_structure.append({
                "level": level,
                "text": heading.get_text(strip=True)[:50],
                "id": heading.get("id", "no-id"),
            })

        # Check for proper heading hierarchy
        if heading_structure:
            current_level = 0
            for heading in heading_structure:
                if heading["level"] > current_level + 1:
                    heading_issues.append({
                        "level": heading["level"],
                        "text": heading["text"],
                        "issue": "Skipped heading level",
                    })
                current_level = heading["level"]

        if heading_issues:
            issues.append(
                self.create_issue(
                    issue_type="aria_improper_heading_structure",
                    severity=Severity.MEDIUM,
                    message=f"ARIA Navigation: {len(heading_issues)} heading structure issues",
                    location=url,
                    evidence={
                        "heading_issues": heading_issues[:5],
                        "wcag_guideline": "1.3.1 Info and Relationships (Level A)",
                        "eaa_requirement": "Content structure accessibility",
                        "recommendation": "Maintain proper heading hierarchy (h1 > h2 > h3...)",
                    },
                )
            )

        metadata["headings_count"] = len(headings)
        metadata["heading_structure_issues"] = len(heading_issues)

        return {"issues": issues, "metadata": metadata}

    async def _check_error_aria_handling(self, soup: BeautifulSoup, url: str) -> dict:
        """Check error handling with ARIA - EU/EAA standard for error identification."""
        issues = []
        metadata = {}

        # Check for error messages with proper ARIA
        error_elements = soup.find_all(
            string=re.compile(r"error|invalid|required|missing", re.I)
        )
        error_elements.extend(
            soup.find_all(attrs={"class": re.compile(r"error|invalid", re.I)})
        )

        error_elements_with_aria = []
        error_elements_without_aria = []

        for error_elem in error_elements:
            parent = error_elem.parent if hasattr(error_elem, "parent") else error_elem

            # Check for ARIA error attributes
            has_aria_invalid = parent.get("aria-invalid") == "true"
            has_aria_describedby = parent.get("aria-describedby")
            has_aria_live = parent.get("aria-live") in ["polite", "assertive"]

            if has_aria_invalid or has_aria_describedby or has_aria_live:
                error_elements_with_aria.append({
                    "text": str(error_elem)[:50],
                    "aria_attributes": {
                        "aria-invalid": has_aria_invalid,
                        "aria-describedby": bool(has_aria_describedby),
                        "aria-live": bool(has_aria_live),
                    },
                })
            else:
                error_elements_without_aria.append({
                    "text": str(error_elem)[:50],
                })

        metadata.update({
            "error_elements_count": len(error_elements),
            "error_elements_with_aria": len(error_elements_with_aria),
            "error_elements_without_aria": len(error_elements_without_aria),
        })

        if error_elements_without_aria:
            issues.append(
                self.create_issue(
                    issue_type="aria_error_handling_incomplete",
                    severity=Severity.MEDIUM,
                    message=f"ARIA Error: {len(error_elements_without_aria)} error messages without proper ARIA",
                    location=url,
                    evidence={
                        "error_messages_without_aria": error_elements_without_aria[:5],
                        "wcag_guideline": "3.3.1 Error Identification (Level A)",
                        "eaa_requirement": "Error message accessibility",
                        "recommendation": "Use aria-invalid, aria-describedby, or aria-live for error messages",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _check_eaa_specific_requirements(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check EU Accessibility Act specific requirements."""
        issues = []
        metadata = {}

        # Check for EU-specific accessibility features
        eu_accessibility_features = []

        # Check for accessibility statement link
        accessibility_links = soup.find_all(
            "a",
            href=re.compile(r"accessibility|barrierefreiheit|toegankelijkheid", re.I),
        )
        if not accessibility_links:
            issues.append(
                self.create_issue(
                    issue_type="eaa_missing_accessibility_statement",
                    severity=Severity.MEDIUM,
                    message="EU Accessibility Act: Missing accessibility statement link",
                    location=url,
                    evidence={
                        "requirement": "EU EAA Article 7 - Accessibility Statement",
                        "recommendation": "Add a link to accessibility statement in footer or main navigation",
                    },
                )
            )
        else:
            eu_accessibility_features.append("accessibility_statement")

        # Check for contact information for accessibility issues
        contact_patterns = [
            r"accessibility.*contact|contact.*accessibility",
            r"barrierefreiheit.*kontakt|kontakt.*barrierefreiheit",
            r"toegankelijkheid.*contact|contact.*toegankelijkheid",
        ]
        contact_found = False
        for pattern in contact_patterns:
            if soup.find(text=re.compile(pattern, re.I)):
                contact_found = True
                break

        if not contact_found:
            issues.append(
                self.create_issue(
                    issue_type="eaa_missing_accessibility_contact",
                    severity=Severity.MEDIUM,
                    message="EU Accessibility Act: Missing contact information for accessibility issues",
                    location=url,
                    evidence={
                        "requirement": "EU EAA Article 7 - Feedback Mechanism",
                        "recommendation": "Provide clear contact information for accessibility feedback",
                    },
                )
            )
        else:
            eu_accessibility_features.append("accessibility_contact")

        # Check for compliance level declaration
        compliance_patterns = [
            r"wcag.*2\.1.*aa|wcag.*2\.1.*aaa",
            r"conform.*wcag.*2\.1",
            r"compliant.*wcag.*2\.1",
        ]
        compliance_declared = False
        for pattern in compliance_patterns:
            if soup.find(text=re.compile(pattern, re.I)):
                compliance_declared = True
                break

        if not compliance_declared:
            issues.append(
                self.create_issue(
                    issue_type="eaa_missing_compliance_declaration",
                    severity=Severity.LOW,
                    message="EU Accessibility Act: Missing WCAG compliance level declaration",
                    location=url,
                    evidence={
                        "requirement": "EU EAA Article 7 - Compliance Declaration",
                        "recommendation": "Declare WCAG 2.1 AA compliance level in accessibility statement",
                    },
                )
            )
        else:
            eu_accessibility_features.append("compliance_declaration")

        metadata.update({
            "eu_accessibility_features": eu_accessibility_features,
            "eaa_compliance_score": len(eu_accessibility_features) / 3 * 100,
        })

        return {"issues": issues, "metadata": metadata}

    async def _check_mobile_responsive_accessibility(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check mobile and responsive design accessibility features."""
        issues = []
        metadata = {}

        # Check viewport meta tag
        viewport_meta = soup.find("meta", attrs={"name": "viewport"})
        if not viewport_meta:
            issues.append(
                self.create_issue(
                    issue_type="mobile_missing_viewport_meta",
                    severity=Severity.HIGH,
                    message="Mobile accessibility: Missing viewport meta tag",
                    location=url,
                    evidence={
                        "requirement": "Mobile-first responsive design",
                        "recommendation": "Add <meta name='viewport' content='width=device-width, initial-scale=1'>",
                    },
                )
            )
        else:
            content = viewport_meta.get("content", "")
            if "width=device-width" not in content or "initial-scale=1" not in content:
                issues.append(
                    self.create_issue(
                        issue_type="mobile_invalid_viewport_content",
                        severity=Severity.MEDIUM,
                        message="Mobile accessibility: Invalid viewport meta content",
                        location=url,
                        evidence={
                            "current_content": content,
                            "recommended": "width=device-width, initial-scale=1",
                        },
                    )
                )

        # Check for touch-friendly elements
        touch_elements = soup.find_all(["button", "a", "input", "select"])
        small_touch_targets = []

        for element in touch_elements:
            # Check for explicit size attributes or CSS classes that might indicate small size
            style = element.get("style", "")
            class_attr = element.get("class", [])

            # Look for patterns that might indicate small elements
            if any(
                size in style.lower()
                for size in [
                    "width: 20px",
                    "height: 20px",
                    "width: 30px",
                    "height: 30px",
                ]
            ):
                small_touch_targets.append(str(element)[:100])
            elif any(
                cls in str(class_attr).lower() for cls in ["small", "tiny", "mini"]
            ):
                small_touch_targets.append(str(element)[:100])

        if small_touch_targets:
            issues.append(
                self.create_issue(
                    issue_type="mobile_small_touch_targets",
                    severity=Severity.MEDIUM,
                    message=f"Mobile accessibility: {len(small_touch_targets)} potentially small touch targets",
                    location=url,
                    evidence={
                        "small_targets_count": len(small_touch_targets),
                        "recommendation": "Ensure touch targets are at least 44x44px for mobile accessibility",
                        "sample_elements": small_touch_targets[:3],
                    },
                )
            )

        # Check for mobile-specific accessibility issues
        mobile_issues = []

        # Check for horizontal scrolling on mobile
        if soup.find("div", style=re.compile(r"overflow-x.*scroll|overflow.*auto")):
            mobile_issues.append("potential_horizontal_scroll")

        # Check for fixed positioning that might hide content on mobile
        fixed_elements = soup.find_all(attrs={"style": re.compile(r"position.*fixed")})
        if fixed_elements:
            mobile_issues.append("fixed_positioning_may_hide_content")

        # Check for font sizes that might be too small on mobile
        small_fonts = soup.find_all(attrs={"style": re.compile(r"font-size.*[0-9]px")})
        for font in small_fonts:
            style = font.get("style", "")
            if re.search(r"font-size.*1[0-2]px", style):
                mobile_issues.append("potentially_small_fonts")
                break

        if mobile_issues:
            issues.append(
                self.create_issue(
                    issue_type="mobile_accessibility_concerns",
                    severity=Severity.MEDIUM,
                    message=f"Mobile accessibility: {len(mobile_issues)} potential issues detected",
                    location=url,
                    evidence={
                        "mobile_issues": mobile_issues,
                        "recommendation": "Test on actual mobile devices and ensure content is accessible",
                    },
                )
            )

        metadata.update({
            "viewport_meta_present": viewport_meta is not None,
            "small_touch_targets_count": len(small_touch_targets),
            "mobile_issues_detected": len(mobile_issues),
        })

        return {"issues": issues, "metadata": metadata}

    async def _check_responsive_breakpoints(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check for responsive design breakpoints and CSS media queries."""
        issues = []
        metadata = {}

        # Check for CSS media queries in style tags
        style_tags = soup.find_all("style")
        media_queries = []

        for style in style_tags:
            content = style.get_text()
            # Look for common breakpoint patterns
            breakpoints = re.findall(
                r"@media.*\(.*max-width.*\)|@media.*\(.*min-width.*\)", content
            )
            media_queries.extend(breakpoints)

        # Check for external CSS files that might contain responsive styles
        css_links = soup.find_all("link", rel="stylesheet")
        external_css_count = len(css_links)

        # Common responsive breakpoints to check for
        common_breakpoints = {
            "mobile": ["320px", "375px", "425px", "480px"],
            "tablet": ["768px", "768px", "1024px"],
            "desktop": ["1024px", "1200px", "1440px"],
        }

        found_breakpoints = []
        for device, breakpoints in common_breakpoints.items():
            for bp in breakpoints:
                if any(bp in mq for mq in media_queries):
                    found_breakpoints.append(f"{device}: {bp}")

        if not media_queries and external_css_count == 0:
            issues.append(
                self.create_issue(
                    issue_type="responsive_no_media_queries",
                    severity=Severity.HIGH,
                    message="Responsive design: No media queries or external CSS detected",
                    location=url,
                    evidence={
                        "recommendation": "Implement responsive design with CSS media queries",
                        "common_breakpoints": common_breakpoints,
                    },
                )
            )
        elif not found_breakpoints:
            issues.append(
                self.create_issue(
                    issue_type="responsive_no_standard_breakpoints",
                    severity=Severity.MEDIUM,
                    message="Responsive design: No standard breakpoints detected",
                    location=url,
                    evidence={
                        "found_media_queries": len(media_queries),
                        "external_css_files": external_css_count,
                        "recommendation": "Use standard breakpoints for better device compatibility",
                    },
                )
            )

        # Check for flexbox or grid usage
        flexbox_used = any("display: flex" in str(style) for style in style_tags)
        grid_used = any("display: grid" in str(style) for style in style_tags)

        if not flexbox_used and not grid_used:
            issues.append(
                self.create_issue(
                    issue_type="responsive_no_modern_layout",
                    severity=Severity.LOW,
                    message="Responsive design: No flexbox or grid layout detected",
                    location=url,
                    evidence={
                        "recommendation": "Consider using flexbox or CSS grid for better responsive layouts",
                    },
                )
            )

        metadata.update({
            "media_queries_found": len(media_queries),
            "external_css_files": external_css_count,
            "standard_breakpoints_found": found_breakpoints,
            "flexbox_used": flexbox_used,
            "grid_used": grid_used,
        })

        return {"issues": issues, "metadata": metadata}

    async def _check_mobile_performance_accessibility(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check mobile performance aspects that affect accessibility."""
        issues = []
        metadata = {}

        # Check for large images without optimization
        images = soup.find_all("img")
        large_images = []

        for img in images:
            src = img.get("src", "")
            # Check for common large image patterns
            if any(pattern in src.lower() for pattern in [".jpg", ".jpeg", ".png"]):
                # Look for size hints in attributes
                width = img.get("width")
                height = img.get("height")
                if width and height:
                    try:
                        w, h = int(width), int(height)
                        if w > 1200 or h > 1200:
                            large_images.append({"src": src, "size": f"{w}x{h}"})
                    except ValueError:
                        pass

        if large_images:
            issues.append(
                self.create_issue(
                    issue_type="mobile_large_images",
                    severity=Severity.MEDIUM,
                    message=f"Mobile performance: {len(large_images)} potentially large images detected",
                    location=url,
                    evidence={
                        "large_images_count": len(large_images),
                        "sample_images": large_images[:3],
                        "recommendation": "Optimize images for mobile devices and use responsive images",
                    },
                )
            )

        # Check for external resources that might slow down mobile
        external_resources = []

        # External scripts
        scripts = soup.find_all("script", src=True)
        for script in scripts:
            src = script.get("src")
            if src and not src.startswith(("/", "./", "../")):
                external_resources.append(f"script: {src}")

        # External stylesheets
        stylesheets = soup.find_all("link", rel="stylesheet")
        for stylesheet in stylesheets:
            href = stylesheet.get("href")
            if href and not href.startswith(("/", "./", "../")):
                external_resources.append(f"stylesheet: {href}")

        if len(external_resources) > 5:
            issues.append(
                self.create_issue(
                    issue_type="mobile_too_many_external_resources",
                    severity=Severity.MEDIUM,
                    message=f"Mobile performance: {len(external_resources)} external resources may slow loading",
                    location=url,
                    evidence={
                        "external_resources_count": len(external_resources),
                        "sample_resources": external_resources[:5],
                        "recommendation": "Minimize external resources and use resource hints for critical resources",
                    },
                )
            )

        # Check for missing resource hints
        resource_hints = soup.find_all(
            "link", rel=["preload", "prefetch", "dns-prefetch"]
        )
        if not resource_hints:
            issues.append(
                self.create_issue(
                    issue_type="mobile_missing_resource_hints",
                    severity=Severity.LOW,
                    message="Mobile performance: No resource hints for performance optimization",
                    location=url,
                    evidence={
                        "recommendation": "Use preload, prefetch, or dns-prefetch for critical resources",
                    },
                )
            )

        metadata.update({
            "total_images": len(images),
            "large_images_count": len(large_images),
            "external_resources_count": len(external_resources),
            "resource_hints_count": len(resource_hints),
        })

        return {"issues": issues, "metadata": metadata}
