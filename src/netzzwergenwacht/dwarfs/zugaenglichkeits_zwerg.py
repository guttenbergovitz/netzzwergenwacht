"""Zugaenglichkeits-Zwerg for EU Accessibility Act (EAA) compliance analysis."""

import re
from typing import Any

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
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.content, "html.parser")

                issues = []
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

                # Perform accessibility analysis
                # WCAG 2.1 AA Compliance Checks

                # 1. Perceivable
                text_alternatives = await self._check_text_alternatives(soup, url)
                issues.extend(text_alternatives["issues"])
                metadata.update(text_alternatives["metadata"])

                color_contrast = await self._check_color_contrast(soup, url)
                issues.extend(color_contrast["issues"])
                metadata.update(color_contrast["metadata"])

                # 2. Operable
                keyboard_access = await self._check_keyboard_accessibility(soup, url)
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
                eaa_compliance = await self._check_eaa_specific_requirements(soup, url)
                issues.extend(eaa_compliance["issues"])
                metadata.update(eaa_compliance["metadata"])

                # Mobile and responsive accessibility testing
                mobile_responsive = await self._check_mobile_responsive_accessibility(
                    soup, url
                )
                issues.extend(mobile_responsive["issues"])
                metadata.update(mobile_responsive["metadata"])

                responsive_breakpoints = await self._check_responsive_breakpoints(
                    soup, url
                )
                issues.extend(responsive_breakpoints["issues"])
                metadata.update(responsive_breakpoints["metadata"])

                mobile_performance = await self._check_mobile_performance_accessibility(
                    soup, url
                )
                issues.extend(mobile_performance["issues"])
                metadata.update(mobile_performance["metadata"])

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
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.content, "html.parser")

                detailed_issues = []
                accessibility_metrics = AccessibilityMetrics()
                raw_data: dict[str, Any] = {}

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
                accessibility_metrics.total_images = text_alternatives["metrics"].get(
                    "total_images", 0
                )
                raw_data["text_alternatives"] = text_alternatives["raw"]

                color_contrast = await self._check_color_contrast_detailed(soup, url)
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
                accessibility_metrics.focus_issues = focus_management["metrics"].get(
                    "focus_issues", 0
                )
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

                forms_labels = await self._check_forms_and_labels_detailed(soup, url)
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

                aria_compliance = await self._check_aria_compliance_detailed(soup, url)
                detailed_issues.extend(aria_compliance["issues"])
                accessibility_metrics.aria_issues = aria_compliance["metrics"].get(
                    "aria_issues", 0
                )
                raw_data["aria_compliance"] = aria_compliance["raw"]

                # EAA-specific requirements
                eaa_compliance = await self._check_eaa_specific_requirements_detailed(
                    soup, url
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
                accessibility_metrics.mobile_issues = mobile_responsive["metrics"].get(
                    "mobile_issues", 0
                )
                raw_data["mobile_responsive"] = mobile_responsive["raw"]

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

    async def _check_text_alternatives(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 1.1.1 - Text Alternatives for non-text content."""
        issues = []
        metadata: dict[str, Any] = {}

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
            has_captions = (
                has_track and "captions" in str(has_track.get("kind"))
                if has_track
                else False
            )
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

    async def _check_text_alternatives_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 1.1.1 - Text Alternatives for non-text content with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

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
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_1_1_1_missing_alt_text",
                            severity=Severity.HIGH,
                            message=f"Image missing alt text: {src}",
                            location=url,
                            category="perceivable",
                            subcategory="text_alternatives",
                            description="Non-text content (images) must have text alternatives.",
                            impact="Screen reader users will not know the content/function of the image.",
                            technical_details={
                                "image_src": src,
                                "alt_attribute": "missing",
                            },
                            recommendations=[
                                "Provide a concise and accurate alt text for the image."
                            ],
                            fix_suggestions=[
                                f"Add alt='description of image' to <img src='{src}'>"
                            ],
                            priority_score=0.8,
                            code_location=CodeLocation(
                                element_selector=f"img[src='{src}']",
                                element_tag="img",
                                attribute_name="alt",
                                attribute_value="missing",
                                full_element=str(img),
                            ),
                        )
                    )
                elif alt == "":
                    decorative_images.append(src)
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_1_1_1_decorative_image_alt_empty",
                            severity=Severity.LOW,
                            message=f"Decorative image has empty alt text: {src}",
                            location=url,
                            category="perceivable",
                            subcategory="text_alternatives",
                            description="Decorative images should have empty alt text (alt='') to be ignored by screen readers.",
                            impact="Generally good, but ensure it is truly decorative.",
                            technical_details={
                                "image_src": src,
                                "alt_attribute": "empty",
                            },
                            recommendations=[
                                "Verify the image is purely decorative; otherwise, provide descriptive alt text."
                            ],
                            fix_suggestions=[
                                f"Ensure <img src='{src}' alt=''> is decorative or add alt text."
                            ],
                            priority_score=0.2,
                            code_location=CodeLocation(
                                element_selector=f"img[src='{src}']",
                                element_tag="img",
                                attribute_name="alt",
                                attribute_value="",
                                full_element=str(img),
                            ),
                        )
                    )
                elif len(alt) > 150:
                    complex_images.append({"src": src, "alt_length": len(alt)})
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_1_1_1_complex_image_long_alt",
                            severity=Severity.MEDIUM,
                            message=f"Image alt text is very long ({len(alt)} chars): {src}",
                            location=url,
                            category="perceivable",
                            subcategory="text_alternatives",
                            description="Very long alt text can be cumbersome for screen reader users. Consider providing a short alt text and a longer description elsewhere.",
                            impact="May hinder comprehension for screen reader users.",
                            technical_details={
                                "image_src": src,
                                "alt_length": len(alt),
                                "alt_text_sample": alt[:50],
                            },
                            recommendations=[
                                "Provide a concise alt text and a more detailed description using aria-describedby or a separate text block."
                            ],
                            fix_suggestions=[
                                f"Shorten alt text for <img src='{src}'> or use aria-describedby."
                            ],
                            priority_score=0.5,
                            code_location=CodeLocation(
                                element_selector=f"img[src='{src}']",
                                element_tag="img",
                                attribute_name="alt",
                                attribute_value=alt,
                                full_element=str(img),
                            ),
                        )
                    )

        metrics.update({
            "total_images": len(images),
            "images_without_alt": len(images_without_alt),
            "decorative_images": len(decorative_images),
            "complex_images": len(complex_images),
        })
        raw_data["images"] = {
            "images_without_alt_list": images_without_alt,
            "decorative_images_list": decorative_images,
            "complex_images_list": complex_images,
        }

        # Check audio/video elements
        media_elements = soup.find_all(["audio", "video"])
        media_missing_alternatives = []

        for media in media_elements:
            # Check for captions, transcripts, or audio descriptions
            has_track = media.find("track")
            has_captions = (
                has_track and "captions" in str(has_track.get("kind"))
                if has_track
                else False
            )
            has_transcript = "transcript" in media.get("aria-describedby", "").lower()

            if not (has_captions or has_transcript):
                media_missing_alternatives.append({
                    "tag": media.name,
                    "src": media.get("src", "embedded"),
                })
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="wcag_1_2_media_missing_alternatives",
                        severity=Severity.HIGH,
                        message=f"Media element missing captions/transcripts: {media.name} {media.get('src', '')}",
                        location=url,
                        category="perceivable",
                        subcategory="time_based_media",
                        description="Time-based media (audio/video) must have alternatives like captions or transcripts.",
                        impact="Users with hearing impairments will not be able to access the content.",
                        technical_details={
                            "media_tag": media.name,
                            "media_src": media.get("src", ""),
                        },
                        recommendations=[
                            "Provide captions for all audio content and transcripts for all video content."
                        ],
                        fix_suggestions=[
                            f"Add <track kind='captions'> for {media.name} or link to a transcript."
                        ],
                        priority_score=0.9,
                        code_location=CodeLocation(
                            element_selector=media.name,
                            element_tag=media.name,
                            attribute_name="src",
                            attribute_value=media.get("src", ""),
                            full_element=str(media),
                        ),
                    )
                )

        metrics["media_missing_alternatives"] = len(media_missing_alternatives)
        raw_data["media"] = {
            "media_missing_alternatives_list": media_missing_alternatives
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_color_contrast_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 1.4.3 & 1.4.6 - Color Contrast requirements with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

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
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_1_4_3_potential_contrast_issues",
                            severity=Severity.MEDIUM,
                            message=f"Potential low contrast element: {element.name} with style {style[:50]}",
                            location=url,
                            category="perceivable",
                            subcategory="contrast",
                            description="Text and images of text should have a contrast ratio of at least 4.5:1.",
                            impact="Users with low vision may struggle to read content.",
                            technical_details={
                                "element_name": element.name,
                                "style_snippet": style[:100],
                            },
                            recommendations=[
                                "Increase the contrast ratio between text/image and background."
                            ],
                            fix_suggestions=[
                                "Adjust CSS color and background-color properties."
                            ],
                            priority_score=0.6,
                            code_location=CodeLocation(
                                element_selector=element.name,
                                element_tag=element.name,
                                attribute_name="style",
                                attribute_value=style,
                                full_element=str(element),
                            ),
                        )
                    )

        metrics.update({
            "elements_with_inline_styles": len(inline_styles),
            "potential_contrast_issues": potential_issues,
            "style_elements_count": len(style_elements),
            "low_contrast_elements": len(contrast_issues),
        })
        raw_data["contrast_analysis"] = {
            "inline_styles_count": len(inline_styles),
            "contrast_issues_list": contrast_issues,
        }

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
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_1_4_1_color_only_information",
                            severity=Severity.MEDIUM,
                            message=f"Information conveyed by color alone: {text[:50]}",
                            location=url,
                            category="perceivable",
                            subcategory="use_of_color",
                            description="Color should not be the only visual means of conveying information.",
                            impact="Users with color blindness or low vision may miss information.",
                            technical_details={
                                "element_name": element.name,
                                "text_content": text[:50],
                            },
                            recommendations=[
                                "Provide additional visual cues (e.g., text labels, icons, patterns) to convey information."
                            ],
                            fix_suggestions=[
                                "Add text labels or icons next to color-coded information."
                            ],
                            priority_score=0.5,
                            code_location=CodeLocation(
                                element_selector=element.name,
                                element_tag=element.name,
                                full_element=str(element),
                            ),
                        )
                    )

        raw_data["color_only_information"] = {
            "color_only_indicators_list": color_only_indicators
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_keyboard_accessibility_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 2.1.1 & 2.1.2 - Keyboard accessibility with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

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
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="wcag_2_1_1_non_focusable_interactive",
                        severity=Severity.HIGH,
                        message=f"Interactive element not keyboard focusable: {element.name}",
                        location=url,
                        category="operable",
                        subcategory="keyboard_accessibility",
                        description="All interactive elements must be operable via keyboard.",
                        impact="Keyboard-only users will not be able to interact with this element.",
                        technical_details={
                            "element_name": element.name,
                            "tabindex": tabindex,
                        },
                        recommendations=[
                            "Ensure all interactive elements are keyboard accessible."
                        ],
                        fix_suggestions=[
                            "Remove tabindex='-1' or ensure element is naturally focusable."
                        ],
                        priority_score=0.8,
                        code_location=CodeLocation(
                            element_selector=element.name,
                            element_tag=element.name,
                            attribute_name="tabindex",
                            attribute_value=tabindex,
                            full_element=str(element),
                        ),
                    )
                )

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
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_2_1_1_custom_controls_not_keyboard_accessible",
                            severity=Severity.HIGH,
                            message=f"Custom control not keyboard accessible: {element.name}",
                            location=url,
                            category="operable",
                            subcategory="keyboard_accessibility",
                            description="Custom interactive elements must be keyboard operable.",
                            impact="Keyboard-only users will not be able to interact with this custom control.",
                            technical_details={
                                "element_name": element.name,
                                "role": element.get("role"),
                            },
                            recommendations=[
                                "Add tabindex='0' and appropriate keyboard event handlers (e.g., for Space/Enter keys)."
                            ],
                            fix_suggestions=["Add tabindex='0' to the element."],
                            priority_score=0.9,
                            code_location=CodeLocation(
                                element_selector=element.name,
                                element_tag=element.name,
                                attribute_name="tabindex",
                                attribute_value=element.get("tabindex"),
                                full_element=str(element),
                            ),
                        )
                    )

        metrics.update({
            "interactive_elements_count": len(interactive_elements),
            "non_focusable_interactive": len(non_focusable_interactive),
            "custom_interactive_elements": len(potential_interactive),
            "inaccessible_custom_controls": len(inaccessible_custom_controls),
        })
        raw_data["keyboard_accessibility"] = {
            "non_focusable_interactive_list": non_focusable_interactive,
            "inaccessible_custom_controls_list": inaccessible_custom_controls,
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_focus_management_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 2.4.3 & 2.4.7 - Focus Order and Focus Visible with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

        # Check for skip links
        skip_links = soup.find_all("a", href=re.compile(r"^#"))
        skip_to_content = [
            link
            for link in skip_links
            if "skip" in link.get_text().lower() or "main" in link.get("href", "")
        ]

        if not skip_to_content:
            detailed_issues.append(
                self.create_detailed_issue(
                    issue_type="wcag_2_4_1_missing_skip_links",
                    severity=Severity.MEDIUM,
                    message="No skip links found for bypassing repetitive content",
                    location=url,
                    category="operable",
                    subcategory="navigation",
                    description="A mechanism to bypass blocks of content that are repeated on multiple Web pages should be available.",
                    impact="Keyboard and screen reader users may have difficulty navigating past repetitive content.",
                    technical_details={"skip_links_found": False},
                    recommendations=[
                        "Add a 'Skip to main content' link at the top of the page."
                    ],
                    fix_suggestions=[
                        "Add <a href='#maincontent' class='skip-link'>Skip to main content</a> and a corresponding <div id='maincontent'>."
                    ],
                    priority_score=0.5,
                    code_location=CodeLocation(resource_type="html_structure"),
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
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="wcag_2_4_6_incorrect_heading_hierarchy",
                        severity=Severity.MEDIUM,
                        message=f"Incorrect heading hierarchy: skipped from h{prev_level} to h{level}",
                        location=url,
                        category="understandable",
                        subcategory="navigation",
                        description="Headings should be nested hierarchically without skipping levels.",
                        impact="Screen reader users rely on proper heading structure for navigation.",
                        technical_details={
                            "skipped_levels": f"h{prev_level} to h{level}"
                        },
                        recommendations=[
                            "Ensure headings follow a logical, hierarchical order (e.g., H1, H2, H3, not H1, H3)."
                        ],
                        fix_suggestions=[
                            "Adjust heading tags to maintain proper hierarchy."
                        ],
                        priority_score=0.6,
                        code_location=CodeLocation(
                            element_selector=headings[i].name,
                            element_tag=headings[i].name,
                            full_element=str(headings[i]),
                        ),
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
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="wcag_2_1_2_focus_trap",
                        severity=Severity.HIGH,
                        message=f"Potential focus trap in modal: {modal.get('id', 'no-id')}",
                        location=url,
                        category="operable",
                        subcategory="keyboard_accessibility",
                        description="If keyboard focus can be moved to a component of the page, then focus can be moved away from that component using only keyboard interface.",
                        impact="Keyboard users may get trapped within a modal or component.",
                        technical_details={
                            "modal_id": modal.get("id", "no-id"),
                            "focusable_elements_count": len(focusable_elements),
                        },
                        recommendations=[
                            "Implement proper focus management for modals, ensuring focus can be moved in and out."
                        ],
                        fix_suggestions=[
                            "Use a focus trap script or library to manage focus within modals."
                        ],
                        priority_score=0.9,
                        code_location=CodeLocation(
                            element_selector=modal.name,
                            element_tag=modal.name,
                            attribute_name="role",
                            attribute_value=modal.get("role"),
                            full_element=str(modal),
                        ),
                    )
                )

        metrics.update({
            "skip_links_count": len(skip_to_content),
            "heading_hierarchy_issues": len(hierarchy_issues),
            "modal_count": len(modals),
            "focus_trap_issues": len(focus_trap_issues),
        })
        raw_data["focus_management"] = {
            "skip_links_list": skip_to_content,
            "heading_hierarchy_issues_list": hierarchy_issues,
            "focus_trap_issues_list": focus_trap_issues,
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_language_identification_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 3.1.1 & 3.1.2 - Language identification with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

        # Check for lang attribute on html element
        html_element = soup.find("html")
        page_lang = html_element.get("lang") if html_element else None

        metrics["page_language"] = page_lang
        raw_data["page_language"] = page_lang

        if not page_lang:
            detailed_issues.append(
                self.create_detailed_issue(
                    issue_type="wcag_3_1_1_missing_page_language",
                    severity=Severity.HIGH,
                    message="Page language not specified in html lang attribute",
                    location=url,
                    category="understandable",
                    subcategory="language",
                    description="The primary human language of the Web page should be identified.",
                    impact="Screen readers may not render content correctly without language identification.",
                    technical_details={"html_lang_attribute": "missing"},
                    recommendations=[
                        "Add a 'lang' attribute to the <html> element (e.g., <html lang='en'>)."
                    ],
                    fix_suggestions=["Add lang='en' to the <html> tag."],
                    priority_score=0.8,
                    code_location=CodeLocation(
                        element_tag="html", attribute_name="lang"
                    ),
                )
            )

        # Check for language changes within content
        elements_with_lang = soup.find_all(attrs={"lang": True})
        metrics["elements_with_lang_changes"] = len(elements_with_lang)

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
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_3_1_2_potential_unlabeled_language_changes",
                            severity=Severity.LOW,
                            message=f"Potential unlabeled language change: {text[:50]}",
                            location=url,
                            category="understandable",
                            subcategory="language",
                            description="The human language of each passage or phrase in the content should be identified.",
                            impact="Screen readers may mispronounce words or phrases in different languages.",
                            technical_details={
                                "element_name": element.name,
                                "text_content": text[:50],
                            },
                            recommendations=[
                                "Identify language changes with the 'lang' attribute on the specific element."
                            ],
                            fix_suggestions=[
                                "Add lang='es' to <span lang='es'>Spanish text</span>."
                            ],
                            priority_score=0.3,
                            code_location=CodeLocation(
                                element_selector=element.name,
                                element_tag=element.name,
                                full_element=str(element),
                            ),
                        )
                    )

        raw_data["potential_language_changes"] = potential_lang_changes

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_forms_and_labels_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 3.3.2 & 4.1.2 - Forms and Labels with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

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
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="wcag_3_3_2_unlabeled_form_inputs",
                        severity=Severity.HIGH,
                        message=f"Form input missing label: {input_elem.name} (id: {input_id or 'no-id'})",
                        location=url,
                        category="understandable",
                        subcategory="forms",
                        description="Form elements must have associated labels to identify their purpose.",
                        impact="Screen reader users will not know the purpose of the input field.",
                        technical_details={
                            "element_name": input_elem.name,
                            "input_id": input_id,
                            "input_name": input_elem.get("name"),
                        },
                        recommendations=[
                            "Provide a visible label using <label for='id'> or an aria-label/aria-labelledby attribute."
                        ],
                        fix_suggestions=[
                            f"Add <label for='{input_id}'>Label Text</label> or aria-label='Label Text' to the input."
                        ],
                        priority_score=0.8,
                        code_location=CodeLocation(
                            element_selector=input_elem.name,
                            element_tag=input_elem.name,
                            attribute_name="id",
                            attribute_value=input_id,
                            full_element=str(input_elem),
                        ),
                    )
                )

        metrics.update({
            "total_form_inputs": len(form_inputs),
            "unlabeled_inputs": len(unlabeled_inputs),
            "properly_labeled_inputs": len(inputs_with_labels),
        })
        raw_data["form_labels"] = {
            "unlabeled_inputs_list": unlabeled_inputs,
            "properly_labeled_inputs_list": inputs_with_labels,
        }

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
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="wcag_3_3_2_required_fields_not_indicated",
                        severity=Severity.MEDIUM,
                        message=f"Required field without clear indication: {required.name} (id: {required.get('id', 'no-id')})",
                        location=url,
                        category="understandable",
                        subcategory="forms",
                        description="Required fields must have a clear visual indication (e.g., asterisk, text).",
                        impact="Users may not know which fields are mandatory, leading to form submission errors.",
                        technical_details={
                            "element_name": required.name,
                            "input_id": required.get("id"),
                            "has_asterisk": has_asterisk,
                            "has_aria_label": has_aria_label,
                            "has_aria_describedby": bool(has_aria_describedby),
                        },
                        recommendations=[
                            "Add a visual indicator (e.g., an asterisk) and/or an ARIA attribute (aria-required='true') to required fields."
                        ],
                        fix_suggestions=[
                            "Add a * next to the label or aria-required='true' to the input."
                        ],
                        priority_score=0.6,
                        code_location=CodeLocation(
                            element_selector=required.name,
                            element_tag=required.name,
                            attribute_name="required",
                            attribute_value="true",
                            full_element=str(required),
                        ),
                    )
                )

        raw_data["required_fields"] = {
            "required_without_indication_list": required_without_indication
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_semantic_structure_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check WCAG 4.1.1 & 4.1.2 - Semantic structure and valid markup with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

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
        metrics["semantic_elements_count"] = len(semantic_elements)

        # Check for main landmark
        main_elements = soup.find_all("main")
        main_with_role = soup.find_all(attrs={"role": "main"})

        if not main_elements and not main_with_role:
            detailed_issues.append(
                self.create_detailed_issue(
                    issue_type="wcag_4_1_2_missing_main_landmark",
                    severity=Severity.MEDIUM,
                    message="No main landmark found for primary content",
                    location=url,
                    category="robust",
                    subcategory="parsing",
                    description="Web pages should have a main landmark to identify the primary content area.",
                    impact="Screen reader users may have difficulty locating the main content.",
                    technical_details={"main_landmark_found": False},
                    recommendations=[
                        "Add a <main> element or role='main' to the primary content area."
                    ],
                    fix_suggestions=[
                        "Wrap the main content in <main>...</main> or add role='main' to the main content container."
                    ],
                    priority_score=0.6,
                    code_location=CodeLocation(resource_type="html_structure"),
                )
            )
        elif len(main_elements) + len(main_with_role) > 1:
            detailed_issues.append(
                self.create_detailed_issue(
                    issue_type="wcag_4_1_2_multiple_main_landmarks",
                    severity=Severity.MEDIUM,
                    message="Multiple main landmarks found - should be unique",
                    location=url,
                    category="robust",
                    subcategory="parsing",
                    description="There should only be one main landmark per Web page.",
                    impact="Screen reader users may be confused by multiple main content areas.",
                    technical_details={
                        "main_count": len(main_elements) + len(main_with_role)
                    },
                    recommendations=[
                        "Ensure only one main landmark is present on the page."
                    ],
                    fix_suggestions=[
                        "Remove duplicate <main> elements or role='main' attributes."
                    ],
                    priority_score=0.6,
                    code_location=CodeLocation(resource_type="html_structure"),
                )
            )

        # Check for navigation landmarks
        nav_elements = soup.find_all("nav")
        nav_with_role = soup.find_all(attrs={"role": "navigation"})
        total_nav = len(nav_elements) + len(nav_with_role)

        metrics["navigation_landmarks"] = total_nav

        if total_nav == 0:
            detailed_issues.append(
                self.create_detailed_issue(
                    issue_type="wcag_4_1_2_missing_navigation_landmark",
                    severity=Severity.LOW,
                    message="No navigation landmarks found",
                    location=url,
                    category="robust",
                    subcategory="parsing",
                    description="Navigation sections should be identified with a <nav> element or role='navigation'.",
                    impact="Screen reader users may have difficulty identifying navigation areas.",
                    technical_details={"navigation_landmarks_found": False},
                    recommendations=[
                        "Add <nav> elements or role='navigation' to navigation areas."
                    ],
                    fix_suggestions=[
                        "Wrap navigation links in <nav>...</nav> or add role='navigation' to the navigation container."
                    ],
                    priority_score=0.3,
                    code_location=CodeLocation(resource_type="html_structure"),
                )
            )

        # Check for duplicate IDs
        elements_with_id = soup.find_all(attrs={"id": True})
        id_counts: dict[str, int] = {}
        duplicate_ids = []

        for element in elements_with_id:
            element_id = element.get("id")
            if element_id:
                id_counts[element_id] = id_counts.get(element_id, 0) + 1
                if id_counts[element_id] > 1:
                    duplicate_ids.append(element_id)
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="wcag_4_1_1_duplicate_ids",
                            severity=Severity.HIGH,
                            message=f"Duplicate ID found: {element_id}",
                            location=url,
                            category="robust",
                            subcategory="parsing",
                            description="All IDs in an HTML document must be unique.",
                            impact="Assistive technologies may not correctly reference elements with duplicate IDs.",
                            technical_details={
                                "duplicate_id": element_id,
                                "element_name": element.name,
                            },
                            recommendations=[
                                "Ensure all IDs are unique within the HTML document."
                            ],
                            fix_suggestions=[
                                f"Change the ID of {element.name} to a unique value."
                            ],
                            priority_score=0.9,
                            code_location=CodeLocation(
                                element_selector=element.name,
                                element_tag=element.name,
                                attribute_name="id",
                                attribute_value=element_id,
                                full_element=str(element),
                            ),
                        )
                    )

        metrics["duplicate_ids_count"] = len(set(duplicate_ids))
        raw_data["semantic_structure"] = {
            "main_elements_count": len(main_elements) + len(main_with_role),
            "navigation_elements_count": total_nav,
            "duplicate_ids_list": list(set(duplicate_ids)),
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_aria_compliance_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check ARIA usage and compliance with EU regulations and WCAG 2.1 AA with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

        # Check for ARIA attributes
        aria_elements = soup.find_all(
            attrs=lambda x: x and any(attr.startswith("aria-") for attr in x)
        )
        metrics["elements_with_aria"] = len(aria_elements)

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
            role = element.get("role")
            if isinstance(role, list):
                role = " ".join(role)
            if role.strip().lower() not in valid_roles:
                invalid_roles.append({
                    "element": element.name,
                    "invalid_role": role,
                    "id": element.get("id", "no-id"),
                })
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="aria_invalid_roles",
                        severity=Severity.MEDIUM,
                        message=f"Invalid ARIA role: {role} on {element.name}",
                        location=url,
                        category="robust",
                        subcategory="aria_usage",
                        description="Elements with ARIA roles must use valid roles from the WAI-ARIA specification.",
                        impact="Assistive technologies may not correctly interpret the element's purpose.",
                        technical_details={
                            "element_name": element.name,
                            "invalid_role": role,
                        },
                        recommendations=[
                            "Use a valid ARIA role or remove the invalid role attribute."
                        ],
                        fix_suggestions=[
                            f"Change role='{role}' to a valid role or remove it from {element.name}."
                        ],
                        priority_score=0.5,
                        code_location=CodeLocation(
                            element_selector=element.name,
                            element_tag=element.name,
                            attribute_name="role",
                            attribute_value=role,
                            full_element=str(element),
                        ),
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
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="aria_broken_labelledby_references",
                            severity=Severity.HIGH,
                            message=f"Broken aria-labelledby reference: {ref_id} not found",
                            location=url,
                            category="robust",
                            subcategory="aria_usage",
                            description="aria-labelledby attributes must reference existing elements.",
                            impact="Screen readers will not be able to associate the label with the element.",
                            technical_details={
                                "element_id": element.get("id", "no-id"),
                                "missing_reference_id": ref_id,
                            },
                            recommendations=[
                                "Ensure all IDs referenced by aria-labelledby exist on the page."
                            ],
                            fix_suggestions=[
                                f"Create an element with id='{ref_id}' or update aria-labelledby on {element.name}."
                            ],
                            priority_score=0.9,
                            code_location=CodeLocation(
                                element_selector=element.name,
                                element_tag=element.name,
                                attribute_name="aria-labelledby",
                                attribute_value=element.get("aria-labelledby"),
                                full_element=str(element),
                            ),
                        )
                    )

        # EU/EAA Standard ARIA Checks - WCAG 2.1 AA Compliance

        # 1. Form Accessibility (WCAG 3.3.2 - Labels or Instructions)
        form_aria_issues = await self._check_form_aria_accessibility_detailed(soup, url)
        detailed_issues.extend(form_aria_issues["issues"])
        metrics.update(form_aria_issues["metrics"])
        raw_data["form_aria_accessibility"] = form_aria_issues["raw"]

        # 2. Live Regions (WCAG 4.1.3 - Status Messages)
        live_region_issues = await self._check_live_regions_detailed(soup, url)
        detailed_issues.extend(live_region_issues["issues"])
        metrics.update(live_region_issues["metrics"])
        raw_data["live_regions"] = live_region_issues["raw"]

        # 3. Interactive Elements (WCAG 2.1.1 - Keyboard)
        interactive_aria_issues = await self._check_interactive_aria_elements_detailed(
            soup, url
        )
        detailed_issues.extend(interactive_aria_issues["issues"])
        metrics.update(interactive_aria_issues["metrics"])
        raw_data["interactive_aria_elements"] = interactive_aria_issues["raw"]

        # 4. Navigation and Landmarks (WCAG 2.4.1 - Bypass Blocks)
        navigation_aria_issues = await self._check_navigation_aria_detailed(soup, url)
        detailed_issues.extend(navigation_aria_issues["issues"])
        metrics.update(navigation_aria_issues["metrics"])
        raw_data["navigation_aria"] = navigation_aria_issues["raw"]

        # 5. Error Handling (WCAG 3.3.1 - Error Identification)
        error_aria_issues = await self._check_error_aria_handling_detailed(soup, url)
        detailed_issues.extend(error_aria_issues["issues"])
        metrics.update(error_aria_issues["metrics"])
        raw_data["error_aria_handling"] = error_aria_issues["raw"]

        metrics["invalid_roles_count"] = len(invalid_roles)
        metrics["broken_labelledby_count"] = len(labelledby_issues)
        raw_data["aria_compliance"] = {
            "invalid_roles_list": invalid_roles,
            "broken_labelledby_list": labelledby_issues,
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_form_aria_accessibility_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check form ARIA compliance - EU/EAA standard for form accessibility with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

        # Check form inputs for proper ARIA attributes
        form_inputs = soup.find_all(["input", "textarea", "select"])
        inputs_without_labels = []
        inputs_with_labels = []

        for input_elem in form_inputs:
            input_id = input_elem.get("id")
            input_name = input_elem.get("name")
            input_type = input_elem.get("type", "text")

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
            else:
                inputs_with_labels.append({
                    "type": input_type,
                    "id": input_id,
                    "name": input_name,
                })
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="aria_form_missing_labels",
                        severity=Severity.HIGH,
                        message=f"Form input missing label: {input_elem.name} (id: {input_id or 'no-id'})",
                        location=url,
                        category="understandable",
                        subcategory="forms",
                        description="Form elements must have associated labels to identify their purpose.",
                        impact="Screen reader users will not know the purpose of the input field.",
                        technical_details={
                            "element_name": input_elem.name,
                            "input_id": input_id,
                            "input_name": input_elem.get("name"),
                        },
                        recommendations=[
                            "Provide a visible label using <label for='id'> or an aria-label/aria-labelledby attribute."
                        ],
                        fix_suggestions=[
                            f"Add <label for='{input_id}'>Label Text</label> or aria-label='Label Text' to the input."
                        ],
                        priority_score=0.8,
                        code_location=CodeLocation(
                            element_selector=input_elem.name,
                            element_tag=input_elem.name,
                            attribute_name="id",
                            attribute_value=input_id,
                            full_element=str(input_elem),
                        ),
                    )
                )

        metrics.update({
            "total_form_inputs": len(form_inputs),
            "inputs_without_labels": len(inputs_without_labels),
            "properly_labeled_inputs": len(inputs_with_labels),
        })
        raw_data["form_labels"] = {
            "unlabeled_inputs_list": inputs_without_labels,
            "properly_labeled_inputs_list": inputs_with_labels,
        }

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
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="wcag_3_3_2_required_fields_not_indicated",
                        severity=Severity.MEDIUM,
                        message=f"Required field without clear indication: {required.name} (id: {required.get('id', 'no-id')})",
                        location=url,
                        category="understandable",
                        subcategory="forms",
                        description="Required fields must have a clear visual indication (e.g., asterisk, text).",
                        impact="Users may not know which fields are mandatory, leading to form submission errors.",
                        technical_details={
                            "element_name": required.name,
                            "input_id": required.get("id"),
                            "has_asterisk": has_asterisk,
                            "has_aria_label": has_aria_label,
                            "has_aria_describedby": bool(has_aria_describedby),
                        },
                        recommendations=[
                            "Add a visual indicator (e.g., an asterisk) and/or an ARIA attribute (aria-required='true') to required fields."
                        ],
                        fix_suggestions=[
                            "Add a * next to the label or aria-required='true' to the input."
                        ],
                        priority_score=0.6,
                        code_location=CodeLocation(
                            element_selector=required.name,
                            element_tag=required.name,
                            attribute_name="required",
                            attribute_value="true",
                            full_element=str(required),
                        ),
                    )
                )

        raw_data["required_fields"] = {
            "required_without_indication_list": required_without_indication
        }

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_live_regions_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check live regions for dynamic content - EU/EAA standard for status messages with detailed issues."""
        detailed_issues = []
        metrics: dict[str, Any] = {}
        raw_data: dict[str, Any] = {}

        # Check for live regions
        live_regions = soup.find_all(attrs={"aria-live": True})
        live_region_types: dict[str, int] = {}

        for region in live_regions:
            live_type = region.get("aria-live", "off")
            if isinstance(live_type, list):
                live_type = " ".join(live_type)
            live_region_types[live_type] = live_region_types.get(live_type, 0) + 1

        metrics["live_regions_count"] = len(live_regions)
        metrics["live_region_types"] = live_region_types

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
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="aria_inappropriate_live_regions",
                        severity=Severity.MEDIUM,
                        message=f"Inappropriate live region usage: {live_type} on {region.name}",
                        location=url,
                        category="robust",
                        subcategory="aria_usage",
                        description="aria-live='assertive' should only be used for critical, time-sensitive updates.",
                        impact="May interrupt screen reader users with non-critical information.",
                        technical_details={
                            "element_name": region.name,
                            "aria_live_type": live_type,
                        },
                        recommendations=[
                            "Use aria-live='polite' for most dynamic content updates."
                        ],
                        fix_suggestions=[
                            f"Change aria-live='{live_type}' to aria-live='polite' on {region.name}."
                        ],
                        priority_score=0.5,
                        code_location=CodeLocation(
                            element_selector=region.name,
                            element_tag=region.name,
                            attribute_name="aria-live",
                            attribute_value=live_type,
                            full_element=str(region),
                        ),
                    )
                )

        raw_data["inappropriate_live_regions_list"] = inappropriate_live_regions

        return {"issues": detailed_issues, "metrics": metrics, "raw": raw_data}

    async def _check_interactive_aria_elements(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check interactive ARIA elements for proper keyboard accessibility - EU/EAA standard."""
        issues = []
        metadata: dict[str, Any] = {}

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

    async def _check_navigation_aria(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check navigation ARIA for proper landmark structure - EU/EAA standard."""
        issues = []
        metadata: dict[str, Any] = {}

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

    async def _check_error_aria_handling(
        self, soup: BeautifulSoup, url: str
    ) -> dict[str, Any]:
        """Check error handling with ARIA - EU/EAA standard for error identification."""
        issues = []
        metadata: dict[str, Any] = {}

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
    ) -> dict[str, Any]:
        """Check EU Accessibility Act specific requirements."""
        issues = []
        metadata: dict[str, Any] = {}

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
            if soup.find(string=re.compile(pattern, re.I)):
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
            if soup.find(string=re.compile(pattern, re.I)):
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
    ) -> dict[str, Any]:
        """Check mobile and responsive design accessibility features."""
        issues = []
        metadata: dict[str, Any] = {}

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
    ) -> dict[str, Any]:
        """Check for responsive design breakpoints and CSS media queries."""
        issues = []
        metadata: dict[str, Any] = {}

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
    ) -> dict[str, Any]:
        """Check mobile performance aspects that affect accessibility."""
        issues = []
        metadata: dict[str, Any] = {}

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
            if (
                src
                and not isinstance(src, list)
                and not src.startswith(("/", "./", "../"))
            ):
                external_resources.append(f"script: {src}")

        # External stylesheets
        stylesheets = soup.find_all("link", rel="stylesheet")
        for stylesheet in stylesheets:
            href = stylesheet.get("href")
            if (
                href
                and not isinstance(href, list)
                and not href.startswith(("/", "./", "../"))
            ):
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
