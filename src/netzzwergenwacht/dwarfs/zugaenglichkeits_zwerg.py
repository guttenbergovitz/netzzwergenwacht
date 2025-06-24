"""Zugaenglichkeits-Zwerg for EU Accessibility Act (EAA) compliance analysis."""

import re

import httpx
from bs4 import BeautifulSoup

from .base import AnalysisResult, Dwarf, Severity


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

        metadata.update(
            {
                "total_images": len(images),
                "images_without_alt": len(images_without_alt),
                "decorative_images": len(decorative_images),
                "complex_images": len(complex_images),
            }
        )

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
                media_without_alternatives.append(
                    {"tag": media.name, "src": media.get("src", "embedded")}
                )

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
                    contrast_issues.append(
                        {
                            "element": element.name,
                            "style": style[:100],  # Truncate for evidence
                        }
                    )

        metadata.update(
            {
                "elements_with_inline_styles": len(inline_styles),
                "potential_contrast_issues": potential_issues,
                "style_elements_count": len(style_elements),
            }
        )

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
                    color_only_indicators.append(
                        {"text": text[:50], "element": element.name}
                    )

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
        interactive_elements = soup.find_all(
            ["a", "button", "input", "select", "textarea"]
        )
        non_focusable_interactive = []

        for element in interactive_elements:
            tabindex = element.get("tabindex")
            if tabindex == "-1":
                non_focusable_interactive.append(
                    {
                        "tag": element.name,
                        "text": element.get_text(strip=True)[:50],
                        "id": element.get("id", "no-id"),
                    }
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
                    inaccessible_custom_controls.append(
                        {
                            "tag": element.name,
                            "text": element.get_text(strip=True)[:50],
                            "role": element.get("role", "none"),
                        }
                    )

        metadata.update(
            {
                "interactive_elements_count": len(interactive_elements),
                "non_focusable_interactive": len(non_focusable_interactive),
                "custom_interactive_elements": len(potential_interactive),
                "inaccessible_custom_controls": len(inaccessible_custom_controls),
            }
        )

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
                hierarchy_issues.append(
                    {
                        "position": i,
                        "jumped_from": f"h{prev_level}",
                        "jumped_to": f"h{level}",
                    }
                )

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
            focusable_elements = modal.find_all(
                ["a", "button", "input", "select", "textarea"]
            )
            focusable_elements.extend(modal.find_all(attrs={"tabindex": "0"}))

            if (
                len(focusable_elements) < 2
            ):  # Should have at least close button and one other element
                focus_trap_issues.append(
                    {
                        "modal_id": modal.get("id", "no-id"),
                        "focusable_count": len(focusable_elements),
                    }
                )

        metadata.update(
            {
                "skip_links_count": len(skip_to_content),
                "heading_hierarchy_issues": len(hierarchy_issues),
                "modal_count": len(modals),
                "focus_trap_issues": len(focus_trap_issues),
            }
        )

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
                    potential_lang_changes.append(
                        {"text": text[:50], "element": element.name}
                    )

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
                unlabeled_inputs.append(
                    {
                        "type": input_type,
                        "id": input_id or "no-id",
                        "name": input_elem.get("name", "no-name"),
                    }
                )

        metadata.update(
            {
                "total_form_inputs": len(form_inputs),
                "unlabeled_inputs": len(unlabeled_inputs),
                "properly_labeled_inputs": len(inputs_with_labels),
            }
        )

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
                required_without_indication.append(
                    {
                        "type": required.get("type", "unknown"),
                        "id": required.get("id", "no-id"),
                    }
                )

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
        semantic_elements = soup.find_all(
            ["main", "nav", "header", "footer", "aside", "section", "article"]
        )
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
        """Check ARIA usage and compliance."""
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
                invalid_roles.append(
                    {
                        "element": element.name,
                        "invalid_role": role,
                        "id": element.get("id", "no-id"),
                    }
                )

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
                    labelledby_issues.append(
                        {
                            "element_id": element.get("id", "no-id"),
                            "missing_reference": ref_id,
                        }
                    )

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

        metadata["invalid_roles_count"] = len(invalid_roles)
        metadata["broken_labelledby_count"] = len(labelledby_issues)

        return {"issues": issues, "metadata": metadata}

    async def _check_eaa_specific_requirements(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Check EU Accessibility Act specific requirements."""
        issues = []
        metadata = {}

        # EAA requires accessibility statements
        accessibility_statement_links = soup.find_all(
            "a", string=re.compile(r"accessibility|barrierefreiheit", re.I)
        )
        accessibility_statement_links.extend(
            soup.find_all("a", href=re.compile(r"accessibility|barrierefreiheit", re.I))
        )

        metadata["accessibility_statement_links"] = len(accessibility_statement_links)

        if not accessibility_statement_links:
            issues.append(
                self.create_issue(
                    issue_type="eaa_missing_accessibility_statement",
                    severity=Severity.HIGH,
                    message="EAA: No accessibility statement link found",
                    location=url,
                    evidence={
                        "eaa_requirement": "Article 7 - Accessibility statement",
                        "recommendation": "Provide a link to an accessibility statement",
                    },
                )
            )

        # EAA requires feedback mechanisms
        feedback_mechanisms = soup.find_all(
            "a", href=re.compile(r"mailto:|contact|feedback", re.I)
        )
        contact_forms = soup.find_all("form")

        metadata["feedback_mechanisms"] = len(feedback_mechanisms) + len(contact_forms)

        if len(feedback_mechanisms) + len(contact_forms) == 0:
            issues.append(
                self.create_issue(
                    issue_type="eaa_missing_feedback_mechanism",
                    severity=Severity.MEDIUM,
                    message="EAA: No clear feedback mechanism found",
                    location=url,
                    evidence={
                        "eaa_requirement": "Article 7 - Feedback mechanism",
                        "recommendation": "Provide contact information or feedback form for accessibility issues",
                    },
                )
            )

        # Check for compatibility with assistive technologies
        # This is a basic check - full compliance would require actual AT testing
        problematic_elements = soup.find_all(["blink", "marquee"])
        if problematic_elements:
            issues.append(
                self.create_issue(
                    issue_type="eaa_incompatible_elements",
                    severity=Severity.HIGH,
                    message=f"EAA: {len(problematic_elements)} elements incompatible with assistive technologies",
                    location=url,
                    evidence={
                        "problematic_elements": [
                            elem.name for elem in problematic_elements
                        ],
                        "eaa_requirement": "Compatibility with assistive technologies",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}
