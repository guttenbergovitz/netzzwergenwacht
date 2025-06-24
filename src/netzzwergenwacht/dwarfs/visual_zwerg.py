"""Visual-Zwerg for visual analysis and UI testing."""

from datetime import datetime
from pathlib import Path

import httpx
from bs4 import BeautifulSoup
from PIL import Image, ImageStat
from playwright.async_api import async_playwright

from .base import AnalysisResult, Dwarf, Issue, Severity


class VisualZwerg(Dwarf):
    """Visual-Zwerg - Analyzes websites for visual consistency, UI elements, and visual regression testing."""

    def __init__(self):
        super().__init__(
            name="Visual-Zwerg",
            description="Visual analysis and UI testing for consistency and accessibility",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL for visual consistency and UI elements."""
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

            # Perform visual analysis with Playwright
            visual_issues, visual_metadata = await self._analyze_visual_elements(url)
            issues.extend(visual_issues)
            metadata.update(visual_metadata)

            # Perform UI element analysis
            ui_issues, ui_metadata = await self._analyze_ui_elements(url)
            issues.extend(ui_issues)
            metadata.update(ui_metadata)

            # Perform color scheme analysis
            color_issues, color_metadata = await self._analyze_color_scheme(url)
            issues.extend(color_issues)
            metadata.update(color_metadata)

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

    async def _analyze_visual_elements(self, url: str) -> tuple[list[Issue], dict]:
        """Analyze visual elements and layout consistency."""
        issues = []
        metadata = {}

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Set viewport for consistent testing
                await page.set_viewport_size({"width": 1920, "height": 1080})

                # Navigate to page
                response = await page.goto(url, wait_until="networkidle", timeout=30000)

                if not response or response.status != 200:
                    issues.append(
                        self.create_issue(
                            issue_type="visual_analysis_failed",
                            severity=Severity.HIGH,
                            message="Failed to load page for visual analysis",
                            location=url,
                            evidence={
                                "status": response.status if response else "No response"
                            },
                        )
                    )
                    await browser.close()
                    return issues, metadata

                # Take screenshot for analysis
                screenshot_path = await self._take_screenshot(page, url)
                if screenshot_path:
                    metadata["screenshot_path"] = screenshot_path

                    # Analyze screenshot for visual issues
                    visual_analysis = await self._analyze_screenshot(screenshot_path)
                    metadata.update(visual_analysis)

                    # Check for visual consistency issues
                    consistency_issues = await self._check_visual_consistency(page)
                    issues.extend(consistency_issues)

                # Check for layout issues
                layout_issues = await self._check_layout_issues(page)
                issues.extend(layout_issues)

                await browser.close()

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="visual_analysis_error",
                    severity=Severity.MEDIUM,
                    message=f"Visual analysis failed: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def _analyze_ui_elements(self, url: str) -> tuple[list[Issue], dict]:
        """Analyze UI elements and their accessibility."""
        issues = []
        metadata = {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.content, "html.parser")

                # Analyze buttons and interactive elements
                button_analysis = await self._analyze_buttons(soup, url)
                issues.extend(button_analysis["issues"])
                metadata.update(button_analysis["metadata"])

                # Analyze forms
                form_analysis = await self._analyze_forms(soup, url)
                issues.extend(form_analysis["issues"])
                metadata.update(form_analysis["metadata"])

                # Analyze navigation
                nav_analysis = await self._analyze_navigation(soup, url)
                issues.extend(nav_analysis["issues"])
                metadata.update(nav_analysis["metadata"])

                # Analyze images and media
                media_analysis = await self._analyze_media_elements(soup, url)
                issues.extend(media_analysis["issues"])
                metadata.update(media_analysis["metadata"])

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="ui_analysis_error",
                    severity=Severity.MEDIUM,
                    message=f"UI analysis failed: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def _analyze_color_scheme(self, url: str) -> tuple[list[Issue], dict]:
        """Analyze color scheme and contrast."""
        issues = []
        metadata = {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.content, "html.parser")

                # Extract CSS and analyze colors
                color_analysis = await self._extract_color_scheme(soup, url)
                issues.extend(color_analysis["issues"])
                metadata.update(color_analysis["metadata"])

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="color_analysis_error",
                    severity=Severity.LOW,
                    message=f"Color analysis failed: {str(e)}",
                    location=url,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def _take_screenshot(self, page, url: str) -> str | None:
        """Take a screenshot and save it to the output directory."""
        try:
            # Create output directory
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = url.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
            filename = f"{safe_url}_visual_{timestamp}.png"
            screenshot_path = output_dir / filename

            # Take screenshot
            await page.screenshot(path=str(screenshot_path), full_page=True)
            return str(screenshot_path)

        except Exception:
            # Log error but don't fail the entire analysis
            return None

    async def _analyze_screenshot(self, screenshot_path: str) -> dict:
        """Analyze screenshot for visual characteristics."""
        metadata = {}

        try:
            with Image.open(screenshot_path) as img:
                # Basic image analysis
                metadata.update({
                    "image_width": img.width,
                    "image_height": img.height,
                    "image_mode": img.mode,
                    "image_format": img.format,
                })

                # Color analysis
                if img.mode in ["RGB", "RGBA"]:
                    # Convert to RGB for analysis
                    rgb_img = img.convert("RGB")
                    stat = ImageStat.Stat(rgb_img)

                    metadata.update({
                        "average_color": tuple(int(x) for x in stat.mean),
                        "color_std": tuple(int(x) for x in stat.stddev),
                        "dominant_colors": await self._get_dominant_colors(rgb_img),
                    })

        except Exception as e:
            metadata["screenshot_analysis_error"] = str(e)

        return metadata

    async def _get_dominant_colors(
        self, img: Image.Image
    ) -> list[tuple[int, int, int]]:
        """Extract dominant colors from image."""
        try:
            # Resize for faster processing
            img_small = img.resize((150, 150))

            # Get color palette
            colors = img_small.getcolors(maxcolors=256)
            if colors:
                # Sort by frequency and return top 5
                colors.sort(key=lambda x: x[0], reverse=True)
                return [color[1] for color in colors[:5]]

            return []
        except Exception:
            return []

    async def _check_visual_consistency(self, page) -> list[Issue]:
        """Check for visual consistency issues."""
        issues = []

        try:
            # Check for consistent spacing
            spacing_issues = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    const spacingValues = new Set();

                    elements.forEach(el => {
                        const style = window.getComputedStyle(el);
                        const margin = style.margin;
                        const padding = style.padding;

                        if (margin && margin !== '0px') spacingValues.add(margin);
                        if (padding && padding !== '0px') spacingValues.add(padding);
                    });

                    return Array.from(spacingValues).length > 10; // Too many different spacing values
                }
            """)

            if spacing_issues:
                issues.append(
                    self.create_issue(
                        issue_type="inconsistent_spacing",
                        severity=Severity.LOW,
                        message="Inconsistent spacing detected across elements",
                        location=page.url,
                        evidence={
                            "recommendation": "Use consistent spacing system (e.g., 8px grid)",
                        },
                    )
                )

            # Check for consistent font sizes
            font_issues = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    const fontSizes = new Set();

                    elements.forEach(el => {
                        const style = window.getComputedStyle(el);
                        const fontSize = style.fontSize;
                        if (fontSize) fontSizes.add(fontSize);
                    });

                    return Array.from(fontSizes).length > 8; // Too many different font sizes
                }
            """)

            if font_issues:
                issues.append(
                    self.create_issue(
                        issue_type="inconsistent_font_sizes",
                        severity=Severity.LOW,
                        message="Too many different font sizes detected",
                        location=page.url,
                        evidence={
                            "recommendation": "Use consistent typography scale",
                        },
                    )
                )

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="visual_consistency_check_failed",
                    severity=Severity.LOW,
                    message=f"Visual consistency check failed: {str(e)}",
                    location=page.url,
                    evidence={"error": str(e)},
                )
            )

        return issues

    async def _check_layout_issues(self, page) -> list[Issue]:
        """Check for layout and positioning issues."""
        issues = []

        try:
            # Check for overlapping elements
            overlapping = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    const overlapping = [];

                    for (let i = 0; i < elements.length; i++) {
                        for (let j = i + 1; j < elements.length; j++) {
                            const rect1 = elements[i].getBoundingClientRect();
                            const rect2 = elements[j].getBoundingClientRect();

                            if (rect1.left < rect2.right && rect1.right > rect2.left &&
                                rect1.top < rect2.bottom && rect1.bottom > rect2.top) {
                                overlapping.push({
                                    element1: elements[i].tagName,
                                    element2: elements[j].tagName
                                });
                            }
                        }
                    }

                    return overlapping.slice(0, 5); // Limit results
                }
            """)

            if overlapping:
                issues.append(
                    self.create_issue(
                        issue_type="overlapping_elements",
                        severity=Severity.MEDIUM,
                        message=f"Found {len(overlapping)} overlapping elements",
                        location=page.url,
                        evidence={
                            "overlapping_elements": overlapping,
                            "recommendation": "Fix overlapping elements for better UX",
                        },
                    )
                )

            # Check for broken layouts
            broken_layout = await page.evaluate("""
                () => {
                    const body = document.body;
                    const html = document.documentElement;

                    return {
                        body_overflow: body.scrollWidth > body.clientWidth || body.scrollHeight > body.clientHeight,
                        html_overflow: html.scrollWidth > html.clientWidth || html.scrollHeight > html.clientHeight,
                        viewport_issues: window.innerWidth !== html.clientWidth || window.innerHeight !== html.clientHeight
                    };
                }
            """)

            if broken_layout["body_overflow"] or broken_layout["html_overflow"]:
                issues.append(
                    self.create_issue(
                        issue_type="layout_overflow",
                        severity=Severity.MEDIUM,
                        message="Layout overflow detected",
                        location=page.url,
                        evidence={
                            "overflow_details": broken_layout,
                            "recommendation": "Fix layout overflow issues",
                        },
                    )
                )

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="layout_check_failed",
                    severity=Severity.LOW,
                    message=f"Layout check failed: {str(e)}",
                    location=page.url,
                    evidence={"error": str(e)},
                )
            )

        return issues

    async def _analyze_buttons(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze buttons and interactive elements."""
        issues = []
        metadata = {}

        buttons = soup.find_all([
            "button",
            "input[type='button']",
            "input[type='submit']",
        ])
        links = soup.find_all("a", href=True)

        # Analyze button consistency
        button_texts = [
            btn.get_text(strip=True) for btn in buttons if btn.get_text(strip=True)
        ]
        unique_button_texts = set(button_texts)

        if len(button_texts) > len(unique_button_texts) * 1.5:
            issues.append(
                self.create_issue(
                    issue_type="inconsistent_button_texts",
                    severity=Severity.LOW,
                    message="Inconsistent button text patterns detected",
                    location=url,
                    evidence={
                        "total_buttons": len(buttons),
                        "unique_texts": len(unique_button_texts),
                        "recommendation": "Use consistent button text patterns",
                    },
                )
            )

        # Check for buttons without text
        buttons_without_text = [btn for btn in buttons if not btn.get_text(strip=True)]
        if buttons_without_text:
            issues.append(
                self.create_issue(
                    issue_type="buttons_without_text",
                    severity=Severity.MEDIUM,
                    message=f"Found {len(buttons_without_text)} buttons without text",
                    location=url,
                    evidence={
                        "buttons_without_text_count": len(buttons_without_text),
                        "recommendation": "Add descriptive text to all buttons",
                    },
                )
            )

        metadata.update({
            "total_buttons": len(buttons),
            "total_links": len(links),
            "buttons_with_text": len(buttons) - len(buttons_without_text),
            "buttons_without_text": len(buttons_without_text),
        })

        return {"issues": issues, "metadata": metadata}

    async def _analyze_forms(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze forms and form elements."""
        issues = []
        metadata = {}

        forms = soup.find_all("form")
        inputs = soup.find_all("input")
        textareas = soup.find_all("textarea")
        selects = soup.find_all("select")

        # Check for forms without labels
        forms_without_labels = []
        for form in forms:
            form_inputs = form.find_all("input")
            inputs_without_labels = []

            for inp in form_inputs:
                if inp.get("type") not in ["hidden", "submit", "button"]:
                    # Check for associated label
                    label = soup.find("label", attrs={"for": inp.get("id")})
                    if not label and not inp.get("aria-label"):
                        inputs_without_labels.append(inp.get("name", "unnamed"))

            if inputs_without_labels:
                forms_without_labels.append({
                    "form_id": form.get("id", "unnamed"),
                    "inputs_without_labels": inputs_without_labels,
                })

        if forms_without_labels:
            issues.append(
                self.create_issue(
                    issue_type="forms_without_labels",
                    severity=Severity.HIGH,
                    message=f"Found {len(forms_without_labels)} forms with unlabeled inputs",
                    location=url,
                    evidence={
                        "forms_without_labels": forms_without_labels,
                        "recommendation": "Add labels or aria-label to all form inputs",
                    },
                )
            )

        metadata.update({
            "total_forms": len(forms),
            "total_inputs": len(inputs),
            "total_textareas": len(textareas),
            "total_selects": len(selects),
            "forms_without_labels": len(forms_without_labels),
        })

        return {"issues": issues, "metadata": metadata}

    async def _analyze_navigation(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze navigation elements."""
        issues = []
        metadata = {}

        # Find navigation elements
        nav_elements = soup.find_all(["nav", "ul", "ol"])
        nav_links = soup.find_all("a", href=True)

        # Check for navigation structure
        navigation_structure = []
        for nav in nav_elements:
            if nav.name == "nav" or (
                nav.find_parent("nav") and nav.name in ["ul", "ol"]
            ):
                nav_items = nav.find_all("li")
                navigation_structure.append({
                    "type": nav.name,
                    "items_count": len(nav_items),
                    "has_links": bool(nav.find_all("a")),
                })

        # Check for missing navigation
        if not navigation_structure:
            issues.append(
                self.create_issue(
                    issue_type="missing_navigation",
                    severity=Severity.MEDIUM,
                    message="No clear navigation structure found",
                    location=url,
                    evidence={
                        "recommendation": "Add semantic navigation elements",
                    },
                )
            )

        # Check for navigation depth
        deep_navigation = [
            nav for nav in navigation_structure if nav["items_count"] > 10
        ]
        if deep_navigation:
            issues.append(
                self.create_issue(
                    issue_type="deep_navigation",
                    severity=Severity.LOW,
                    message="Very deep navigation structure detected",
                    location=url,
                    evidence={
                        "deep_navigation_count": len(deep_navigation),
                        "recommendation": "Consider simplifying navigation structure",
                    },
                )
            )

        metadata.update({
            "total_nav_elements": len(nav_elements),
            "total_nav_links": len(nav_links),
            "navigation_structures": navigation_structure,
            "deep_navigation_count": len(deep_navigation),
        })

        return {"issues": issues, "metadata": metadata}

    async def _analyze_media_elements(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze images and media elements."""
        issues = []
        metadata = {}

        images = soup.find_all("img")
        videos = soup.find_all("video")
        audios = soup.find_all("audio")

        # Check for images without alt text
        images_without_alt = [img for img in images if not img.get("alt")]
        if images_without_alt:
            issues.append(
                self.create_issue(
                    issue_type="images_without_alt",
                    severity=Severity.MEDIUM,
                    message=f"Found {len(images_without_alt)} images without alt text",
                    location=url,
                    evidence={
                        "images_without_alt_count": len(images_without_alt),
                        "recommendation": "Add alt text to all images",
                    },
                )
            )

        # Check for large images
        large_images = []
        for img in images:
            src = img.get("src", "")
            if any(ext in src.lower() for ext in [".jpg", ".jpeg", ".png"]):
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
                    issue_type="large_images",
                    severity=Severity.LOW,
                    message=f"Found {len(large_images)} potentially large images",
                    location=url,
                    evidence={
                        "large_images": large_images[:5],
                        "recommendation": "Optimize large images for web",
                    },
                )
            )

        metadata.update({
            "total_images": len(images),
            "total_videos": len(videos),
            "total_audios": len(audios),
            "images_without_alt": len(images_without_alt),
            "large_images": len(large_images),
        })

        return {"issues": issues, "metadata": metadata}

    async def _extract_color_scheme(self, soup: BeautifulSoup, url: str) -> dict:
        """Extract and analyze color scheme from CSS."""
        issues = []
        metadata = {}

        # Extract colors from inline styles
        color_values = set()
        background_values = set()

        # Find elements with color styles
        elements_with_color = soup.find_all(attrs={"style": True})
        for element in elements_with_color:
            style = element.get("style", "")
            if "color:" in style:
                # Extract color value (simplified)
                color_match = style.split("color:")[1].split(";")[0].strip()
                if color_match:
                    color_values.add(color_match)

            if "background" in style:
                bg_match = style.split("background")[1].split(";")[0].strip()
                if bg_match:
                    background_values.add(bg_match)

        # Check for too many different colors
        if len(color_values) > 20:
            issues.append(
                self.create_issue(
                    issue_type="too_many_colors",
                    severity=Severity.LOW,
                    message=f"Too many different colors detected: {len(color_values)}",
                    location=url,
                    evidence={
                        "color_count": len(color_values),
                        "recommendation": "Use a consistent color palette",
                    },
                )
            )

        # Check for potential contrast issues (basic check)
        light_colors = [
            c
            for c in color_values
            if any(
                light in c.lower() for light in ["white", "light", "#fff", "#f0f0f0"]
            )
        ]
        dark_colors = [
            c
            for c in color_values
            if any(dark in c.lower() for dark in ["black", "dark", "#000", "#333"])
        ]

        if len(light_colors) > 0 and len(dark_colors) > 0:
            # Potential contrast issues if both light and dark colors are used extensively
            if len(light_colors) > 5 and len(dark_colors) > 5:
                issues.append(
                    self.create_issue(
                        issue_type="potential_contrast_issues",
                        severity=Severity.MEDIUM,
                        message="Potential color contrast issues detected",
                        location=url,
                        evidence={
                            "light_colors_count": len(light_colors),
                            "dark_colors_count": len(dark_colors),
                            "recommendation": "Verify color contrast ratios meet WCAG guidelines",
                        },
                    )
                )

        metadata.update({
            "color_values_count": len(color_values),
            "background_values_count": len(background_values),
            "light_colors_count": len(light_colors),
            "dark_colors_count": len(dark_colors),
        })

        return {"issues": issues, "metadata": metadata}
