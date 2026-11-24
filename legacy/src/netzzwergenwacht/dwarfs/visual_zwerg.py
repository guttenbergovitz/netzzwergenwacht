"""Visual-Zwerg for visual analysis and UI testing."""

from datetime import datetime
from pathlib import Path

import httpx
from bs4 import BeautifulSoup
from PIL import Image, ImageStat
from playwright.async_api import async_playwright

from .base import (
    AnalysisResult,
    CodeLocation,
    DetailedAnalysisResult,
    Dwarf,
    Issue,
    Severity,
    VisualMetrics,
)


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

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL for visual consistency and UI elements with detailed context and improvement suggestions."""
        try:
            detailed_issues = []
            visual_metrics = VisualMetrics()
            raw_data = {}

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="invalid_url_scheme",
                        severity=Severity.HIGH,
                        message="URL must start with http:// or https://",
                        location=url,
                        category="visual",
                        subcategory="url_structure",
                        description="The provided URL does not use a valid HTTP scheme",
                        impact="Cannot perform visual analysis without valid scheme.",
                        technical_details={"provided_url": url},
                        recommendations=[
                            "Use HTTPS URLs for better security and visual delivery."
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
                    visual_metrics=visual_metrics,
                    raw_data=raw_data,
                )

            # Perform detailed visual analysis with Playwright
            visual_elements_data = await self._analyze_visual_elements_detailed(url)
            detailed_issues.extend(visual_elements_data["issues"])
            visual_metrics.screenshot_path = visual_elements_data["metrics"].get(
                "screenshot_path"
            )
            visual_metrics.dominant_colors = visual_elements_data["metrics"].get(
                "dominant_colors", []
            )
            raw_data["visual_elements"] = visual_elements_data["raw"]

            # Handle responsive screenshots in VisualMetrics
            if "screenshots" in visual_elements_data["raw"]:
                screenshots_data = visual_elements_data["raw"]["screenshots"]
                if (
                    isinstance(screenshots_data, dict)
                    and "screenshots" in screenshots_data
                ):
                    screenshots_list = screenshots_data["screenshots"]
                    visual_metrics.screenshots = {
                        screenshot["device"]: screenshot["filename"]
                        for screenshot in screenshots_list
                        if "device" in screenshot and "filename" in screenshot
                    }

            # Perform UI element analysis with detailed context
            ui_elements_data = await self._analyze_ui_elements_detailed(url)
            detailed_issues.extend(ui_elements_data["issues"])
            visual_metrics.button_count = ui_elements_data["metrics"].get(
                "button_count", 0
            )
            visual_metrics.form_count = ui_elements_data["metrics"].get("form_count", 0)
            visual_metrics.navigation_issues = ui_elements_data["metrics"].get(
                "navigation_issues", 0
            )
            raw_data["ui_elements"] = ui_elements_data["raw"]

            # Perform color scheme analysis with detailed context
            color_scheme_data = await self._analyze_color_scheme_detailed(url)
            detailed_issues.extend(color_scheme_data["issues"])
            visual_metrics.color_contrast_issues = color_scheme_data["metrics"].get(
                "color_contrast_issues", 0
            )
            visual_metrics.color_palette_size = color_scheme_data["metrics"].get(
                "color_palette_size", 0
            )
            raw_data["color_scheme"] = color_scheme_data["raw"]

            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                detailed_issues=detailed_issues,
                visual_metrics=visual_metrics,
                raw_data=raw_data,
            )

        except Exception as e:
            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
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

                # Take responsive screenshots for analysis
                screenshots_metadata = await self._take_responsive_screenshots(
                    page, url
                )
                metadata.update(screenshots_metadata)

                # Analyze the desktop screenshot for visual issues (use first successful screenshot)
                screenshots = screenshots_metadata.get("screenshots", [])
                desktop_screenshot = None
                for screenshot in screenshots:
                    if (
                        screenshot.get("device") == "desktop"
                        and "filename" in screenshot
                    ):
                        desktop_screenshot = screenshot["filename"]
                        break

                if desktop_screenshot:
                    metadata["screenshot_path"] = desktop_screenshot
                    # Analyze screenshot for visual issues
                    visual_analysis = await self._analyze_screenshot(desktop_screenshot)
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

    async def _take_responsive_screenshots(self, page, url: str) -> dict:
        """Take screenshots for different viewport sizes and save to output directory."""
        metadata = {}
        screenshots_taken = []

        # Create output directory if it doesn't exist
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

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
                filename = f"{safe_url}_visual_{device}_{timestamp}.png"
                screenshot_path = output_dir / filename
                await page.screenshot(path=str(screenshot_path), full_page=True)

                screenshots_taken.append({
                    "device": device,
                    "viewport": viewport,
                    "filename": str(screenshot_path),
                })

            except Exception as e:
                # Log error but continue with other viewports
                screenshots_taken.append({
                    "device": device,
                    "viewport": viewport,
                    "error": str(e),
                })

        metadata["screenshots"] = screenshots_taken
        metadata["screenshots_directory"] = str(output_dir)

        return metadata

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

    async def _analyze_visual_elements_detailed(self, url: str) -> dict:
        """Analyze visual elements and layout consistency with detailed context."""
        issues = []
        metrics = {}
        raw = {}

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
                        self.create_detailed_issue(
                            issue_type="visual_analysis_failed",
                            severity=Severity.HIGH,
                            message="Failed to load page for visual analysis",
                            location=url,
                            category="visual",
                            subcategory="page_loading",
                            description="Page could not be loaded for visual analysis",
                            impact="Cannot perform visual analysis",
                            technical_details={
                                "status": response.status if response else "No response"
                            },
                            recommendations=["Check page accessibility and try again"],
                            code_location=CodeLocation(
                                resource_type="http", attribute_value=url
                            ),
                            priority_score=0.8,
                        )
                    )
                    await browser.close()
                    return {"issues": issues, "metrics": metrics, "raw": raw}

                # Take responsive screenshots for analysis
                screenshots_metadata = await self._take_responsive_screenshots(
                    page, url
                )
                raw["screenshots"] = screenshots_metadata

                # Analyze all screenshots for visual issues and responsiveness
                screenshots = screenshots_metadata.get("screenshots", [])
                screenshot_analyses = {}

                for screenshot in screenshots:
                    if "filename" in screenshot and "device" in screenshot:
                        device = screenshot["device"]
                        filename = screenshot["filename"]

                        # Analyze each screenshot
                        analysis = await self._analyze_screenshot_detailed(filename)
                        screenshot_analyses[device] = {
                            "filename": filename,
                            "analysis": analysis,
                        }

                # Use desktop screenshot as primary for metrics
                if "desktop" in screenshot_analyses:
                    desktop_analysis = screenshot_analyses["desktop"]["analysis"]
                    metrics["screenshot_path"] = screenshot_analyses["desktop"][
                        "filename"
                    ]
                    metrics.update(desktop_analysis["metrics"])
                    raw["screenshot_analysis"] = desktop_analysis["raw"]

                # Add all screenshot analyses to raw data
                raw["screenshot_analyses"] = screenshot_analyses

                # Analyze responsiveness by comparing screenshots
                if len(screenshot_analyses) >= 2:
                    responsiveness_issues = await self._analyze_responsiveness(
                        screenshot_analyses, url
                    )
                    issues.extend(responsiveness_issues["issues"])
                    metrics.update(responsiveness_issues["metrics"])
                    raw["responsiveness_analysis"] = responsiveness_issues["raw"]

                # Check for visual consistency issues
                consistency_issues = await self._check_visual_consistency_detailed(
                    page, url
                )
                issues.extend(consistency_issues["issues"])
                metrics.update(consistency_issues["metrics"])
                raw["visual_consistency"] = consistency_issues["raw"]

                # Check for layout issues
                layout_issues = await self._check_layout_issues_detailed(page, url)
                issues.extend(layout_issues["issues"])
                metrics.update(layout_issues["metrics"])
                raw["layout_analysis"] = layout_issues["raw"]

                await browser.close()

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="visual_analysis_error",
                    severity=Severity.MEDIUM,
                    message=f"Visual analysis failed: {str(e)}",
                    location=url,
                    category="visual",
                    subcategory="analysis_error",
                    description="Visual analysis encountered an error",
                    impact="Cannot determine visual issues",
                    technical_details={"error": str(e)},
                    recommendations=["Check browser automation setup"],
                    code_location=CodeLocation(
                        resource_type="browser", attribute_value=url
                    ),
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_screenshot_detailed(self, screenshot_path: str) -> dict:
        """Analyze screenshot with detailed context and improvement suggestions."""
        metrics = {}
        raw = {}

        try:
            with Image.open(screenshot_path) as img:
                # Get image statistics
                stat = ImageStat.Stat(img)

                # Get dominant colors
                dominant_colors = await self._get_dominant_colors(img)

                # Calculate brightness and contrast
                brightness = sum(stat.mean) / 3
                contrast = max(stat.stddev) - min(stat.stddev)

                metrics.update({
                    "image_width": img.width,
                    "image_height": img.height,
                    "brightness": brightness,
                    "contrast": contrast,
                    "dominant_colors": len(dominant_colors),
                })

                raw["screenshot_stats"] = {
                    "dimensions": {"width": img.width, "height": img.height},
                    "brightness": brightness,
                    "contrast": contrast,
                    "dominant_colors": dominant_colors,
                    "file_size": Path(screenshot_path).stat().st_size,
                }

        except Exception as e:
            raw["screenshot_error"] = str(e)

        return {"metrics": metrics, "raw": raw}

    async def _check_visual_consistency_detailed(self, page, url: str) -> dict:
        """Check visual consistency with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        try:
            # Check for consistent spacing
            spacing_issues = []

            # Check for consistent font sizes
            font_sizes = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    const sizes = new Set();
                    elements.forEach(el => {
                        const style = window.getComputedStyle(el);
                        if (style.fontSize) {
                            sizes.add(style.fontSize);
                        }
                    });
                    return Array.from(sizes);
                }
            """)

            if len(font_sizes) > 10:
                spacing_issues.append("Too many different font sizes")
                issues.append(
                    self.create_detailed_issue(
                        issue_type="inconsistent_font_sizes",
                        severity=Severity.MEDIUM,
                        message=f"Inconsistent font sizes detected ({len(font_sizes)} different sizes)",
                        location=url,
                        category="visual",
                        subcategory="typography",
                        description="Page uses too many different font sizes, reducing visual consistency",
                        impact="Poor visual hierarchy and user experience",
                        technical_details={
                            "font_sizes_count": len(font_sizes),
                            "sample_sizes": font_sizes[:5],
                        },
                        recommendations=[
                            "Standardize font sizes for better consistency"
                        ],
                        fix_suggestions=[
                            "Use a limited set of font sizes (e.g., 12px, 14px, 16px, 18px, 24px)",
                            "Create a typography scale",
                            "Use CSS variables for font sizes",
                            "Apply consistent sizing across similar elements",
                        ],
                        code_location=CodeLocation(
                            element_selector="*",
                            resource_type="css",
                        ),
                        affected_elements=["*"],
                        priority_score=0.6,
                    )
                )

            # Check for consistent colors
            colors = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    const colors = new Set();
                    elements.forEach(el => {
                        const style = window.getComputedStyle(el);
                        if (style.color && style.color !== 'rgba(0, 0, 0, 0)') {
                            colors.add(style.color);
                        }
                        if (style.backgroundColor && style.backgroundColor !== 'rgba(0, 0, 0, 0)') {
                            colors.add(style.backgroundColor);
                        }
                    });
                    return Array.from(colors);
                }
            """)

            if len(colors) > 20:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="too_many_colors",
                        severity=Severity.MEDIUM,
                        message=f"Too many colors detected ({len(colors)})",
                        location=url,
                        category="visual",
                        subcategory="color_scheme",
                        description="Page uses too many different colors, reducing visual consistency",
                        impact="Poor visual cohesion and brand consistency",
                        technical_details={
                            "colors_count": len(colors),
                            "sample_colors": colors[:5],
                        },
                        recommendations=["Reduce color palette for better consistency"],
                        fix_suggestions=[
                            "Use a limited color palette (3-5 main colors)",
                            "Create a design system with defined colors",
                            "Use CSS variables for colors",
                            "Apply consistent colors across similar elements",
                        ],
                        code_location=CodeLocation(
                            element_selector="*",
                            resource_type="css",
                        ),
                        affected_elements=["*"],
                        priority_score=0.5,
                    )
                )

            metrics.update({
                "font_sizes_count": len(font_sizes),
                "colors_count": len(colors),
                "spacing_issues": len(spacing_issues),
            })

            raw["visual_consistency"] = {
                "font_sizes": font_sizes,
                "colors": colors,
                "spacing_issues": spacing_issues,
            }

        except Exception as e:
            raw["consistency_error"] = str(e)

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _check_layout_issues_detailed(self, page, url: str) -> dict:
        """Check layout issues with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        try:
            # Check for responsive design issues
            viewport_meta = await page.evaluate("""
                () => {
                    const viewport = document.querySelector('meta[name="viewport"]');
                    return viewport ? viewport.getAttribute('content') : null;
                }
            """)

            if not viewport_meta:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="missing_viewport_meta",
                        severity=Severity.MEDIUM,
                        message="Missing viewport meta tag",
                        location=url,
                        category="visual",
                        subcategory="responsive_design",
                        description="Page lacks viewport meta tag for proper mobile rendering",
                        impact="Poor mobile user experience",
                        technical_details={"viewport_meta": viewport_meta},
                        recommendations=["Add viewport meta tag for responsive design"],
                        fix_suggestions=[
                            'Add <meta name="viewport" content="width=device-width, initial-scale=1">',
                            "Test on different screen sizes",
                            "Use responsive CSS techniques",
                            "Implement mobile-first design",
                        ],
                        code_location=CodeLocation(
                            element_selector="meta[name='viewport']",
                            element_tag="meta",
                            resource_type="html",
                        ),
                        affected_elements=["meta"],
                        priority_score=0.7,
                    )
                )

            # Check for horizontal scrolling
            horizontal_scroll = await page.evaluate("""
                () => {
                    return document.documentElement.scrollWidth > document.documentElement.clientWidth;
                }
            """)

            if horizontal_scroll:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="horizontal_scrolling",
                        severity=Severity.MEDIUM,
                        message="Page has horizontal scrolling",
                        location=url,
                        category="visual",
                        subcategory="layout",
                        description="Page content extends beyond viewport width",
                        impact="Poor user experience and potential layout issues",
                        technical_details={"horizontal_scroll": horizontal_scroll},
                        recommendations=["Fix horizontal scrolling issues"],
                        fix_suggestions=[
                            "Use responsive CSS units (%, vw, vh)",
                            "Set max-width on containers",
                            "Use flexbox or grid for layouts",
                            "Test on different screen sizes",
                        ],
                        code_location=CodeLocation(
                            element_selector="body",
                            element_tag="body",
                            resource_type="html",
                        ),
                        affected_elements=["body", "div", "section"],
                        priority_score=0.6,
                    )
                )

            # Check for overlapping elements
            overlapping_elements = await page.evaluate("""
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

                    return overlapping.slice(0, 10); // Limit to first 10
                }
            """)

            if overlapping_elements:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="overlapping_elements",
                        severity=Severity.MEDIUM,
                        message=f"Overlapping elements detected ({len(overlapping_elements)})",
                        location=url,
                        category="visual",
                        subcategory="layout",
                        description="Page contains overlapping elements",
                        impact="Poor visual presentation and potential accessibility issues",
                        technical_details={
                            "overlapping_count": len(overlapping_elements),
                            "sample_overlaps": overlapping_elements[:3],
                        },
                        recommendations=["Fix overlapping elements"],
                        fix_suggestions=[
                            "Adjust element positioning",
                            "Use proper CSS layout techniques",
                            "Check z-index values",
                            "Test on different screen sizes",
                        ],
                        code_location=CodeLocation(
                            element_selector="*",
                            resource_type="css",
                        ),
                        affected_elements=["*"],
                        priority_score=0.5,
                    )
                )

            metrics.update({
                "has_viewport_meta": bool(viewport_meta),
                "horizontal_scroll": horizontal_scroll,
                "overlapping_elements": len(overlapping_elements),
            })

            raw["layout_analysis"] = {
                "viewport_meta": viewport_meta,
                "horizontal_scroll": horizontal_scroll,
                "overlapping_elements": overlapping_elements,
            }

        except Exception as e:
            raw["layout_error"] = str(e)

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_ui_elements_detailed(self, url: str) -> dict:
        """Analyze UI elements and their accessibility with detailed context."""
        issues = []
        metrics = {}
        raw = {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.content, "html.parser")

                # Analyze buttons and interactive elements
                button_analysis = await self._analyze_buttons_detailed(soup, url)
                issues.extend(button_analysis["issues"])
                metrics.update(button_analysis["metrics"])
                raw["buttons"] = button_analysis["raw"]

                # Analyze forms
                form_analysis = await self._analyze_forms_detailed(soup, url)
                issues.extend(form_analysis["issues"])
                metrics.update(form_analysis["metrics"])
                raw["forms"] = form_analysis["raw"]

                # Analyze navigation
                nav_analysis = await self._analyze_navigation_detailed(soup, url)
                issues.extend(nav_analysis["issues"])
                metrics.update(nav_analysis["metrics"])
                raw["navigation"] = nav_analysis["raw"]

                # Analyze images and media
                media_analysis = await self._analyze_media_elements_detailed(soup, url)
                issues.extend(media_analysis["issues"])
                metrics.update(media_analysis["metrics"])
                raw["media"] = media_analysis["raw"]

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="ui_analysis_error",
                    severity=Severity.MEDIUM,
                    message=f"UI analysis failed: {str(e)}",
                    location=url,
                    category="visual",
                    subcategory="analysis_error",
                    description="UI analysis encountered an error",
                    impact="Cannot determine UI issues",
                    technical_details={"error": str(e)},
                    recommendations=["Check page accessibility and try again"],
                    code_location=CodeLocation(
                        resource_type="http", attribute_value=url
                    ),
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_buttons_detailed(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze buttons with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        buttons = soup.find_all([
            "button",
            "input[type='button']",
            "input[type='submit']",
        ])
        button_issues = []

        for button in buttons:
            button_type = button.name
            button_text = button.get_text().strip() if button.get_text() else ""
            button_id = button.get("id", "")

            # Check for empty buttons
            if not button_text and not button_id:
                button_issues.append({
                    "type": button_type,
                    "issue": "Empty button without text or ID",
                })

        metrics.update({
            "button_count": len(buttons),
            "button_issues": len(button_issues),
        })

        raw["buttons"] = {
            "total": len(buttons),
            "issues": button_issues,
        }

        if button_issues:
            issues.append(
                self.create_detailed_issue(
                    issue_type="button_accessibility_issues",
                    severity=Severity.MEDIUM,
                    message=f"Button accessibility issues detected ({len(button_issues)})",
                    location=url,
                    category="visual",
                    subcategory="ui_elements",
                    description="Buttons have accessibility issues",
                    impact="Poor user experience for screen reader users",
                    technical_details={
                        "button_issues_count": len(button_issues),
                        "sample_issues": button_issues[:3],
                    },
                    recommendations=["Fix button accessibility issues"],
                    fix_suggestions=[
                        "Add descriptive text to buttons",
                        "Use aria-label for buttons without text",
                        "Ensure buttons have proper IDs",
                        "Test with screen readers",
                    ],
                    code_location=CodeLocation(
                        element_selector="button, input[type='button'], input[type='submit']",
                        resource_type="html",
                    ),
                    affected_elements=["button", "input"],
                    priority_score=0.6,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_forms_detailed(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze forms with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        forms = soup.find_all("form")
        form_issues = []

        for form in forms:
            form_id = form.get("id", "")
            form_action = form.get("action", "")

            # Check for missing form attributes
            if not form_id and not form_action:
                form_issues.append({
                    "issue": "Form without ID or action",
                })

        metrics.update({
            "form_count": len(forms),
            "form_issues": len(form_issues),
        })

        raw["forms"] = {
            "total": len(forms),
            "issues": form_issues,
        }

        if form_issues:
            issues.append(
                self.create_detailed_issue(
                    issue_type="form_accessibility_issues",
                    severity=Severity.MEDIUM,
                    message=f"Form accessibility issues detected ({len(form_issues)})",
                    location=url,
                    category="visual",
                    subcategory="ui_elements",
                    description="Forms have accessibility issues",
                    impact="Poor user experience for form interactions",
                    technical_details={
                        "form_issues_count": len(form_issues),
                        "sample_issues": form_issues[:3],
                    },
                    recommendations=["Fix form accessibility issues"],
                    fix_suggestions=[
                        "Add IDs to forms",
                        "Specify form actions",
                        "Use proper form methods",
                        "Add form labels and descriptions",
                    ],
                    code_location=CodeLocation(
                        element_selector="form",
                        element_tag="form",
                        resource_type="html",
                    ),
                    affected_elements=["form"],
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_navigation_detailed(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze navigation with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        nav_elements = soup.find_all("nav")
        navigation_issues = []

        for nav in nav_elements:
            nav_id = nav.get("id", "")
            nav_aria_label = nav.get("aria-label", "")

            # Check for missing navigation labels
            if not nav_id and not nav_aria_label:
                navigation_issues.append({
                    "issue": "Navigation without ID or aria-label",
                })

        metrics.update({
            "navigation_count": len(nav_elements),
            "navigation_issues": len(navigation_issues),
        })

        raw["navigation"] = {
            "total": len(nav_elements),
            "issues": navigation_issues,
        }

        if navigation_issues:
            issues.append(
                self.create_detailed_issue(
                    issue_type="navigation_accessibility_issues",
                    severity=Severity.MEDIUM,
                    message=f"Navigation accessibility issues detected ({len(navigation_issues)})",
                    location=url,
                    category="visual",
                    subcategory="ui_elements",
                    description="Navigation elements have accessibility issues",
                    impact="Poor navigation experience for screen reader users",
                    technical_details={
                        "navigation_issues_count": len(navigation_issues),
                        "sample_issues": navigation_issues[:3],
                    },
                    recommendations=["Fix navigation accessibility issues"],
                    fix_suggestions=[
                        "Add IDs to navigation elements",
                        "Use aria-label for navigation",
                        "Add proper navigation roles",
                        "Test with screen readers",
                    ],
                    code_location=CodeLocation(
                        element_selector="nav",
                        element_tag="nav",
                        resource_type="html",
                    ),
                    affected_elements=["nav"],
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_media_elements_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze media elements with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        images = soup.find_all("img")
        videos = soup.find_all("video")
        media_issues = []

        for img in images:
            src = img.get("src", "")
            alt = img.get("alt", "")

            # Check for missing alt text
            if not alt:
                media_issues.append({
                    "type": "image",
                    "issue": "Missing alt text",
                    "src": src,
                })

        for video in videos:
            controls = video.get("controls")
            if not controls:
                media_issues.append({
                    "type": "video",
                    "issue": "Missing controls",
                })

        metrics.update({
            "image_count": len(images),
            "video_count": len(videos),
            "media_issues": len(media_issues),
        })

        raw["media"] = {
            "images": len(images),
            "videos": len(videos),
            "issues": media_issues,
        }

        if media_issues:
            issues.append(
                self.create_detailed_issue(
                    issue_type="media_accessibility_issues",
                    severity=Severity.MEDIUM,
                    message=f"Media accessibility issues detected ({len(media_issues)})",
                    location=url,
                    category="visual",
                    subcategory="ui_elements",
                    description="Media elements have accessibility issues",
                    impact="Poor experience for users with disabilities",
                    technical_details={
                        "media_issues_count": len(media_issues),
                        "sample_issues": media_issues[:3],
                    },
                    recommendations=["Fix media accessibility issues"],
                    fix_suggestions=[
                        "Add alt text to all images",
                        "Add controls to videos",
                        "Provide captions for videos",
                        "Use descriptive file names",
                    ],
                    code_location=CodeLocation(
                        element_selector="img, video",
                        resource_type="html",
                    ),
                    affected_elements=["img", "video"],
                    priority_score=0.6,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_color_scheme_detailed(self, url: str) -> dict:
        """Analyze color scheme and contrast with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.content, "html.parser")

                # Extract CSS and analyze colors
                color_analysis = await self._extract_color_scheme_detailed(soup, url)
                issues.extend(color_analysis["issues"])
                metrics.update(color_analysis["metrics"])
                raw["color_scheme"] = color_analysis["raw"]

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="color_analysis_error",
                    severity=Severity.LOW,
                    message=f"Color analysis failed: {str(e)}",
                    location=url,
                    category="visual",
                    subcategory="analysis_error",
                    description="Color analysis encountered an error",
                    impact="Cannot determine color scheme issues",
                    technical_details={"error": str(e)},
                    recommendations=["Check page accessibility and try again"],
                    code_location=CodeLocation(
                        resource_type="http", attribute_value=url
                    ),
                    priority_score=0.3,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _extract_color_scheme_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Extract color scheme with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        # Extract inline styles and analyze colors
        elements_with_style = soup.find_all(attrs={"style": True})
        color_issues = []
        color_palette = set()

        for element in elements_with_style:
            style = element.get("style", "")

            # Extract color values (simplified)
            if "color:" in style or "background-color:" in style:
                # This is a simplified color extraction
                # In a real implementation, you would use a proper CSS parser
                color_palette.add("extracted_color")

        metrics.update({
            "color_palette_size": len(color_palette),
            "color_contrast_issues": len(color_issues),
        })

        raw["color_analysis"] = {
            "color_palette": list(color_palette),
            "color_issues": color_issues,
        }

        if len(color_palette) > 15:
            issues.append(
                self.create_detailed_issue(
                    issue_type="too_many_colors",
                    severity=Severity.LOW,
                    message=f"Too many colors in palette ({len(color_palette)})",
                    location=url,
                    category="visual",
                    subcategory="color_scheme",
                    description="Page uses too many different colors",
                    impact="Poor visual consistency and brand cohesion",
                    technical_details={
                        "color_palette_size": len(color_palette),
                        "recommended_max": 15,
                    },
                    recommendations=["Reduce color palette for better consistency"],
                    fix_suggestions=[
                        "Use a limited color palette (3-7 main colors)",
                        "Create a design system",
                        "Use CSS variables for colors",
                        "Apply consistent colors across elements",
                    ],
                    code_location=CodeLocation(
                        element_selector="[style]",
                        resource_type="css",
                    ),
                    affected_elements=["*"],
                    priority_score=0.4,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_responsiveness(
        self, screenshot_analyses: dict, url: str
    ) -> dict:
        """Analyze responsiveness by comparing screenshots."""
        issues = []
        metrics = {}
        raw = {}

        try:
            # Check for inconsistent image sizes
            image_sizes = set()
            for analysis in screenshot_analyses.values():
                image_sizes.add(
                    f"{analysis['metrics']['image_width']}x{analysis['metrics']['image_height']}"
                )

            if len(image_sizes) > 1:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="inconsistent_image_sizes",
                        severity=Severity.MEDIUM,
                        message=f"Found {len(image_sizes)} different image sizes",
                        location=url,
                        category="visual",
                        subcategory="responsiveness",
                        description="Page contains images with different dimensions",
                        impact="Poor visual consistency and potential layout issues",
                        technical_details={
                            "image_sizes": list(image_sizes),
                        },
                        recommendations=["Ensure consistent image dimensions"],
                        fix_suggestions=[
                            "Resize images to a consistent size",
                            "Use responsive images",
                            "Implement image optimization",
                        ],
                        code_location=CodeLocation(
                            element_selector="img",
                            resource_type="html",
                        ),
                        affected_elements=["img"],
                        priority_score=0.5,
                    )
                )

            metrics.update({
                "image_sizes_count": len(image_sizes),
            })

            raw["responsiveness_analysis"] = {
                "image_sizes": list(image_sizes),
            }

        except Exception as e:
            raw["responsiveness_error"] = str(e)

        return {"issues": issues, "metrics": metrics, "raw": raw}
