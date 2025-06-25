"""SEO-Zwerg for search engine optimization analysis."""

import json
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from .base import (
    AnalysisResult,
    CodeLocation,
    DetailedAnalysisResult,
    Dwarf,
    SEOMetrics,
    Severity,
)


class SEOZwerg(Dwarf):
    """SEO-Zwerg - Analyzes websites for search engine optimization and social media presence."""

    def __init__(self):
        super().__init__(
            name="SEO-Zwerg",
            description="SEO analysis for meta tags, structured data and social media optimization",
        )

    def _get_category(self) -> str:
        """Get the category for this dwarf's issues."""
        return "seo"

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL for SEO issues with detailed location information."""
        try:
            detailed_issues = []
            seo_metrics = SEOMetrics()

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="invalid_url_scheme",
                        severity=Severity.HIGH,
                        message="URL must start with http:// or https://",
                        location=url,
                        category="seo",
                        subcategory="url_structure",
                        description="The provided URL does not use a valid HTTP scheme",
                        impact="This prevents proper SEO analysis and may affect search engine indexing",
                        technical_details={"provided_url": url},
                        recommendations=["Use HTTPS URLs for better SEO and security"],
                        fix_suggestions=[
                            f"Change URL from '{url}' to 'https://{url.replace('http://', '').replace('https://', '')}'"
                        ],
                        priority_score=0.9,
                    )
                )
                return DetailedAnalysisResult(
                    url=url,
                    dwarf_name=self.name,
                    detailed_issues=detailed_issues,
                    seo_metrics=seo_metrics,
                )

            # Perform detailed SEO analysis
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
                                category="seo",
                                subcategory="page_accessibility",
                                description=f"The page is not accessible with status code {response.status_code}",
                                impact="This prevents search engines from indexing the page properly",
                                technical_details={"status_code": response.status_code},
                                recommendations=[
                                    "Fix the server error or redirect issue"
                                ],
                                priority_score=0.8,
                            )
                        )
                        return DetailedAnalysisResult(
                            url=url,
                            dwarf_name=self.name,
                            detailed_issues=detailed_issues,
                            seo_metrics=seo_metrics,
                        )

                    # Parse HTML content
                    soup = BeautifulSoup(response.content, "html.parser")

                    # Analyze meta tags with detailed location
                    meta_analysis = await self._analyze_meta_tags_detailed(soup, url)
                    detailed_issues.extend(meta_analysis["issues"])
                    seo_metrics = meta_analysis["metrics"]

                    # Analyze Open Graph and Twitter Cards
                    social_analysis = await self._analyze_social_meta_detailed(
                        soup, url
                    )
                    detailed_issues.extend(social_analysis["issues"])

                    # Analyze structured data
                    structured_data_analysis = (
                        await self._analyze_structured_data_detailed(soup, url)
                    )
                    detailed_issues.extend(structured_data_analysis["issues"])

                    # Analyze canonical URLs and links
                    link_analysis = await self._analyze_links_detailed(soup, url)
                    detailed_issues.extend(link_analysis["issues"])

                    # Analyze content quality
                    content_analysis = await self._analyze_content_quality_detailed(
                        soup, url
                    )
                    detailed_issues.extend(content_analysis["issues"])

                except httpx.RequestError as e:
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="seo_analysis_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to analyze SEO: {str(e)}",
                            location=url,
                            category="seo",
                            subcategory="analysis_error",
                            description="The SEO analysis failed due to a network or request error",
                            impact="Unable to identify SEO issues on this page",
                            technical_details={"error": str(e)},
                            recommendations=[
                                "Check network connectivity and try again"
                            ],
                            priority_score=0.7,
                        )
                    )

            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                detailed_issues=detailed_issues,
                seo_metrics=seo_metrics,
            )

        except Exception as e:
            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                success=False,
                error_message=str(e),
            )

    async def _analyze_meta_tags_detailed(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze meta tags for SEO optimization with detailed location information."""
        issues = []
        metrics = SEOMetrics()

        # Title tag analysis with detailed location
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            title = title_tag.string.strip()
            title_length = len(title)

            metrics.title_length = title_length

            # Get detailed location information
            title_location = self._get_element_location(title_tag, "title")

            if title_length == 0:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="empty_title",
                        severity=Severity.HIGH,
                        message="Title tag is empty",
                        location=url,
                        category="seo",
                        subcategory="meta_tags",
                        description="The title tag exists but contains no text",
                        impact="This severely impacts SEO as search engines rely heavily on title tags",
                        technical_details={"title_length": title_length},
                        recommendations=["Add descriptive text to the title tag"],
                        fix_suggestions=[
                            "<title>Your Page Title Here</title>",
                            f"<title>Add a descriptive title for {urlparse(url).netloc}</title>",
                        ],
                        code_location=title_location,
                        affected_elements=["title"],
                        priority_score=0.95,
                    )
                )
            elif title_length < 30:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="title_too_short",
                        severity=Severity.MEDIUM,
                        message=f"Title is too short ({title_length} chars, recommended: 30-60)",
                        location=url,
                        category="seo",
                        subcategory="meta_tags",
                        description="The title tag is too short for optimal SEO",
                        impact="Short titles may not provide enough context for search engines and users",
                        technical_details={
                            "title_length": title_length,
                            "title": title,
                        },
                        recommendations=["Expand the title to be more descriptive"],
                        fix_suggestions=[
                            f"<title>{title} - Additional Context Here</title>",
                            f"<title>More Descriptive Title for {urlparse(url).netloc}</title>",
                        ],
                        code_location=title_location,
                        affected_elements=["title"],
                        priority_score=0.6,
                    )
                )
            elif title_length > 60:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="title_too_long",
                        severity=Severity.MEDIUM,
                        message=f"Title is too long ({title_length} chars, recommended: 30-60)",
                        location=url,
                        category="seo",
                        subcategory="meta_tags",
                        description="The title tag is too long and may be truncated in search results",
                        impact="Long titles may be cut off in search engine results pages",
                        technical_details={
                            "title_length": title_length,
                            "title": title,
                        },
                        recommendations=[
                            "Shorten the title to fit within recommended length"
                        ],
                        fix_suggestions=[
                            f"<title>{title[:50]}...</title>",
                            "<title>Shorter, More Concise Title</title>",
                        ],
                        code_location=title_location,
                        affected_elements=["title"],
                        priority_score=0.5,
                    )
                )
        else:
            # Find the head tag to provide context
            head_tag = soup.find("head")
            head_location = (
                self._get_element_location(head_tag, "head") if head_tag else None
            )

            issues.append(
                self.create_detailed_issue(
                    issue_type="missing_title",
                    severity=Severity.CRITICAL,
                    message="Page is missing title tag",
                    location=url,
                    category="seo",
                    subcategory="meta_tags",
                    description="The page does not have a title tag in the HTML head",
                    impact="This is critical for SEO as search engines cannot properly index the page",
                    technical_details={},
                    recommendations=["Add a title tag to the HTML head section"],
                    fix_suggestions=[
                        "<head><title>Your Page Title</title>...</head>",
                        "<title>Descriptive Title for Your Page</title>",
                    ],
                    code_location=head_location,
                    affected_elements=["head", "title"],
                    priority_score=1.0,
                )
            )

        # Meta description analysis with detailed location
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            description = meta_desc.get("content").strip()
            desc_length = len(description)

            metrics.description_length = desc_length

            # Get detailed location information
            desc_location = self._get_element_location(
                meta_desc, "meta[name='description']"
            )

            if desc_length < 120:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="meta_description_too_short",
                        severity=Severity.MEDIUM,
                        message=f"Meta description is too short ({desc_length} chars, recommended: 120-160)",
                        location=url,
                        category="seo",
                        subcategory="meta_tags",
                        description="The meta description is too short for optimal SEO",
                        impact="Short descriptions may not provide enough information in search results",
                        technical_details={
                            "description_length": desc_length,
                            "description": description,
                        },
                        recommendations=[
                            "Expand the meta description to be more descriptive"
                        ],
                        fix_suggestions=[
                            f'<meta name="description" content="{description} - Additional context and details about this page...">',
                            '<meta name="description" content="A comprehensive description of what this page offers to users...">',
                        ],
                        code_location=desc_location,
                        affected_elements=["meta[name='description']"],
                        priority_score=0.5,
                    )
                )
            elif desc_length > 160:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="meta_description_too_long",
                        severity=Severity.LOW,
                        message=f"Meta description is too long ({desc_length} chars, recommended: 120-160)",
                        location=url,
                        category="seo",
                        subcategory="meta_tags",
                        description="The meta description is too long and may be truncated",
                        impact="Long descriptions may be cut off in search engine results",
                        technical_details={
                            "description_length": desc_length,
                            "description": description,
                        },
                        recommendations=[
                            "Shorten the meta description to fit within recommended length"
                        ],
                        fix_suggestions=[
                            f'<meta name="description" content="{description[:150]}...">',
                            '<meta name="description" content="Shorter, more concise description...">',
                        ],
                        code_location=desc_location,
                        affected_elements=["meta[name='description']"],
                        priority_score=0.3,
                    )
                )
        else:
            # Find the head tag to provide context
            head_tag = soup.find("head")
            head_location = (
                self._get_element_location(head_tag, "head") if head_tag else None
            )

            issues.append(
                self.create_detailed_issue(
                    issue_type="missing_meta_description",
                    severity=Severity.HIGH,
                    message="Page is missing meta description",
                    location=url,
                    category="seo",
                    subcategory="meta_tags",
                    description="The page does not have a meta description tag",
                    impact="Search engines may not display proper descriptions in search results",
                    technical_details={},
                    recommendations=[
                        "Add a meta description tag to the HTML head section"
                    ],
                    fix_suggestions=[
                        '<meta name="description" content="A descriptive summary of this page content">',
                        '<meta name="description" content="What users can expect to find on this page">',
                    ],
                    code_location=head_location,
                    affected_elements=["head", "meta[name='description']"],
                    priority_score=0.8,
                )
            )

        return {"issues": issues, "metrics": metrics}

    def _get_element_location(self, element, element_type: str) -> CodeLocation | None:
        """Get detailed location information for an HTML element."""
        if not element:
            return None

        # Get the parent elements for context
        parent = element.parent

        # Build context strings
        context_before = ""
        context_after = ""

        if parent:
            # Get siblings for context
            siblings = list(parent.children)
            try:
                element_index = siblings.index(element)
                if element_index > 0:
                    context_before = str(siblings[element_index - 1])[:100]
                if element_index < len(siblings) - 1:
                    context_after = str(siblings[element_index + 1])[:100]
            except ValueError:
                pass

        return CodeLocation(
            element_selector=element_type,
            element_tag=element.name,
            element_id=element.get("id"),
            element_class=element.get("class", [""])[0]
            if element.get("class")
            else None,
            attribute_name=list(element.attrs.keys())[0] if element.attrs else None,
            attribute_value=list(element.attrs.values())[0] if element.attrs else None,
            context_before=context_before,
            context_after=context_after,
            full_element=str(element)[:500],  # Limit to 500 chars
            resource_type="html",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL for SEO issues."""
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

            # Perform SEO analysis
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

                    # Analyze meta tags
                    meta_analysis = await self._analyze_meta_tags(soup, url)
                    issues.extend(meta_analysis["issues"])
                    metadata.update(meta_analysis["metadata"])

                    # Analyze Open Graph and Twitter Cards
                    social_analysis = await self._analyze_social_meta(soup, url)
                    issues.extend(social_analysis["issues"])
                    metadata.update(social_analysis["metadata"])

                    # Analyze structured data
                    structured_data_analysis = await self._analyze_structured_data(
                        soup, url
                    )
                    issues.extend(structured_data_analysis["issues"])
                    metadata.update(structured_data_analysis["metadata"])

                    # Analyze canonical URLs and links
                    link_analysis = await self._analyze_links(soup, url)
                    issues.extend(link_analysis["issues"])
                    metadata.update(link_analysis["metadata"])

                    # Analyze content quality
                    content_analysis = await self._analyze_content_quality(soup, url)
                    issues.extend(content_analysis["issues"])
                    metadata.update(content_analysis["metadata"])

                except httpx.RequestError as e:
                    issues.append(
                        self.create_issue(
                            issue_type="seo_analysis_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to analyze SEO: {str(e)}",
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

    async def _analyze_meta_tags(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze meta tags for SEO optimization."""
        issues = []
        metadata = {}

        # Title tag analysis
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            title = title_tag.string.strip()
            title_length = len(title)

            metadata.update({
                "title": title,
                "title_length": title_length,
            })

            # Title length recommendations
            if title_length == 0:
                issues.append(
                    self.create_issue(
                        issue_type="empty_title",
                        severity=Severity.HIGH,
                        message="Title tag is empty",
                        location=url,
                        evidence={"title_length": title_length},
                    )
                )
            elif title_length < 30:
                issues.append(
                    self.create_issue(
                        issue_type="title_too_short",
                        severity=Severity.MEDIUM,
                        message=f"Title is too short ({title_length} chars, recommended: 30-60)",
                        location=url,
                        evidence={"title_length": title_length, "title": title},
                    )
                )
            elif title_length > 60:
                issues.append(
                    self.create_issue(
                        issue_type="title_too_long",
                        severity=Severity.MEDIUM,
                        message=f"Title is too long ({title_length} chars, recommended: 30-60)",
                        location=url,
                        evidence={"title_length": title_length, "title": title},
                    )
                )
            else:
                metadata["title_rating"] = "good"
        else:
            issues.append(
                self.create_issue(
                    issue_type="missing_title",
                    severity=Severity.CRITICAL,
                    message="Page is missing title tag",
                    location=url,
                    evidence={},
                )
            )

        # Meta description analysis
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            description = meta_desc.get("content").strip()
            desc_length = len(description)

            metadata.update({
                "meta_description": description,
                "meta_description_length": desc_length,
            })

            if desc_length < 120:
                issues.append(
                    self.create_issue(
                        issue_type="meta_description_too_short",
                        severity=Severity.MEDIUM,
                        message=f"Meta description is too short ({desc_length} chars, recommended: 120-160)",
                        location=url,
                        evidence={
                            "description_length": desc_length,
                            "description": description,
                        },
                    )
                )
            elif desc_length > 160:
                issues.append(
                    self.create_issue(
                        issue_type="meta_description_too_long",
                        severity=Severity.MEDIUM,
                        message=f"Meta description is too long ({desc_length} chars, recommended: 120-160)",
                        location=url,
                        evidence={
                            "description_length": desc_length,
                            "description": description,
                        },
                    )
                )
            else:
                metadata["meta_description_rating"] = "good"
        else:
            issues.append(
                self.create_issue(
                    issue_type="missing_meta_description",
                    severity=Severity.HIGH,
                    message="Page is missing meta description",
                    location=url,
                    evidence={},
                )
            )

        # Meta keywords (generally not recommended anymore)
        meta_keywords = soup.find("meta", attrs={"name": "keywords"})
        if meta_keywords:
            issues.append(
                self.create_issue(
                    issue_type="meta_keywords_present",
                    severity=Severity.LOW,
                    message="Meta keywords tag is present (not recommended by search engines)",
                    location=url,
                    evidence={"keywords": meta_keywords.get("content", "")},
                )
            )

        # Viewport meta tag (mobile SEO)
        viewport_meta = soup.find("meta", attrs={"name": "viewport"})
        if viewport_meta:
            metadata["viewport_meta"] = viewport_meta.get("content", "")
            metadata["mobile_optimized"] = True
        else:
            issues.append(
                self.create_issue(
                    issue_type="missing_viewport_meta",
                    severity=Severity.MEDIUM,
                    message="Missing viewport meta tag (important for mobile SEO)",
                    location=url,
                    evidence={},
                )
            )

        # Robots meta tag
        robots_meta = soup.find("meta", attrs={"name": "robots"})
        if robots_meta:
            robots_content = robots_meta.get("content", "").lower()
            metadata["robots_meta"] = robots_content

            if "noindex" in robots_content:
                issues.append(
                    self.create_issue(
                        issue_type="page_set_to_noindex",
                        severity=Severity.HIGH,
                        message="Page is set to noindex (will not be indexed by search engines)",
                        location=url,
                        evidence={"robots_content": robots_content},
                    )
                )

            if "nofollow" in robots_content:
                issues.append(
                    self.create_issue(
                        issue_type="page_set_to_nofollow",
                        severity=Severity.MEDIUM,
                        message="Page is set to nofollow (links will not be followed)",
                        location=url,
                        evidence={"robots_content": robots_content},
                    )
                )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_social_meta(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze Open Graph and Twitter Card meta tags."""
        issues = []
        metadata = {}

        # Open Graph analysis
        og_tags = {}
        for meta in soup.find_all("meta"):
            property_attr = meta.get("property", "")
            if property_attr.startswith("og:"):
                og_tags[property_attr] = meta.get("content", "")

        metadata["open_graph_tags"] = og_tags
        metadata["open_graph_count"] = len(og_tags)

        # Essential OG tags
        essential_og = ["og:title", "og:description", "og:image", "og:url"]
        missing_og = [tag for tag in essential_og if tag not in og_tags]

        if missing_og:
            issues.append(
                self.create_issue(
                    issue_type="missing_open_graph_tags",
                    severity=Severity.MEDIUM,
                    message=f"Missing essential Open Graph tags: {', '.join(missing_og)}",
                    location=url,
                    evidence={
                        "missing_tags": missing_og,
                        "present_tags": list(og_tags.keys()),
                    },
                )
            )
        else:
            metadata["open_graph_complete"] = True

        # Twitter Card analysis
        twitter_tags = {}
        for meta in soup.find_all("meta"):
            name_attr = meta.get("name", "")
            if name_attr.startswith("twitter:"):
                twitter_tags[name_attr] = meta.get("content", "")

        metadata["twitter_card_tags"] = twitter_tags
        metadata["twitter_card_count"] = len(twitter_tags)

        if not twitter_tags:
            issues.append(
                self.create_issue(
                    issue_type="missing_twitter_cards",
                    severity=Severity.LOW,
                    message="No Twitter Card tags found",
                    location=url,
                    evidence={},
                )
            )
        else:
            # Check for essential Twitter Card tags
            if "twitter:card" not in twitter_tags:
                issues.append(
                    self.create_issue(
                        issue_type="missing_twitter_card_type",
                        severity=Severity.LOW,
                        message="Twitter Card type not specified",
                        location=url,
                        evidence={"present_tags": list(twitter_tags.keys())},
                    )
                )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_structured_data(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze structured data (JSON-LD, microdata)."""
        issues = []
        metadata = {}

        # JSON-LD analysis
        json_ld_scripts = soup.find_all("script", type="application/ld+json")
        json_ld_data = []

        for script in json_ld_scripts:
            try:
                if script.string:
                    data = json.loads(script.string)
                    json_ld_data.append(data)
            except json.JSONDecodeError:
                issues.append(
                    self.create_issue(
                        issue_type="invalid_json_ld",
                        severity=Severity.LOW,
                        message="Invalid JSON-LD structured data found",
                        location=url,
                        evidence={
                            "invalid_json": script.string[:200] if script.string else ""
                        },
                    )
                )

        metadata["json_ld_count"] = len(json_ld_data)
        metadata["json_ld_types"] = []

        for data in json_ld_data:
            if isinstance(data, dict) and "@type" in data:
                metadata["json_ld_types"].append(data["@type"])

        # Microdata analysis
        microdata_items = soup.find_all(attrs={"itemscope": True})
        microdata_types = []

        for item in microdata_items:
            itemtype = item.get("itemtype", "")
            if itemtype:
                microdata_types.append(itemtype)

        metadata["microdata_count"] = len(microdata_items)
        metadata["microdata_types"] = microdata_types

        # Overall structured data assessment
        total_structured_data = len(json_ld_data) + len(microdata_items)
        metadata["total_structured_data"] = total_structured_data

        if total_structured_data == 0:
            issues.append(
                self.create_issue(
                    issue_type="no_structured_data",
                    severity=Severity.LOW,
                    message="No structured data found (JSON-LD or microdata)",
                    location=url,
                    evidence={},
                )
            )
        else:
            metadata["structured_data_present"] = True

        return {"issues": issues, "metadata": metadata}

    async def _analyze_links(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze canonical URLs and link structure."""
        issues = []
        metadata = {}

        # Canonical URL analysis
        canonical_link = soup.find("link", rel="canonical")
        if canonical_link:
            canonical_url = canonical_link.get("href", "")
            metadata["canonical_url"] = canonical_url

            # Check if canonical URL is absolute
            if not canonical_url.startswith(("http://", "https://")):
                issues.append(
                    self.create_issue(
                        issue_type="relative_canonical_url",
                        severity=Severity.MEDIUM,
                        message="Canonical URL should be absolute",
                        location=url,
                        evidence={"canonical_url": canonical_url},
                    )
                )

            # Check if canonical URL points to current page
            parsed_current = urlparse(url)
            parsed_canonical = urlparse(canonical_url)

            if (
                parsed_canonical.netloc
                and parsed_canonical.netloc != parsed_current.netloc
            ):
                issues.append(
                    self.create_issue(
                        issue_type="canonical_points_external",
                        severity=Severity.HIGH,
                        message="Canonical URL points to external domain",
                        location=url,
                        evidence={
                            "current_domain": parsed_current.netloc,
                            "canonical_domain": parsed_canonical.netloc,
                        },
                    )
                )
        else:
            issues.append(
                self.create_issue(
                    issue_type="missing_canonical_url",
                    severity=Severity.MEDIUM,
                    message="Missing canonical URL",
                    location=url,
                    evidence={},
                )
            )

        # Hreflang analysis
        hreflang_links = soup.find_all("link", rel="alternate", hreflang=True)
        if hreflang_links:
            hreflang_data = []
            for link in hreflang_links:
                hreflang_data.append({
                    "hreflang": link.get("hreflang"),
                    "href": link.get("href"),
                })
            metadata["hreflang_tags"] = hreflang_data
            metadata["hreflang_count"] = len(hreflang_data)

        return {"issues": issues, "metadata": metadata}

    async def _analyze_content_quality(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze content quality and structure."""
        issues = []
        metadata = {}

        # Heading structure analysis
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        heading_structure = {}

        for heading in headings:
            tag = heading.name
            text = heading.get_text(strip=True)
            if tag not in heading_structure:
                heading_structure[tag] = []
            heading_structure[tag].append(text)

        metadata["heading_structure"] = heading_structure

        # H1 analysis
        h1_tags = heading_structure.get("h1", [])
        metadata["h1_count"] = len(h1_tags)

        if len(h1_tags) == 0:
            issues.append(
                self.create_issue(
                    issue_type="missing_h1",
                    severity=Severity.HIGH,
                    message="Page is missing H1 tag",
                    location=url,
                    evidence={},
                )
            )
        elif len(h1_tags) > 1:
            issues.append(
                self.create_issue(
                    issue_type="multiple_h1_tags",
                    severity=Severity.MEDIUM,
                    message=f"Multiple H1 tags found ({len(h1_tags)}), should be only one",
                    location=url,
                    evidence={"h1_tags": h1_tags},
                )
            )
        else:
            h1_text = h1_tags[0]
            metadata["h1_text"] = h1_text
            metadata["h1_length"] = len(h1_text)

            if len(h1_text) < 10:
                issues.append(
                    self.create_issue(
                        issue_type="h1_too_short",
                        severity=Severity.LOW,
                        message=f"H1 tag is very short ({len(h1_text)} chars)",
                        location=url,
                        evidence={"h1_text": h1_text, "h1_length": len(h1_text)},
                    )
                )

        # Content length analysis
        # Remove script and style content
        for script in soup(["script", "style"]):
            script.decompose()

        text_content = soup.get_text()
        words = text_content.split()
        word_count = len(words)
        char_count = len(text_content.strip())

        metadata.update({
            "word_count": word_count,
            "character_count": char_count,
        })

        if word_count < 300:
            issues.append(
                self.create_issue(
                    issue_type="thin_content",
                    severity=Severity.MEDIUM,
                    message=f"Page has thin content ({word_count} words, recommended: 300+)",
                    location=url,
                    evidence={"word_count": word_count},
                )
            )
        else:
            metadata["content_length_rating"] = (
                "good" if word_count >= 600 else "adequate"
            )

        # Image alt text analysis (SEO perspective)
        images = soup.find_all("img")
        images_without_alt = []
        total_images = len(images)

        for img in images:
            alt = img.get("alt", "")
            src = img.get("src", "")
            if not alt and src:
                images_without_alt.append(src)

        metadata.update({
            "total_images": total_images,
            "images_without_alt": len(images_without_alt),
        })

        if (
            images_without_alt and len(images_without_alt) > total_images * 0.2
        ):  # >20% missing alt
            issues.append(
                self.create_issue(
                    issue_type="many_images_missing_alt",
                    severity=Severity.MEDIUM,
                    message=f"Many images missing alt text ({len(images_without_alt)}/{total_images})",
                    location=url,
                    evidence={
                        "missing_alt_count": len(images_without_alt),
                        "total_images": total_images,
                        "percentage": round(
                            (len(images_without_alt) / total_images) * 100, 1
                        ),
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_social_meta_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze social media meta tags with detailed location information."""
        # TODO: Implement detailed social meta analysis
        return {"issues": []}

    async def _analyze_structured_data_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze structured data with detailed location information."""
        # TODO: Implement detailed structured data analysis
        return {"issues": []}

    async def _analyze_links_detailed(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze links and canonical URLs with detailed location information."""
        # TODO: Implement detailed link analysis
        return {"issues": []}

    async def _analyze_content_quality_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze content quality with detailed location information."""
        # TODO: Implement detailed content quality analysis
        return {"issues": []}
