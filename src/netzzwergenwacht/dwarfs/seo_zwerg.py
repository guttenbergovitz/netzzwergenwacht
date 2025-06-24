"""SEO-Zwerg for search engine optimization analysis."""

import json
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from .base import AnalysisResult, Dwarf, Severity


class SEOZwerg(Dwarf):
    """SEO-Zwerg - Analyzes websites for search engine optimization and social media presence."""

    def __init__(self):
        super().__init__(
            name="SEO-Zwerg",
            description="SEO analysis for meta tags, structured data and social media optimization",
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
