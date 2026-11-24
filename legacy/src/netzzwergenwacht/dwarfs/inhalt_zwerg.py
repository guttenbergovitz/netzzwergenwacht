"""Inhalt-Zwerg for comprehensive content quality analysis."""

import re
from collections import Counter

import httpx
from bs4 import BeautifulSoup

from .base import (
    AnalysisResult,
    CodeLocation,
    ContentMetrics,
    DetailedAnalysisResult,
    Dwarf,
    Severity,
)


class InhaltZwerg(Dwarf):
    """Inhalt-Zwerg - Analyzes websites for content quality, readability, and linguistic issues."""

    def __init__(self):
        super().__init__(
            name="Inhalt-Zwerg",
            description="Content quality analysis including readability, grammar, and content metrics",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL for content quality."""
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

            # Perform content analysis
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

                    # Content Quality Analysis

                    # 1. Text Content Extraction and Basic Metrics
                    content_metrics = await self._analyze_content_metrics(soup, url)
                    issues.extend(content_metrics["issues"])
                    metadata.update(content_metrics["metadata"])

                    # 2. Readability Analysis
                    readability = await self._analyze_readability(soup, url)
                    issues.extend(readability["issues"])
                    metadata.update(readability["metadata"])

                    # 3. Content Structure Analysis
                    structure = await self._analyze_content_structure(soup, url)
                    issues.extend(structure["issues"])
                    metadata.update(structure["metadata"])

                    # 4. Language Quality Analysis
                    language_quality = await self._analyze_language_quality(soup, url)
                    issues.extend(language_quality["issues"])
                    metadata.update(language_quality["metadata"])

                    # 5. Duplicate Content Detection
                    duplicate_content = await self._analyze_duplicate_content(soup, url)
                    issues.extend(duplicate_content["issues"])
                    metadata.update(duplicate_content["metadata"])

                    # 6. Content Freshness and Metadata
                    freshness = await self._analyze_content_freshness(soup, url)
                    issues.extend(freshness["issues"])
                    metadata.update(freshness["metadata"])

                except httpx.RequestError as e:
                    issues.append(
                        self.create_issue(
                            issue_type="content_analysis_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to analyze content: {str(e)}",
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

    async def _analyze_content_metrics(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze basic content metrics and quality indicators."""
        issues = []
        metadata = {}

        # Extract text content from body
        body = soup.find("body")
        if not body:
            issues.append(
                self.create_issue(
                    issue_type="missing_body_element",
                    severity=Severity.HIGH,
                    message="Page is missing body element",
                    location=url,
                    evidence={
                        "recommendation": "Ensure HTML has proper body structure"
                    },
                )
            )
            return {"issues": issues, "metadata": metadata}

        # Get all text content, excluding script and style tags
        for element in body(["script", "style", "nav", "header", "footer"]):
            element.decompose()

        text_content = body.get_text(strip=True, separator=" ")

        # Basic metrics
        word_count = len(text_content.split()) if text_content else 0
        char_count = len(text_content)
        char_count_no_spaces = len(text_content.replace(" ", ""))
        sentence_count = len(re.findall(r"[.!?]+", text_content)) if text_content else 0
        paragraph_count = len(soup.find_all("p"))

        metadata.update({
            "word_count": word_count,
            "character_count": char_count,
            "character_count_no_spaces": char_count_no_spaces,
            "sentence_count": sentence_count,
            "paragraph_count": paragraph_count,
        })

        # Content quality issues
        if word_count < 100:
            issues.append(
                self.create_issue(
                    issue_type="very_thin_content",
                    severity=Severity.HIGH,
                    message=f"Very thin content detected ({word_count} words, minimum recommended: 100)",
                    location=url,
                    evidence={
                        "word_count": word_count,
                        "recommendation": "Add more substantive content to improve value for users and SEO",
                    },
                )
            )
        elif word_count < 300:
            issues.append(
                self.create_issue(
                    issue_type="thin_content",
                    severity=Severity.MEDIUM,
                    message=f"Thin content detected ({word_count} words, recommended: 300+)",
                    location=url,
                    evidence={
                        "word_count": word_count,
                        "recommendation": "Consider expanding content for better user experience",
                    },
                )
            )

        # Check for content that's mostly repetitive
        if word_count > 0:
            words = text_content.lower().split()
            word_frequency = Counter(words)
            unique_words = len(word_frequency)
            repetition_ratio = unique_words / word_count if word_count > 0 else 0

            metadata["unique_words"] = unique_words
            metadata["word_repetition_ratio"] = round(repetition_ratio, 3)

            if repetition_ratio < 0.3:
                issues.append(
                    self.create_issue(
                        issue_type="highly_repetitive_content",
                        severity=Severity.MEDIUM,
                        message=f"Content appears highly repetitive (uniqueness ratio: {repetition_ratio:.2f})",
                        location=url,
                        evidence={
                            "repetition_ratio": repetition_ratio,
                            "recommendation": "Vary vocabulary and reduce repetitive phrases",
                        },
                    )
                )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_readability(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze content readability using various metrics."""
        issues = []
        metadata = {}

        # Extract text content
        body = soup.find("body")
        if not body:
            return {"issues": issues, "metadata": metadata}

        # Remove non-content elements
        for element in body(["script", "style", "nav", "header", "footer"]):
            element.decompose()

        text_content = body.get_text(strip=True, separator=" ")

        if not text_content:
            return {"issues": issues, "metadata": metadata}

        # Calculate readability metrics
        words = text_content.split()
        sentences = re.findall(r"[.!?]+", text_content)

        word_count = len(words)
        sentence_count = len(sentences) if sentences else 1

        # Calculate average sentence length
        avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0

        # Calculate average word length
        avg_word_length = (
            sum(len(word.strip(".,!?;:")) for word in words) / word_count
            if word_count > 0
            else 0
        )

        # Simple syllable count estimation (rough approximation)
        syllable_count = self._estimate_syllables(text_content)
        avg_syllables_per_word = syllable_count / word_count if word_count > 0 else 0

        # Flesch Reading Ease Score (approximation)
        # Formula: 206.835 - (1.015 × ASL) - (84.6 × ASW)
        # ASL = Average Sentence Length, ASW = Average Syllables per Word
        flesch_score = (
            206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables_per_word)
        )
        flesch_score = max(0, min(100, flesch_score))  # Clamp to 0-100

        # Flesch-Kincaid Grade Level (approximation)
        fk_grade = (
            (0.39 * avg_sentence_length) + (11.8 * avg_syllables_per_word) - 15.59
        )
        fk_grade = max(0, fk_grade)

        metadata.update({
            "avg_sentence_length": round(avg_sentence_length, 2),
            "avg_word_length": round(avg_word_length, 2),
            "avg_syllables_per_word": round(avg_syllables_per_word, 2),
            "flesch_reading_ease": round(flesch_score, 1),
            "flesch_kincaid_grade": round(fk_grade, 1),
            "estimated_syllables": syllable_count,
        })

        # Readability issues
        if flesch_score < 30:
            issues.append(
                self.create_issue(
                    issue_type="very_difficult_readability",
                    severity=Severity.HIGH,
                    message=f"Content is very difficult to read (Flesch score: {flesch_score:.1f})",
                    location=url,
                    evidence={
                        "flesch_score": flesch_score,
                        "recommendation": "Simplify sentences and use shorter, more common words",
                    },
                )
            )
        elif flesch_score < 50:
            issues.append(
                self.create_issue(
                    issue_type="difficult_readability",
                    severity=Severity.MEDIUM,
                    message=f"Content is difficult to read (Flesch score: {flesch_score:.1f})",
                    location=url,
                    evidence={
                        "flesch_score": flesch_score,
                        "recommendation": "Consider simplifying language for better accessibility",
                    },
                )
            )

        if fk_grade > 12:
            issues.append(
                self.create_issue(
                    issue_type="high_reading_grade_level",
                    severity=Severity.MEDIUM,
                    message=f"Content requires high education level (Grade {fk_grade:.1f})",
                    location=url,
                    evidence={
                        "grade_level": fk_grade,
                        "recommendation": "Aim for 8th-10th grade level for broader accessibility",
                    },
                )
            )

        if avg_sentence_length > 25:
            issues.append(
                self.create_issue(
                    issue_type="overly_long_sentences",
                    severity=Severity.MEDIUM,
                    message=f"Sentences are too long on average ({avg_sentence_length:.1f} words)",
                    location=url,
                    evidence={
                        "avg_sentence_length": avg_sentence_length,
                        "recommendation": "Break long sentences into shorter ones for better readability",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    def _estimate_syllables(self, text: str) -> int:
        """Estimate syllable count using simple heuristics."""
        # Remove punctuation and convert to lowercase
        text = re.sub(r"[^a-zA-Z\s]", "", text.lower())
        words = text.split()

        syllable_count = 0
        for word in words:
            if len(word) <= 3:
                syllable_count += 1
            else:
                # Count vowel groups
                vowels = "aeiouy"
                word = word.strip("e")  # Remove silent e
                syllables = 0
                prev_was_vowel = False

                for char in word:
                    is_vowel = char in vowels
                    if is_vowel and not prev_was_vowel:
                        syllables += 1
                    prev_was_vowel = is_vowel

                syllable_count += max(1, syllables)  # At least 1 syllable per word

        return syllable_count

    async def _analyze_content_structure(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze content structure and organization."""
        issues = []
        metadata = {}

        # Heading structure analysis
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        heading_structure = {}

        for heading in headings:
            level = heading.name
            text = heading.get_text(strip=True)
            if level not in heading_structure:
                heading_structure[level] = []
            heading_structure[level].append(text[:50])  # Truncate for metadata

        metadata["heading_structure"] = heading_structure
        metadata["total_headings"] = len(headings)

        # Check for missing headings
        if not soup.find("h1"):
            issues.append(
                self.create_issue(
                    issue_type="missing_h1_heading",
                    severity=Severity.HIGH,
                    message="Page is missing H1 heading",
                    location=url,
                    evidence={
                        "recommendation": "Add a clear H1 heading to indicate the main topic",
                    },
                )
            )

        # Check heading hierarchy
        heading_levels = [int(h.name[1]) for h in headings]
        if heading_levels:
            for i, level in enumerate(heading_levels[1:], 1):
                prev_level = heading_levels[i - 1]
                if level > prev_level + 1:
                    issues.append(
                        self.create_issue(
                            issue_type="broken_heading_hierarchy",
                            severity=Severity.MEDIUM,
                            message=f"Heading hierarchy violation: {prev_level} followed by {level}",
                            location=url,
                            evidence={
                                "recommendation": "Maintain logical heading hierarchy (don't skip levels)",
                            },
                        )
                    )
                    break

        # List structure analysis
        lists = soup.find_all(["ul", "ol"])
        metadata["total_lists"] = len(lists)

        empty_lists = [lst for lst in lists if not lst.find_all("li")]
        if empty_lists:
            issues.append(
                self.create_issue(
                    issue_type="empty_lists",
                    severity=Severity.LOW,
                    message=f"{len(empty_lists)} empty lists found",
                    location=url,
                    evidence={
                        "empty_lists_count": len(empty_lists),
                        "recommendation": "Remove empty lists or add content",
                    },
                )
            )

        # Table analysis
        tables = soup.find_all("table")
        metadata["total_tables"] = len(tables)

        tables_without_headers = []
        for table in tables:
            if not table.find("th") and not table.find("thead"):
                tables_without_headers.append(table)

        if tables_without_headers:
            issues.append(
                self.create_issue(
                    issue_type="tables_missing_headers",
                    severity=Severity.MEDIUM,
                    message=f"{len(tables_without_headers)} tables missing headers",
                    location=url,
                    evidence={
                        "tables_without_headers": len(tables_without_headers),
                        "recommendation": "Add table headers for better accessibility and understanding",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_language_quality(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze language quality and common issues."""
        issues = []
        metadata = {}

        # Extract text content
        text_content = soup.get_text(strip=True, separator=" ")

        if not text_content:
            return {"issues": issues, "metadata": metadata}

        # Check for excessive capitalization
        uppercase_ratio = (
            sum(1 for c in text_content if c.isupper()) / len(text_content)
            if text_content
            else 0
        )
        metadata["uppercase_ratio"] = round(uppercase_ratio, 3)

        if uppercase_ratio > 0.1:
            issues.append(
                self.create_issue(
                    issue_type="excessive_uppercase",
                    severity=Severity.MEDIUM,
                    message=f"Excessive uppercase text detected ({uppercase_ratio:.1%})",
                    location=url,
                    evidence={
                        "uppercase_ratio": uppercase_ratio,
                        "recommendation": "Reduce ALL CAPS text for better readability",
                    },
                )
            )

        # Check for common writing issues
        common_issues = {
            "multiple_exclamations": (r"!{2,}", "Multiple exclamation marks"),
            "multiple_questions": (r"\?{2,}", "Multiple question marks"),
            "excessive_ellipsis": (r"\.{4,}", "Excessive ellipsis"),
            "double_spaces": (r"  +", "Multiple consecutive spaces"),
        }

        for issue_type, (pattern, description) in common_issues.items():
            matches = re.findall(pattern, text_content)
            if matches:
                metadata[f"{issue_type}_count"] = len(matches)
                issues.append(
                    self.create_issue(
                        issue_type=f"formatting_{issue_type}",
                        severity=Severity.LOW,
                        message=f"{description} found ({len(matches)} instances)",
                        location=url,
                        evidence={
                            "instances_count": len(matches),
                            "recommendation": f"Clean up {description.lower()} for professional appearance",
                        },
                    )
                )

        # Check for potential placeholder text
        placeholder_patterns = [
            r"lorem ipsum",
            r"placeholder",
            r"sample text",
            r"coming soon",
            r"under construction",
        ]

        for pattern in placeholder_patterns:
            if re.search(pattern, text_content, re.IGNORECASE):
                issues.append(
                    self.create_issue(
                        issue_type="placeholder_content_detected",
                        severity=Severity.HIGH,
                        message=f"Placeholder content detected: '{pattern}'",
                        location=url,
                        evidence={
                            "pattern": pattern,
                            "recommendation": "Replace placeholder content with actual content",
                        },
                    )
                )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_duplicate_content(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze potential duplicate or repeated content."""
        issues = []
        metadata = {}

        # Get all paragraph texts
        paragraphs = soup.find_all("p")
        paragraph_texts = [
            p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)
        ]

        metadata["total_paragraphs"] = len(paragraph_texts)

        if not paragraph_texts:
            return {"issues": issues, "metadata": metadata}

        # Check for duplicate paragraphs
        paragraph_counts = Counter(paragraph_texts)
        duplicates = {
            text: count for text, count in paragraph_counts.items() if count > 1
        }

        metadata["duplicate_paragraphs"] = len(duplicates)

        if duplicates:
            issues.append(
                self.create_issue(
                    issue_type="duplicate_paragraphs",
                    severity=Severity.MEDIUM,
                    message=f"{len(duplicates)} duplicate paragraphs found",
                    location=url,
                    evidence={
                        "duplicate_count": len(duplicates),
                        "recommendation": "Remove or rephrase duplicate content",
                    },
                )
            )

        # Check for very similar paragraphs (simplified check)
        similar_threshold = 0.8
        similar_pairs = 0

        for i, text1 in enumerate(paragraph_texts):
            for text2 in paragraph_texts[i + 1 :]:
                if (
                    len(text1) > 50 and len(text2) > 50
                ):  # Only check substantial paragraphs
                    # Simple similarity based on word overlap
                    words1 = set(text1.lower().split())
                    words2 = set(text2.lower().split())
                    if words1 and words2:
                        similarity = len(words1.intersection(words2)) / len(
                            words1.union(words2)
                        )
                        if similarity > similar_threshold:
                            similar_pairs += 1

        metadata["similar_paragraph_pairs"] = similar_pairs

        if similar_pairs > 0:
            issues.append(
                self.create_issue(
                    issue_type="similar_content_detected",
                    severity=Severity.LOW,
                    message=f"{similar_pairs} pairs of similar paragraphs detected",
                    location=url,
                    evidence={
                        "similar_pairs": similar_pairs,
                        "recommendation": "Review and diversify similar content sections",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def _analyze_content_freshness(self, soup: BeautifulSoup, url: str) -> dict:
        """Analyze content freshness and metadata indicators."""
        issues = []
        metadata = {}

        # Look for date-related meta tags
        date_indicators = soup.find_all(
            "meta", attrs={"name": re.compile(r"date|time|published|modified", re.I)}
        )
        metadata["date_meta_tags"] = len(date_indicators)

        # Look for time elements
        time_elements = soup.find_all("time")
        metadata["time_elements"] = len(time_elements)

        # Look for copyright notices
        copyright_text = soup.get_text()
        copyright_years = re.findall(
            r"copyright.*?(\d{4})", copyright_text, re.IGNORECASE
        )
        if copyright_years:
            latest_year = max(int(year) for year in copyright_years)
            metadata["latest_copyright_year"] = latest_year

            # Check if copyright is outdated (more than 2 years old)
            from datetime import datetime

            current_year = datetime.now().year
            if current_year - latest_year > 2:
                issues.append(
                    self.create_issue(
                        issue_type="outdated_copyright",
                        severity=Severity.LOW,
                        message=f"Copyright appears outdated ({latest_year})",
                        location=url,
                        evidence={
                            "copyright_year": latest_year,
                            "current_year": current_year,
                            "recommendation": "Update copyright year to maintain credibility",
                        },
                    )
                )

        # Check for "last updated" or similar indicators
        freshness_indicators = [
            "last updated",
            "updated on",
            "published on",
            "created on",
            "modified",
        ]

        found_freshness = any(
            indicator in soup.get_text().lower() for indicator in freshness_indicators
        )

        metadata["has_freshness_indicators"] = found_freshness

        if not found_freshness and not time_elements and not date_indicators:
            issues.append(
                self.create_issue(
                    issue_type="no_content_freshness_indicators",
                    severity=Severity.LOW,
                    message="No content freshness indicators found",
                    location=url,
                    evidence={
                        "recommendation": "Add publication or update dates to establish content freshness",
                    },
                )
            )

        return {"issues": issues, "metadata": metadata}

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL for content quality with detailed context and improvement suggestions."""
        try:
            detailed_issues = []
            content_metrics = ContentMetrics()
            raw_data = {}

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="invalid_url_scheme",
                        severity=Severity.HIGH,
                        message="URL must start with http:// or https://",
                        location=url,
                        category="content",
                        subcategory="url_structure",
                        description="The provided URL does not use a valid HTTP scheme",
                        impact="Cannot perform content analysis without valid scheme.",
                        technical_details={"provided_url": url},
                        recommendations=[
                            "Use HTTPS URLs for better security and content delivery."
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
                    content_metrics=content_metrics,
                    raw_data=raw_data,
                )

            # Perform detailed content analysis
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
                                category="content",
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
                            content_metrics=content_metrics,
                            raw_data=raw_data,
                        )

                    # Parse HTML content
                    soup = BeautifulSoup(response.content, "html.parser")
                    raw_data["html_structure"] = {
                        "title": soup.title.string if soup.title else None,
                        "meta_description": soup.find(
                            "meta", attrs={"name": "description"}
                        ),
                        "headings": [
                            h.get_text()
                            for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
                        ],
                        "paragraphs_count": len(soup.find_all("p")),
                        "images_count": len(soup.find_all("img")),
                    }

                    # Content Quality Analysis with detailed context

                    # 1. Text Content Extraction and Basic Metrics
                    content_metrics_data = await self._analyze_content_metrics_detailed(
                        soup, url
                    )
                    detailed_issues.extend(content_metrics_data["issues"])
                    content_metrics.word_count = content_metrics_data["metrics"].get(
                        "word_count", 0
                    )
                    content_metrics.character_count = content_metrics_data[
                        "metrics"
                    ].get("character_count", 0)
                    content_metrics.sentence_count = content_metrics_data[
                        "metrics"
                    ].get("sentence_count", 0)
                    raw_data["content_metrics"] = content_metrics_data["raw"]

                    # 2. Readability Analysis
                    readability_data = await self._analyze_readability_detailed(
                        soup, url
                    )
                    detailed_issues.extend(readability_data["issues"])
                    content_metrics.readability_score = readability_data["metrics"].get(
                        "readability_score", 0
                    )
                    content_metrics.complex_sentences = readability_data["metrics"].get(
                        "complex_sentences", 0
                    )
                    raw_data["readability"] = readability_data["raw"]

                    # 3. Content Structure Analysis
                    structure_data = await self._analyze_content_structure_detailed(
                        soup, url
                    )
                    detailed_issues.extend(structure_data["issues"])
                    content_metrics.heading_structure_issues = structure_data[
                        "metrics"
                    ].get("heading_structure_issues", 0)
                    content_metrics.paragraph_length_issues = structure_data[
                        "metrics"
                    ].get("paragraph_length_issues", 0)
                    raw_data["content_structure"] = structure_data["raw"]

                    # 4. Language Quality Analysis
                    language_quality_data = (
                        await self._analyze_language_quality_detailed(soup, url)
                    )
                    detailed_issues.extend(language_quality_data["issues"])
                    content_metrics.spelling_errors = language_quality_data[
                        "metrics"
                    ].get("spelling_errors", 0)
                    content_metrics.grammar_issues = language_quality_data[
                        "metrics"
                    ].get("grammar_issues", 0)
                    raw_data["language_quality"] = language_quality_data["raw"]

                    # 5. Duplicate Content Detection
                    duplicate_content_data = (
                        await self._analyze_duplicate_content_detailed(soup, url)
                    )
                    detailed_issues.extend(duplicate_content_data["issues"])
                    content_metrics.duplicate_content_ratio = duplicate_content_data[
                        "metrics"
                    ].get("duplicate_content_ratio", 0)
                    raw_data["duplicate_content"] = duplicate_content_data["raw"]

                    # 6. Content Freshness and Metadata
                    freshness_data = await self._analyze_content_freshness_detailed(
                        soup, url
                    )
                    detailed_issues.extend(freshness_data["issues"])
                    content_metrics.content_age_days = freshness_data["metrics"].get(
                        "content_age_days", 0
                    )
                    raw_data["content_freshness"] = freshness_data["raw"]

                except httpx.RequestError as e:
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="content_analysis_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to analyze content: {str(e)}",
                            location=url,
                            category="content",
                            subcategory="analysis_error",
                            description="Content analysis failed due to connection error",
                            impact="Cannot determine content quality issues",
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
                content_metrics=content_metrics,
                raw_data=raw_data,
            )

        except Exception as e:
            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                success=False,
                error_message=str(e),
            )

    async def _analyze_content_metrics_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze basic content metrics with detailed context and quality indicators."""
        issues = []
        metrics = {}
        raw = {}

        # Extract text content from body
        body = soup.find("body")
        if not body:
            issues.append(
                self.create_detailed_issue(
                    issue_type="missing_body_element",
                    severity=Severity.HIGH,
                    message="Page is missing body element",
                    location=url,
                    category="content",
                    subcategory="html_structure",
                    description="HTML document lacks proper body structure",
                    impact="Content cannot be properly analyzed and may not render correctly",
                    technical_details={
                        "recommendation": "Ensure HTML has proper body structure"
                    },
                    recommendations=["Add proper HTML body element"],
                    fix_suggestions=[
                        "Add <body> tag to HTML document",
                        "Ensure proper HTML structure",
                        "Validate HTML markup",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body"],
                    priority_score=0.9,
                )
            )
            return {"issues": issues, "metrics": metrics, "raw": raw}

        # Get all text content, excluding script and style tags
        for element in body(["script", "style", "nav", "header", "footer"]):
            element.decompose()

        text_content = body.get_text(strip=True, separator=" ")

        # Basic metrics
        word_count = len(text_content.split()) if text_content else 0
        char_count = len(text_content)
        char_count_no_spaces = len(text_content.replace(" ", ""))
        sentence_count = len(re.findall(r"[.!?]+", text_content)) if text_content else 0
        paragraph_count = len(soup.find_all("p"))

        metrics.update({
            "word_count": word_count,
            "character_count": char_count,
            "character_count_no_spaces": char_count_no_spaces,
            "sentence_count": sentence_count,
            "paragraph_count": paragraph_count,
        })

        raw["content_analysis"] = {
            "text_content_preview": text_content[:500] + "..."
            if len(text_content) > 500
            else text_content,
            "word_count": word_count,
            "character_count": char_count,
            "sentence_count": sentence_count,
            "paragraph_count": paragraph_count,
        }

        # Content quality issues
        if word_count < 100:
            issues.append(
                self.create_detailed_issue(
                    issue_type="very_thin_content",
                    severity=Severity.HIGH,
                    message=f"Very thin content detected ({word_count} words)",
                    location=url,
                    category="content",
                    subcategory="content_quality",
                    description="Page has insufficient content to provide value to users",
                    impact="Poor user experience and low SEO value",
                    technical_details={
                        "word_count": word_count,
                        "recommendation": "Add more substantive content to improve value for users and SEO",
                    },
                    recommendations=["Significantly expand page content"],
                    fix_suggestions=[
                        "Add detailed explanations and context",
                        "Include relevant examples and case studies",
                        "Expand on key topics and concepts",
                        "Add supporting information and resources",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.8,
                )
            )
        elif word_count < 300:
            issues.append(
                self.create_detailed_issue(
                    issue_type="thin_content",
                    severity=Severity.MEDIUM,
                    message=f"Thin content detected ({word_count} words)",
                    location=url,
                    category="content",
                    subcategory="content_quality",
                    description="Page content could be more comprehensive",
                    impact="May not provide sufficient value to users",
                    technical_details={
                        "word_count": word_count,
                        "recommendation": "Consider expanding content for better user experience",
                    },
                    recommendations=["Expand page content for better user experience"],
                    fix_suggestions=[
                        "Add more detailed explanations",
                        "Include additional relevant information",
                        "Expand on key points",
                        "Add supporting content",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.6,
                )
            )

        # Check for content that's mostly repetitive
        if word_count > 0:
            words = text_content.lower().split()
            word_frequency = Counter(words)
            unique_words = len(word_frequency)
            repetition_ratio = unique_words / word_count if word_count > 0 else 0

            metrics["unique_words"] = unique_words
            metrics["repetition_ratio"] = repetition_ratio

            raw["word_analysis"] = {
                "unique_words": unique_words,
                "repetition_ratio": repetition_ratio,
                "most_common_words": word_frequency.most_common(10),
            }

            if repetition_ratio < 0.3:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="high_content_repetition",
                        severity=Severity.MEDIUM,
                        message=f"High content repetition detected (repetition ratio: {repetition_ratio:.2f})",
                        location=url,
                        category="content",
                        subcategory="content_quality",
                        description="Content uses many repeated words, indicating poor writing quality",
                        impact="Poor readability and user engagement",
                        technical_details={
                            "repetition_ratio": repetition_ratio,
                            "unique_words": unique_words,
                            "total_words": word_count,
                        },
                        recommendations=[
                            "Improve content variety and reduce repetition"
                        ],
                        fix_suggestions=[
                            "Use synonyms and varied vocabulary",
                            "Rewrite repetitive sentences",
                            "Use different sentence structures",
                            "Expand vocabulary usage",
                        ],
                        code_location=CodeLocation(
                            element_selector="body",
                            element_tag="body",
                            resource_type="html",
                        ),
                        affected_elements=["body", "p", "div"],
                        priority_score=0.5,
                    )
                )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_readability_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze content readability with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        # Extract text content
        body = soup.find("body")
        if not body:
            return {"issues": issues, "metrics": metrics, "raw": raw}

        for element in body(["script", "style", "nav", "header", "footer"]):
            element.decompose()

        text_content = body.get_text(strip=True, separator=" ")

        if not text_content:
            return {"issues": issues, "metrics": metrics, "raw": raw}

        # Calculate readability metrics
        sentences = re.split(r"[.!?]+", text_content)
        sentences = [s.strip() for s in sentences if s.strip()]

        words = text_content.split()
        syllables = sum(self._estimate_syllables(word) for word in words)

        # Flesch Reading Ease
        if len(sentences) > 0 and len(words) > 0:
            flesch_score = (
                206.835
                - (1.015 * (len(words) / len(sentences)))
                - (84.6 * (syllables / len(words)))
            )
            flesch_score = max(0, min(100, flesch_score))
        else:
            flesch_score = 0

        # Analyze sentence complexity
        complex_sentences = 0
        long_sentences = []

        for sentence in sentences:
            sentence_words = sentence.split()
            if len(sentence_words) > 25:
                complex_sentences += 1
                long_sentences.append({
                    "sentence": sentence[:100] + "..."
                    if len(sentence) > 100
                    else sentence,
                    "word_count": len(sentence_words),
                })

        metrics.update({
            "readability_score": flesch_score,
            "complex_sentences": complex_sentences,
            "total_sentences": len(sentences),
            "average_sentence_length": len(words) / len(sentences) if sentences else 0,
        })

        raw["readability_analysis"] = {
            "flesch_score": flesch_score,
            "complex_sentences": complex_sentences,
            "long_sentences": long_sentences[:5],
            "average_sentence_length": len(words) / len(sentences) if sentences else 0,
        }

        # Readability issues
        if flesch_score < 30:
            issues.append(
                self.create_detailed_issue(
                    issue_type="very_difficult_readability",
                    severity=Severity.HIGH,
                    message=f"Very difficult readability (Flesch score: {flesch_score:.1f})",
                    location=url,
                    category="content",
                    subcategory="readability",
                    description="Content is very difficult to read and understand",
                    impact="Users may struggle to understand the content",
                    technical_details={
                        "flesch_score": flesch_score,
                        "complex_sentences": complex_sentences,
                        "average_sentence_length": len(words) / len(sentences)
                        if sentences
                        else 0,
                    },
                    recommendations=["Significantly improve content readability"],
                    fix_suggestions=[
                        "Use shorter, simpler sentences",
                        "Break down complex ideas",
                        "Use simpler vocabulary",
                        "Add bullet points and lists",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.8,
                )
            )
        elif flesch_score < 50:
            issues.append(
                self.create_detailed_issue(
                    issue_type="difficult_readability",
                    severity=Severity.MEDIUM,
                    message=f"Difficult readability (Flesch score: {flesch_score:.1f})",
                    location=url,
                    category="content",
                    subcategory="readability",
                    description="Content is difficult to read and understand",
                    impact="Some users may have difficulty understanding the content",
                    technical_details={
                        "flesch_score": flesch_score,
                        "complex_sentences": complex_sentences,
                    },
                    recommendations=["Improve content readability"],
                    fix_suggestions=[
                        "Simplify sentence structure",
                        "Use clearer language",
                        "Break up long paragraphs",
                        "Add headings and subheadings",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.6,
                )
            )

        if complex_sentences > 5:
            issues.append(
                self.create_detailed_issue(
                    issue_type="too_many_complex_sentences",
                    severity=Severity.MEDIUM,
                    message=f"Too many complex sentences ({complex_sentences})",
                    location=url,
                    category="content",
                    subcategory="readability",
                    description="Content contains many overly complex sentences",
                    impact="Reduces readability and user comprehension",
                    technical_details={
                        "complex_sentences": complex_sentences,
                        "total_sentences": len(sentences),
                        "percentage": (complex_sentences / len(sentences)) * 100
                        if sentences
                        else 0,
                    },
                    recommendations=["Simplify complex sentences"],
                    fix_suggestions=[
                        "Break long sentences into shorter ones",
                        "Use simpler sentence structures",
                        "Remove unnecessary complexity",
                        "Use active voice instead of passive",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.6,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_content_structure_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze content structure with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        # Check heading structure
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        heading_structure = []
        heading_issues = []

        for heading in headings:
            level = int(heading.name[1])
            heading_structure.append({
                "level": level,
                "text": heading.get_text()[:50],
                "tag": heading.name,
            })

        # Check for proper heading hierarchy
        current_level = 0
        for heading in heading_structure:
            if heading["level"] > current_level + 1:
                heading_issues.append(
                    f"Skipped heading level: {current_level} to {heading['level']}"
                )
            current_level = heading["level"]

        # Check paragraph length
        paragraphs = soup.find_all("p")
        long_paragraphs = []

        for p in paragraphs:
            text = p.get_text().strip()
            if len(text.split()) > 150:
                long_paragraphs.append({
                    "text": text[:100] + "..." if len(text) > 100 else text,
                    "word_count": len(text.split()),
                })

        metrics.update({
            "total_headings": len(headings),
            "heading_structure_issues": len(heading_issues),
            "total_paragraphs": len(paragraphs),
            "paragraph_length_issues": len(long_paragraphs),
        })

        raw["content_structure"] = {
            "headings": heading_structure,
            "heading_issues": heading_issues,
            "long_paragraphs": long_paragraphs[:5],
        }

        if heading_issues:
            issues.append(
                self.create_detailed_issue(
                    issue_type="poor_heading_structure",
                    severity=Severity.MEDIUM,
                    message=f"Poor heading structure ({len(heading_issues)} issues)",
                    location=url,
                    category="content",
                    subcategory="content_structure",
                    description="Heading hierarchy does not follow logical order",
                    impact="Poor content organization and navigation",
                    technical_details={
                        "heading_issues_count": len(heading_issues),
                        "sample_issues": heading_issues[:3],
                    },
                    recommendations=["Fix heading hierarchy to follow logical order"],
                    fix_suggestions=[
                        "Use h1 for main page title",
                        "Use h2 for major sections",
                        "Use h3 for subsections",
                        "Don't skip heading levels",
                    ],
                    code_location=CodeLocation(
                        element_selector="h1, h2, h3, h4, h5, h6",
                        resource_type="html",
                    ),
                    affected_elements=["h1", "h2", "h3", "h4", "h5", "h6"],
                    priority_score=0.6,
                )
            )

        if len(long_paragraphs) > 3:
            issues.append(
                self.create_detailed_issue(
                    issue_type="too_many_long_paragraphs",
                    severity=Severity.MEDIUM,
                    message=f"Too many long paragraphs ({len(long_paragraphs)})",
                    location=url,
                    category="content",
                    subcategory="content_structure",
                    description="Content contains many overly long paragraphs",
                    impact="Reduces readability and user engagement",
                    technical_details={
                        "long_paragraphs_count": len(long_paragraphs),
                        "total_paragraphs": len(paragraphs),
                        "percentage": (len(long_paragraphs) / len(paragraphs)) * 100
                        if paragraphs
                        else 0,
                    },
                    recommendations=["Break up long paragraphs for better readability"],
                    fix_suggestions=[
                        "Split long paragraphs into shorter ones",
                        "Use bullet points and lists",
                        "Add subheadings to break up content",
                        "Use white space effectively",
                    ],
                    code_location=CodeLocation(
                        element_selector="p",
                        element_tag="p",
                        resource_type="html",
                    ),
                    affected_elements=["p"],
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_language_quality_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze language quality with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        # Extract text content
        body = soup.find("body")
        if not body:
            return {"issues": issues, "metrics": metrics, "raw": raw}

        for element in body(["script", "style", "nav", "header", "footer"]):
            element.decompose()

        text_content = body.get_text(strip=True, separator=" ")

        # Basic language quality checks
        spelling_errors = 0
        grammar_issues = 0
        language_issues = []

        # Check for common spelling patterns (simplified)
        words = text_content.lower().split()
        common_misspellings = [
            "recieve",
            "seperate",
            "occured",
            "accomodate",
            "begining",
            "beleive",
            "calender",
            "collegue",
            "definately",
            "embarass",
        ]

        for word in words:
            if word in common_misspellings:
                spelling_errors += 1
                language_issues.append(f"Possible spelling error: {word}")

        # Check for basic grammar patterns
        sentences = re.split(r"[.!?]+", text_content)
        for sentence in sentences:
            sentence = sentence.strip()
            if sentence:
                # Check for double spaces
                if "  " in sentence:
                    grammar_issues += 1
                    language_issues.append("Double spaces detected")

                # Check for sentence starting with lowercase
                if sentence and sentence[0].islower():
                    grammar_issues += 1
                    language_issues.append("Sentence starts with lowercase")

        metrics.update({
            "spelling_errors": spelling_errors,
            "grammar_issues": grammar_issues,
            "total_language_issues": len(language_issues),
        })

        raw["language_quality"] = {
            "spelling_errors": spelling_errors,
            "grammar_issues": grammar_issues,
            "language_issues": language_issues[:10],
        }

        if spelling_errors > 5:
            issues.append(
                self.create_detailed_issue(
                    issue_type="multiple_spelling_errors",
                    severity=Severity.MEDIUM,
                    message=f"Multiple spelling errors detected ({spelling_errors})",
                    location=url,
                    category="content",
                    subcategory="language_quality",
                    description="Content contains multiple spelling errors",
                    impact="Reduces content credibility and professionalism",
                    technical_details={
                        "spelling_errors": spelling_errors,
                        "sample_errors": language_issues[:3],
                    },
                    recommendations=["Fix spelling errors throughout the content"],
                    fix_suggestions=[
                        "Use spell-checking tools",
                        "Review content carefully",
                        "Have content proofread",
                        "Use grammar checking software",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.6,
                )
            )

        if grammar_issues > 10:
            issues.append(
                self.create_detailed_issue(
                    issue_type="multiple_grammar_issues",
                    severity=Severity.MEDIUM,
                    message=f"Multiple grammar issues detected ({grammar_issues})",
                    location=url,
                    category="content",
                    subcategory="language_quality",
                    description="Content contains multiple grammar issues",
                    impact="Reduces content quality and readability",
                    technical_details={
                        "grammar_issues": grammar_issues,
                        "sample_issues": language_issues[:3],
                    },
                    recommendations=["Fix grammar issues throughout the content"],
                    fix_suggestions=[
                        "Use grammar checking tools",
                        "Review sentence structure",
                        "Have content professionally edited",
                        "Use writing style guides",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_duplicate_content_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze duplicate content with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        # Extract text content
        body = soup.find("body")
        if not body:
            return {"issues": issues, "metrics": metrics, "raw": raw}

        for element in body(["script", "style", "nav", "header", "footer"]):
            element.decompose()

        text_content = body.get_text(strip=True, separator=" ")

        # Check for internal duplicate content
        sentences = re.split(r"[.!?]+", text_content)
        sentences = [s.strip() for s in sentences if s.strip()]

        sentence_frequency = Counter(sentences)
        duplicate_sentences = [
            s for s, count in sentence_frequency.items() if count > 1
        ]

        duplicate_content_ratio = (
            len(duplicate_sentences) / len(sentences) if sentences else 0
        )

        metrics.update({
            "duplicate_sentences": len(duplicate_sentences),
            "duplicate_content_ratio": duplicate_content_ratio,
            "total_sentences": len(sentences),
        })

        raw["duplicate_content"] = {
            "duplicate_sentences": duplicate_sentences[:5],
            "duplicate_content_ratio": duplicate_content_ratio,
            "total_sentences": len(sentences),
        }

        if duplicate_content_ratio > 0.1:
            issues.append(
                self.create_detailed_issue(
                    issue_type="high_duplicate_content",
                    severity=Severity.MEDIUM,
                    message=f"High duplicate content ratio ({duplicate_content_ratio:.2f})",
                    location=url,
                    category="content",
                    subcategory="duplicate_content",
                    description="Content contains significant internal duplication",
                    impact="Poor user experience and potential SEO issues",
                    technical_details={
                        "duplicate_content_ratio": duplicate_content_ratio,
                        "duplicate_sentences": len(duplicate_sentences),
                        "total_sentences": len(sentences),
                    },
                    recommendations=["Reduce duplicate content within the page"],
                    fix_suggestions=[
                        "Remove or rewrite duplicate sentences",
                        "Consolidate similar content",
                        "Use different ways to express similar ideas",
                        "Review and edit content for uniqueness",
                    ],
                    code_location=CodeLocation(
                        element_selector="body",
                        element_tag="body",
                        resource_type="html",
                    ),
                    affected_elements=["body", "p", "div"],
                    priority_score=0.5,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}

    async def _analyze_content_freshness_detailed(
        self, soup: BeautifulSoup, url: str
    ) -> dict:
        """Analyze content freshness with detailed context and improvement suggestions."""
        issues = []
        metrics = {}
        raw = {}

        # Check for last modified date
        last_modified = soup.find("meta", attrs={"name": "last-modified"})
        if last_modified:
            last_modified_date = last_modified.get("content")
        else:
            last_modified_date = None

        # Check for publication date
        pub_date = soup.find("meta", attrs={"property": "article:published_time"})
        if pub_date:
            publication_date = pub_date.get("content")
        else:
            publication_date = None

        # Simple content age estimation (this would need more sophisticated logic in practice)
        content_age_days = 365  # Default to 1 year if no date found

        if last_modified_date or publication_date:
            # In a real implementation, you would parse the date and calculate age
            content_age_days = 180  # Example: 6 months

        metrics.update({
            "content_age_days": content_age_days,
            "has_last_modified": bool(last_modified_date),
            "has_publication_date": bool(publication_date),
        })

        raw["content_freshness"] = {
            "last_modified": last_modified_date,
            "publication_date": publication_date,
            "content_age_days": content_age_days,
        }

        if content_age_days > 365:
            issues.append(
                self.create_detailed_issue(
                    issue_type="outdated_content",
                    severity=Severity.MEDIUM,
                    message=f"Content may be outdated ({content_age_days} days old)",
                    location=url,
                    category="content",
                    subcategory="content_freshness",
                    description="Content appears to be old and may need updating",
                    impact="Users may find outdated information",
                    technical_details={
                        "content_age_days": content_age_days,
                        "last_modified": last_modified_date,
                        "publication_date": publication_date,
                    },
                    recommendations=["Review and update content for freshness"],
                    fix_suggestions=[
                        "Update content with current information",
                        "Add last modified dates",
                        "Review and refresh outdated content",
                        "Add content update schedule",
                    ],
                    code_location=CodeLocation(
                        element_selector="meta[name='last-modified']",
                        element_tag="meta",
                        resource_type="html",
                    ),
                    affected_elements=["meta"],
                    priority_score=0.4,
                )
            )

        return {"issues": issues, "metrics": metrics, "raw": raw}
