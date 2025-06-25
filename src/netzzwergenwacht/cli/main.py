"""Main CLI application for NetzZwergenWacht."""

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..dwarfs.base import ComprehensiveAnalysisReport, DwarfOrchestrator
from ..dwarfs.inhalt_zwerg import InhaltZwerg
from ..dwarfs.leistungs_zwerg import LeistungsZwerg
from ..dwarfs.seo_zwerg import SEOZwerg
from ..dwarfs.sicherheits_zwerg import SicherheitsZwerg
from ..dwarfs.visual_zwerg import VisualZwerg
from ..dwarfs.web_browser_zwerg import WebBrowserZwerg
from ..dwarfs.zugaenglichkeits_zwerg import ZugaenglichkeitsZwerg

app = typer.Typer(
    help="NetzZwergenWacht - Intelligent website monitoring using LLM-powered Zwerge",
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def check(
    url: str = typer.Argument(help="URL to analyze"),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file path", dir_okay=False, writable=True
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format (json, text)",
        case_sensitive=False,
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose output including technical details"
    ),
    checks: str | None = typer.Option(
        None,
        "--checks",
        "-c",
        help="Specific checks to run (comma separated)",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
        case_sensitive=False,
    ),
) -> None:
    """Run quality checks on a website."""
    console.print(f"[bold blue]Analyzing:[/bold blue] {url}")

    # Run analysis
    results = asyncio.run(_run_analysis(url, checks))

    # Display results
    _display_results(results, verbose)

    # Save to file if requested
    if output:
        # Ensure output directory exists
        output_path = _ensure_output_path(output)
        _save_results(results, output_path, output_format)
        console.print(f"[green]Results saved to:[/green] {output_path}")


@app.command()
def analyze(
    url: str = typer.Argument(help="URL to analyze"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
    output_format: str = typer.Option(
        "json", "--format", "-f", help="Output format (json, text, pdf)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Enable LLM processing of results (requires OPENAI_API_KEY)",
    ),
    pdf_type: str = typer.Option(
        "comprehensive",
        "--pdf-type",
        help="PDF report type (executive, technical, comprehensive)",
    ),
) -> None:
    """Run comprehensive analysis with detailed results for LLM integration."""
    console.print(f"[bold blue]Comprehensive Analysis:[/bold blue] {url}")
    console.print("[dim]Running all Zwerge with detailed metrics...[/dim]")

    # Run detailed analysis
    report = asyncio.run(_run_detailed_analysis(url))

    # Display summary
    _display_comprehensive_summary(report, verbose)

    # Store LLM results for PDF integration
    llm_results = {}

    # Process with LLM if enabled OR if PDF format is requested (auto-enable LLM for PDF)
    if llm or output_format.lower() == "pdf":
        from ..llm import LLMProcessor

        console.print("\n[bold blue]🤖 Initializing LLM Analysis...[/bold blue]")

        try:
            processor = LLMProcessor()
            console.print(f"[dim]Model: {processor.model}[/dim]")

            llm_results = asyncio.run(processor.analyze_report(report))

            if llm_results.get("success", False):
                console.print("\n[bold green]✅ LLM Analysis Complete![/bold green]")

                # Show usage and cost info
                if "usage" in llm_results:
                    usage = llm_results["usage"]
                    console.print(
                        f"[dim]Tokens used: {usage['total_tokens']} (${usage['cost']:.4f})[/dim]"
                    )

                # Display the full LLM analysis only if explicitly requested (not for auto-PDF)
                if llm:
                    console.print("\n[bold cyan]📋 Detailed LLM Analysis:[/bold cyan]")
                    console.print(llm_results["analysis"])

                    # Show extracted recommendations if any
                    if llm_results["recommendations"]:
                        console.print(
                            "\n[bold yellow]💡 Key Recommendations:[/bold yellow]"
                        )
                        for i, rec in enumerate(llm_results["recommendations"], 1):
                            console.print(f"  {i}. {rec}")

                    # Show priority actions
                    if llm_results["priority_actions"]:
                        console.print("\n[bold red]🚨 Priority Actions:[/bold red]")
                        for i, action in enumerate(llm_results["priority_actions"], 1):
                            console.print(f"  {i}. {action}")
                elif output_format.lower() == "pdf":
                    console.print(
                        "\n[dim]🤖 LLM analysis will be integrated into PDF report[/dim]"
                    )
            else:
                console.print(
                    "\n[yellow]⚠️ LLM analysis failed, using fallback analysis[/yellow]"
                )
                console.print(llm_results["summary"])

            # Save LLM results if explicitly requested
            if output and llm:
                llm_path = output.with_suffix(".llm.json")
                processor.save_for_llm(report, llm_path)
                console.print(f"\n[green]💾 LLM results saved to:[/green] {llm_path}")

        except ValueError as e:
            # This is likely the API key missing error
            console.print(f"\n[yellow]⚠️ {str(e)}[/yellow]")
            if output_format.lower() == "pdf":
                console.print("[dim]PDF will be generated without LLM content[/dim]")
            else:
                console.print(
                    "[dim]Continuing with standard analysis without LLM...[/dim]"
                )
        except Exception as e:
            console.print(f"\n[red]❌ Unexpected LLM error:[/red] {str(e)}")
            if output_format.lower() == "pdf":
                console.print("[dim]PDF will be generated without LLM content[/dim]")
            else:
                console.print("[dim]Continuing with standard analysis...[/dim]")

    # Save to file if requested
    if output:
        # Ensure output directory exists
        output_path = _ensure_output_path(output)
        _save_comprehensive_results(
            report, output_path, output_format, pdf_type, llm_results
        )
        console.print(f"[green]Detailed results saved to:[/green] {output_path}")
    else:
        # Auto-generate filename if not provided
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        url_safe = (
            url.replace("://", "_")
            .replace("/", "_")
            .replace(".", "_")
            .replace(":", "_")
        )
        auto_filename = f"analysis_{url_safe}_{timestamp}.{output_format}"
        output_path = _ensure_output_path(Path(auto_filename))
        _save_comprehensive_results(
            report, output_path, output_format, pdf_type, llm_results
        )
        console.print(f"[green]Auto-saved detailed results to:[/green] {output_path}")


@app.command()
def monitor(config_file: Path = typer.Argument(help="Configuration file path")) -> None:
    """Start monitoring websites based on configuration."""
    console.print("[yellow]Monitor command not yet implemented.[/yellow]")
    console.print(f"Configuration file: {config_file}")


@app.command()
def version() -> None:
    """Show version information."""
    from .. import __author__, __version__

    panel = Panel(
        f"[bold]NetzZwergenWacht[/bold]\nVersion: {__version__}\nAuthor: {__author__}",
        title="Version Info",
        border_style="blue",
    )
    console.print(panel)


async def _run_analysis(url: str, checks: str | None = None) -> list:
    """Run analysis using Dwarf orchestrator."""
    orchestrator = DwarfOrchestrator()

    # Convert checks string to list if provided
    check_list = [c.strip() for c in checks.split(",")] if checks else None

    # Add available Zwerge based on checks parameter
    if not check_list or "web" in check_list:
        orchestrator.add_dwarf(WebBrowserZwerg())
    if not check_list or "security" in check_list:
        orchestrator.add_dwarf(SicherheitsZwerg())
    if not check_list or "performance" in check_list:
        orchestrator.add_dwarf(LeistungsZwerg())
    if not check_list or "seo" in check_list:
        orchestrator.add_dwarf(SEOZwerg())
    if not check_list or "accessibility" in check_list:
        orchestrator.add_dwarf(ZugaenglichkeitsZwerg())
    if not check_list or "content" in check_list:
        orchestrator.add_dwarf(InhaltZwerg())
    if not check_list or "visual" in check_list:
        orchestrator.add_dwarf(VisualZwerg())

    return await orchestrator.analyze_url(url)


async def _run_detailed_analysis(url: str) -> ComprehensiveAnalysisReport:
    """Run detailed analysis using Dwarf orchestrator."""
    orchestrator = DwarfOrchestrator()

    # Add available Zwerge
    orchestrator.add_dwarf(WebBrowserZwerg())
    orchestrator.add_dwarf(SicherheitsZwerg())
    orchestrator.add_dwarf(LeistungsZwerg())
    orchestrator.add_dwarf(SEOZwerg())
    orchestrator.add_dwarf(ZugaenglichkeitsZwerg())
    orchestrator.add_dwarf(InhaltZwerg())
    orchestrator.add_dwarf(VisualZwerg())

    return await orchestrator.analyze_url_detailed(url)


def _display_comprehensive_summary(
    report: ComprehensiveAnalysisReport, verbose: bool = False
) -> None:
    """Display comprehensive analysis summary with detailed verbose output."""

    # Overall summary
    console.print("\n[bold green]Analysis Complete![/bold green]")
    console.print(
        f"[dim]Duration:[/dim] {report.analysis_duration_seconds:.2f} seconds"
    )

    # Overall score
    if report.overall_score:
        score_color = (
            "green"
            if report.overall_score >= 80
            else "yellow"
            if report.overall_score >= 60
            else "red"
        )
        console.print(
            f"[bold {score_color}]Overall Score:[/bold {score_color}] {report.overall_score:.1f}/100"
        )

    # Issue summary
    console.print(f"\n[bold]Issues Found:[/bold] {report.total_issues}")
    if report.total_issues > 0:
        console.print(f"  [red]Critical:[/red] {report.critical_issues}")
        console.print(f"  [yellow]High:[/yellow] {report.high_issues}")
        console.print(f"  [blue]Medium:[/blue] {report.medium_issues}")
        console.print(f"  [green]Low:[/green] {report.low_issues}")

    # Issues by category
    if report.issues_by_category:
        console.print("\n[bold]Issues by Category:[/bold]")
        for category, count in report.issues_by_category.items():
            console.print(f"  {category.title()}: {count}")

    # Top recommendations
    if report.top_recommendations:
        console.print("\n[bold]Top Recommendations:[/bold]")
        for i, rec in enumerate(report.top_recommendations, 1):
            console.print(f"  {i}. {rec}")

    # Priority actions
    if report.priority_actions:
        console.print("\n[bold]Priority Actions:[/bold]")
        for i, action in enumerate(report.priority_actions, 1):
            console.print(f"  {i}. {action}")

    # Detailed dwarf results with verbose output
    if verbose:
        console.print("\n[bold]Detailed Results by Dwarf:[/bold]")
        for result in report.dwarf_results:
            console.print(f"\n[bold cyan]{result.dwarf_name}[/bold cyan]")

            if not result.success:
                console.print(f"  [red]Error:[/red] {result.error_message}")
                continue

            # Show metrics tables for each dwarf type
            if result.performance_metrics:
                perf_table = Table(
                    show_header=True,
                    header_style="bold blue",
                    title="Performance Metrics",
                )
                perf_table.add_column("Metric", style="cyan")
                perf_table.add_column("Value", style="white")

                if result.performance_metrics.response_time_ms:
                    perf_table.add_row(
                        "Response Time",
                        f"{result.performance_metrics.response_time_ms} ms",
                    )
                if result.performance_metrics.page_load_time_ms:
                    perf_table.add_row(
                        "Page Load Time",
                        f"{result.performance_metrics.page_load_time_ms} ms",
                    )
                if result.performance_metrics.total_size_bytes:
                    perf_table.add_row(
                        "Total Size",
                        f"{result.performance_metrics.total_size_bytes:,} bytes",
                    )
                if result.performance_metrics.lcp:
                    perf_table.add_row("LCP", f"{result.performance_metrics.lcp} ms")
                if result.performance_metrics.fcp:
                    perf_table.add_row("FCP", f"{result.performance_metrics.fcp} ms")
                if result.performance_metrics.cls:
                    perf_table.add_row("CLS", f"{result.performance_metrics.cls}")
                if result.performance_metrics.ttfb:
                    perf_table.add_row("TTFB", f"{result.performance_metrics.ttfb} ms")
                if result.performance_metrics.image_count:
                    perf_table.add_row(
                        "Images", str(result.performance_metrics.image_count)
                    )
                if result.performance_metrics.css_count:
                    perf_table.add_row(
                        "CSS Files", str(result.performance_metrics.css_count)
                    )
                if result.performance_metrics.js_count:
                    perf_table.add_row(
                        "JS Files", str(result.performance_metrics.js_count)
                    )

                console.print(perf_table)

            if result.security_metrics:
                sec_table = Table(
                    show_header=True, header_style="bold blue", title="Security Metrics"
                )
                sec_table.add_column("Metric", style="cyan")
                sec_table.add_column("Value", style="white")

                if result.security_metrics.ssl_enabled is not None:
                    sec_table.add_row(
                        "SSL Enabled",
                        "Yes" if result.security_metrics.ssl_enabled else "No",
                    )
                if result.security_metrics.ssl_version:
                    sec_table.add_row(
                        "SSL Version", result.security_metrics.ssl_version
                    )
                if result.security_metrics.certificate_valid is not None:
                    sec_table.add_row(
                        "Certificate Valid",
                        "Yes" if result.security_metrics.certificate_valid else "No",
                    )
                if result.security_metrics.certificate_expiry_days:
                    sec_table.add_row(
                        "Certificate Expiry (days)",
                        str(result.security_metrics.certificate_expiry_days),
                    )
                if result.security_metrics.hsts_enabled:
                    sec_table.add_row(
                        "HSTS Enabled",
                        "Yes" if result.security_metrics.hsts_enabled else "No",
                    )
                if result.security_metrics.csp_enabled:
                    sec_table.add_row(
                        "CSP Enabled",
                        "Yes" if result.security_metrics.csp_enabled else "No",
                    )
                if result.security_metrics.open_ports:
                    sec_table.add_row(
                        "Open Ports", str(len(result.security_metrics.open_ports))
                    )

                console.print(sec_table)

            if result.seo_metrics:
                seo_table = Table(
                    show_header=True, header_style="bold blue", title="SEO Metrics"
                )
                seo_table.add_column("Metric", style="cyan")
                seo_table.add_column("Value", style="white")

                if result.seo_metrics.title_length:
                    seo_table.add_row(
                        "Title Length", str(result.seo_metrics.title_length)
                    )
                if result.seo_metrics.description_length:
                    seo_table.add_row(
                        "Meta Description Length",
                        str(result.seo_metrics.description_length),
                    )
                if result.seo_metrics.h1_count:
                    seo_table.add_row("H1 Count", str(result.seo_metrics.h1_count))
                if result.seo_metrics.h2_count:
                    seo_table.add_row("H2 Count", str(result.seo_metrics.h2_count))

                console.print(seo_table)

            if result.accessibility_metrics:
                acc_table = Table(
                    show_header=True,
                    header_style="bold blue",
                    title="Accessibility Metrics",
                )
                acc_table.add_column("Metric", style="cyan")
                acc_table.add_column("Value", style="white")

                if result.accessibility_metrics.aria_issues:
                    acc_table.add_row(
                        "ARIA Issues", str(result.accessibility_metrics.aria_issues)
                    )
                if result.accessibility_metrics.semantic_structure_issues:
                    acc_table.add_row(
                        "Semantic Issues",
                        str(result.accessibility_metrics.semantic_structure_issues),
                    )
                if result.accessibility_metrics.touch_target_issues:
                    acc_table.add_row(
                        "Touch Target Issues",
                        str(result.accessibility_metrics.touch_target_issues),
                    )
                if result.accessibility_metrics.contrast_issues:
                    acc_table.add_row(
                        "Contrast Issues",
                        str(result.accessibility_metrics.contrast_issues),
                    )

                console.print(acc_table)

            if result.visual_metrics:
                vis_table = Table(
                    show_header=True, header_style="bold blue", title="Visual Metrics"
                )
                vis_table.add_column("Metric", style="cyan")
                vis_table.add_column("Value", style="white")

                if result.visual_metrics.layout_issues is not None:
                    vis_table.add_row(
                        "Layout Issues", str(result.visual_metrics.layout_issues)
                    )
                if result.visual_metrics.overlapping_elements is not None:
                    vis_table.add_row(
                        "Overlapping Elements",
                        str(result.visual_metrics.overlapping_elements),
                    )
                if result.visual_metrics.overflow_issues is not None:
                    vis_table.add_row(
                        "Overflow Issues", str(result.visual_metrics.overflow_issues)
                    )
                if result.visual_metrics.color_contrast_issues is not None:
                    vis_table.add_row(
                        "Color Contrast Issues",
                        str(result.visual_metrics.color_contrast_issues),
                    )
                if result.visual_metrics.color_scheme_consistent is not None:
                    vis_table.add_row(
                        "Color Scheme Consistent",
                        str(result.visual_metrics.color_scheme_consistent),
                    )
                if result.visual_metrics.brand_colors_detected:
                    vis_table.add_row(
                        "Brand Colors Detected",
                        str(result.visual_metrics.brand_colors_detected),
                    )
                if result.visual_metrics.button_count is not None:
                    vis_table.add_row(
                        "Button Count", str(result.visual_metrics.button_count)
                    )
                if result.visual_metrics.form_count is not None:
                    vis_table.add_row(
                        "Form Count", str(result.visual_metrics.form_count)
                    )
                if result.visual_metrics.navigation_elements is not None:
                    vis_table.add_row(
                        "Navigation Elements",
                        str(result.visual_metrics.navigation_elements),
                    )
                if result.visual_metrics.responsive_breakpoints:
                    vis_table.add_row(
                        "Responsive Breakpoints",
                        str(result.visual_metrics.responsive_breakpoints),
                    )
                if result.visual_metrics.mobile_friendly is not None:
                    vis_table.add_row(
                        "Mobile Friendly", str(result.visual_metrics.mobile_friendly)
                    )
                if result.visual_metrics.tablet_friendly is not None:
                    vis_table.add_row(
                        "Tablet Friendly", str(result.visual_metrics.tablet_friendly)
                    )
                if result.visual_metrics.screenshots:
                    for device, path in result.visual_metrics.screenshots.items():
                        vis_table.add_row(f"Screenshot ({device})", str(path))
                if result.visual_metrics.screenshot_path:
                    vis_table.add_row(
                        "Screenshot Path", str(result.visual_metrics.screenshot_path)
                    )
                if result.visual_metrics.dominant_colors:
                    vis_table.add_row(
                        "Dominant Colors", str(result.visual_metrics.dominant_colors)
                    )
                if result.visual_metrics.navigation_issues is not None:
                    vis_table.add_row(
                        "Navigation Issues",
                        str(result.visual_metrics.navigation_issues),
                    )
                if result.visual_metrics.color_palette_size is not None:
                    vis_table.add_row(
                        "Color Palette Size",
                        str(result.visual_metrics.color_palette_size),
                    )

                console.print(vis_table)

            if result.content_metrics:
                content_table = Table(
                    show_header=True, header_style="bold blue", title="Content Metrics"
                )
                content_table.add_column("Metric", style="cyan")
                content_table.add_column("Value", style="white")

                if result.content_metrics.word_count:
                    content_table.add_row(
                        "Word Count", str(result.content_metrics.word_count)
                    )
                if result.content_metrics.character_count:
                    content_table.add_row(
                        "Character Count", str(result.content_metrics.character_count)
                    )
                if result.content_metrics.sentence_count:
                    content_table.add_row(
                        "Sentence Count", str(result.content_metrics.sentence_count)
                    )
                if result.content_metrics.paragraph_count:
                    content_table.add_row(
                        "Paragraph Count", str(result.content_metrics.paragraph_count)
                    )
                if result.content_metrics.readability_score:
                    content_table.add_row(
                        "Readability Score",
                        str(result.content_metrics.readability_score),
                    )
                if result.content_metrics.complex_sentences:
                    content_table.add_row(
                        "Complex Sentences",
                        str(result.content_metrics.complex_sentences),
                    )
                if result.content_metrics.spelling_errors:
                    content_table.add_row(
                        "Spelling Errors", str(result.content_metrics.spelling_errors)
                    )
                if result.content_metrics.grammar_issues:
                    content_table.add_row(
                        "Grammar Issues", str(result.content_metrics.grammar_issues)
                    )
                if result.content_metrics.duplicate_content_ratio:
                    content_table.add_row(
                        "Duplicate Content Ratio",
                        str(result.content_metrics.duplicate_content_ratio),
                    )
                if result.content_metrics.heading_structure_issues:
                    content_table.add_row(
                        "Heading Structure Issues",
                        str(result.content_metrics.heading_structure_issues),
                    )
                if result.content_metrics.paragraph_length_issues:
                    content_table.add_row(
                        "Paragraph Length Issues",
                        str(result.content_metrics.paragraph_length_issues),
                    )
                if result.content_metrics.content_age_days:
                    content_table.add_row(
                        "Content Age (days)",
                        str(result.content_metrics.content_age_days),
                    )
                if result.content_metrics.last_modified:
                    content_table.add_row(
                        "Last Modified", str(result.content_metrics.last_modified)
                    )
                if result.content_metrics.publication_date:
                    content_table.add_row(
                        "Publication Date", str(result.content_metrics.publication_date)
                    )
                if result.content_metrics.content_quality_score:
                    content_table.add_row(
                        "Content Quality Score",
                        str(result.content_metrics.content_quality_score),
                    )
                if result.content_metrics.structure_score:
                    content_table.add_row(
                        "Structure Score", str(result.content_metrics.structure_score)
                    )

                console.print(content_table)

            # Show detailed issues with enhanced information
            if not result.detailed_issues:
                console.print("[green]✓[/green] No issues found")
            else:
                # Create enhanced table for detailed issues
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Type", style="cyan")
                table.add_column("Severity", style="yellow")
                table.add_column("Message", style="white")
                table.add_column("Technical Details", style="dim")
                table.add_column("Fix Suggestions", style="green")

                for issue in result.detailed_issues:
                    severity_color = {
                        "low": "green",
                        "medium": "yellow",
                        "high": "red",
                        "critical": "bold red",
                    }.get(issue.severity.value, "white")

                    # Format technical details
                    tech_details = ""
                    if issue.technical_details:
                        key_details = []
                        for k, v in issue.technical_details.items():
                            if isinstance(v, (str, int, float)) and len(str(v)) < 50:
                                key_details.append(f"{k}: {v}")
                        tech_details = ", ".join(
                            key_details[:3]
                        )  # Show first 3 details

                    # Format fix suggestions
                    fix_suggestions = ""
                    if issue.fix_suggestions:
                        fix_suggestions = "; ".join(
                            issue.fix_suggestions[:2]
                        )  # Show first 2 suggestions

                    table.add_row(
                        issue.issue_type.replace("_", " ").title(),
                        f"[{severity_color}]{issue.severity.value.upper()}[/{severity_color}]",
                        issue.message,
                        tech_details,
                        fix_suggestions,
                    )

                console.print(table)

                # Show additional detailed information for each issue
                for issue in result.detailed_issues:
                    console.print(
                        f"\n[bold]{issue.issue_type.replace('_', ' ').title()}[/bold]"
                    )
                    console.print(f"  [dim]Description:[/dim] {issue.description}")
                    console.print(f"  [dim]Impact:[/dim] {issue.impact}")
                    console.print(
                        f"  [dim]Priority Score:[/dim] {issue.priority_score}"
                    )

                    if issue.recommendations:
                        console.print("  [dim]Recommendations:[/dim]")
                        for rec in issue.recommendations:
                            console.print(f"    • {rec}")

                    if issue.code_location and issue.code_location.element_selector:
                        console.print(
                            f"  [dim]Element:[/dim] {issue.code_location.element_selector}"
                        )

                    if issue.browser_console_errors:
                        console.print(
                            f"  [dim]Console Errors:[/dim] {len(issue.browser_console_errors)} found"
                        )
                        for error in issue.browser_console_errors[
                            :2
                        ]:  # Show first 2 errors
                            console.print(f"    • {error}")

                    if issue.network_errors:
                        console.print(
                            f"  [dim]Network Errors:[/dim] {len(issue.network_errors)} found"
                        )
                        for error in issue.network_errors[:2]:  # Show first 2 errors
                            console.print(f"    • {error}")

            # Summary for this dwarf
            if result.detailed_issues:
                console.print(
                    f"\n[dim]Total issues found: {len(result.detailed_issues)}[/dim]"
                )

                # Issue breakdown by severity
                severity_counts: dict[str, int] = {}
                for issue in result.detailed_issues:
                    severity_counts[issue.severity.value] = (
                        severity_counts.get(issue.severity.value, 0) + 1
                    )

                if severity_counts:
                    console.print("[dim]By severity:[/dim]", end=" ")
                    severity_parts = []
                    for severity, count in severity_counts.items():
                        color = {
                            "low": "green",
                            "medium": "yellow",
                            "high": "red",
                            "critical": "bold red",
                        }.get(severity, "white")
                        severity_parts.append(f"[{color}]{severity}: {count}[/{color}]")
                    console.print(" | ".join(severity_parts))


def _save_comprehensive_results(
    report: ComprehensiveAnalysisReport,
    output_path: Path,
    output_format: str,
    pdf_type: str = "comprehensive",
    llm_results: dict | None = None,
) -> None:
    """Save comprehensive results to a file."""
    if output_format.lower() == "json":
        import json

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, default=str, indent=2, ensure_ascii=False)
    elif output_format.lower() == "pdf":
        from ..reporting import PDFReportGenerator

        generator = PDFReportGenerator(
            report_type=pdf_type, llm_results=llm_results or {}
        )
        generator.generate_report(report, output_path)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("NetzZwergenWacht Comprehensive Analysis Report\n")
            f.write("=" * 50 + "\n\n")

            f.write(f"URL: {report.url}\n")
            f.write(f"Timestamp: {report.timestamp}\n")
            f.write(
                f"Analysis Duration: {report.analysis_duration_seconds:.2f} seconds\n"
            )
            f.write(f"Overall Score: {report.overall_score or 'N/A'}\n\n")

            f.write(f"Total Issues: {report.total_issues}\n")
            f.write(f"Critical: {report.critical_issues}\n")
            f.write(f"High: {report.high_issues}\n")
            f.write(f"Medium: {report.medium_issues}\n")
            f.write(f"Low: {report.low_issues}\n\n")

            if report.top_recommendations:
                f.write("Top Recommendations:\n")
                for i, rec in enumerate(report.top_recommendations, 1):
                    f.write(f"  {i}. {rec}\n")
                f.write("\n")

            if report.priority_actions:
                f.write("Priority Actions:\n")
                for i, action in enumerate(report.priority_actions, 1):
                    f.write(f"  {i}. {action}\n")
                f.write("\n")

            f.write("Detailed Results:\n")
            f.write("-" * 20 + "\n")

            for result in report.dwarf_results:
                f.write(f"\n{result.dwarf_name}:\n")
                if not result.success:
                    f.write(f"  Error: {result.error_message}\n")
                    continue

                f.write(f"  Issues: {len(result.detailed_issues)}\n")
                for issue in result.detailed_issues:
                    f.write(
                        f"    [{issue.severity.value.upper()}] {issue.issue_type}: {issue.message}\n"
                    )
                    if issue.recommendations:
                        f.write(
                            f"      Recommendations: {', '.join(issue.recommendations)}\n"
                        )


def _display_results(results: list, verbose: bool = False) -> None:
    """Display analysis results in the console."""
    for result in results:
        # Display dwarf header
        console.print(f"\n[bold cyan]{result.dwarf_name}[/bold cyan]")

        if not result.success:
            console.print(f"[red]Error:[/red] {result.error_message}")
            continue

        # Show metadata in verbose mode
        if verbose and result.metadata:
            metadata_table = Table(
                show_header=True, header_style="bold blue", title="Scan Results"
            )
            metadata_table.add_column("Metric", style="cyan")
            metadata_table.add_column("Value", style="white")

            for key, value in result.metadata.items():
                # Format key for display
                display_key = key.replace("_", " ").title()

                # Format value based on type
                if key == "response_time_ms":
                    display_value = f"{value} ms"
                elif key == "content_length":
                    display_value = f"{value:,} bytes"
                elif key == "redirected":
                    display_value = "Yes" if value else "No"
                else:
                    display_value = str(value)

                metadata_table.add_row(display_key, display_value)

            console.print(metadata_table)

        if not result.issues:
            console.print("[green]✓[/green] No issues found")
        else:
            # Create table for issues
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Type", style="cyan")
            table.add_column("Severity", style="yellow")
            table.add_column("Message", style="white")
            if verbose:
                table.add_column("Evidence", style="dim")

            for issue in result.issues:
                severity_color = {
                    "low": "green",
                    "medium": "yellow",
                    "high": "red",
                    "critical": "bold red",
                }.get(issue.severity.value, "white")

                row_data = [
                    issue.issue_type.replace("_", " ").title(),
                    f"[{severity_color}]{issue.severity.value.upper()}[/{severity_color}]",
                    issue.message,
                ]

                if verbose:
                    # Show key evidence in verbose mode
                    evidence_str = ""
                    if issue.evidence:
                        key_evidence = []
                        for k, v in issue.evidence.items():
                            if k in [
                                "status_code",
                                "response_time_seconds",
                                "title_length",
                                "h1_count",
                                "total_images",
                                "missing_alt_count",
                                "wcag_guideline",
                                "eaa_requirement",
                                "recommendation",
                                "contrast_issues_count",
                                "non_focusable_elements",
                                "duplicate_ids",
                                "invalid_roles_count",
                            ]:
                                key_evidence.append(f"{k}: {v}")
                        evidence_str = ", ".join(key_evidence)
                    row_data.append(evidence_str)

                table.add_row(*row_data)

            console.print(table)

        if verbose and result.issues:
            # Summary
            console.print(f"\n[dim]Total issues found: {len(result.issues)}[/dim]")

            # Issue breakdown by severity
            severity_counts: dict[str, int] = {}
            for issue in result.issues:
                severity_counts[issue.severity.value] = (
                    severity_counts.get(issue.severity.value, 0) + 1
                )

            if severity_counts:
                console.print("[dim]By severity:[/dim]", end=" ")
                severity_parts = []
                for severity, count in severity_counts.items():
                    color = {
                        "low": "green",
                        "medium": "yellow",
                        "high": "red",
                        "critical": "bold red",
                    }.get(severity, "white")
                    severity_parts.append(f"[{color}]{severity}: {count}[/{color}]")
                console.print(" | ".join(severity_parts))


def _save_results(results: list, output_path: Path, output_format: str) -> None:
    """Save results to a file."""
    if output_format.lower() == "json":
        # Convert results to JSON-serializable format
        import json
        from datetime import datetime

        json_data = {
            "timestamp": datetime.now().isoformat(),
            "total_dwarfs": len(results),
            "dwarfs": [],
        }

        for result in results:
            dwarf_data = {
                "dwarf_name": result.dwarf_name,
                "url": result.url,
                "success": result.success,
                "error_message": result.error_message if not result.success else None,
                "issues_count": len(result.issues),
                "issues": [],
            }

            if result.success:
                # Add metadata
                if result.metadata:
                    dwarf_data["metadata"] = result.metadata

                # Add issues
                for issue in result.issues:
                    issue_data = {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "message": issue.message,
                        "evidence": issue.evidence or {},
                    }
                    dwarf_data["issues"].append(issue_data)

            json_data["dwarfs"].append(dwarf_data)

        # Write JSON file
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

    else:
        # Default text format
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("NetzZwergenWacht Analysis Results\n")
            f.write("=" * 40 + "\n\n")

            for result in results:
                f.write(f"Dwarf: {result.dwarf_name}\n")
                f.write(f"URL: {result.url}\n")
                f.write(f"Success: {result.success}\n")

                if result.error_message:
                    f.write(f"Error: {result.error_message}\n")

                f.write(f"Issues found: {len(result.issues)}\n")

                for issue in result.issues:
                    f.write(
                        f"  - {issue.issue_type}: {issue.message} ({issue.severity.value})\n"
                    )

                f.write("\n")


def _ensure_output_path(output_path: Path) -> Path:
    """Ensure the output file is saved to the output/ directory."""
    # Create output directory if it doesn't exist
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # If the path is already in output/, use it as is
    if output_path.parts[0] == "output":
        return output_path

    # Otherwise, place it in the output/ directory
    return output_dir / output_path.name


if __name__ == "__main__":
    app()
