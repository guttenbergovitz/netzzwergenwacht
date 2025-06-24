"""Main CLI application for NetzZwergenWacht."""

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..dwarfs.base import DwarfOrchestrator
from ..dwarfs.inhalt_zwerg import InhaltZwerg
from ..dwarfs.leistungs_zwerg import LeistungsZwerg
from ..dwarfs.seo_zwerg import SEOZwerg
from ..dwarfs.sicherheits_zwerg import SicherheitsZwerg
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
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    checks: list[str] | None = typer.Option(
        None, "--checks", "-c", help="Specific checks to run"
    ),
):
    """Run quality checks on a website."""
    console.print(f"[bold blue]Analyzing:[/bold blue] {url}")

    # Run analysis
    results = asyncio.run(_run_analysis(url, checks))

    # Display results
    _display_results(results, verbose)

    # Save to file if requested
    if output:
        _save_results(results, output)
        console.print(f"[green]Results saved to:[/green] {output}")


@app.command()
def monitor(config_file: Path = typer.Argument(help="Configuration file path")):
    """Start monitoring websites based on configuration."""
    console.print("[yellow]Monitor command not yet implemented.[/yellow]")
    console.print(f"Configuration file: {config_file}")


@app.command()
def version():
    """Show version information."""
    from .. import __author__, __version__

    panel = Panel(
        f"[bold]NetzZwergenWacht[/bold]\nVersion: {__version__}\nAuthor: {__author__}",
        title="Version Info",
        border_style="blue",
    )
    console.print(panel)


async def _run_analysis(url: str, checks: list[str] | None = None) -> list:
    """Run analysis using Dwarf orchestrator."""
    orchestrator = DwarfOrchestrator()

    # Add available Zwerge
    orchestrator.add_dwarf(WebBrowserZwerg())
    orchestrator.add_dwarf(SicherheitsZwerg())
    orchestrator.add_dwarf(LeistungsZwerg())
    orchestrator.add_dwarf(SEOZwerg())
    orchestrator.add_dwarf(ZugaenglichkeitsZwerg())
    orchestrator.add_dwarf(InhaltZwerg())

    # TODO: Add more Zwerge based on checks parameter

    return await orchestrator.analyze_url(url)


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
            severity_counts = {}
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


def _save_results(results: list, output_path: Path) -> None:
    """Save results to a file."""
    # TODO: Implement JSON/CSV/HTML output formats
    with open(output_path, "w") as f:
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


if __name__ == "__main__":
    app()
