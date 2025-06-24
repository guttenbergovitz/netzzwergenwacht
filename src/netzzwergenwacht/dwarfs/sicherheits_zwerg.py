"""Sicherheits-Zwerg for security analysis."""

import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from .base import AnalysisResult, Dwarf, Issue, Severity


class SicherheitsZwerg(Dwarf):
    """Sicherheits-Zwerg - Analyzes websites for security vulnerabilities and best practices."""

    def __init__(self):
        super().__init__(
            name="Sicherheits-Zwerg",
            description="Security analysis for SSL certificates, headers and vulnerabilities",
        )

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL for security issues."""
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

            parsed_url = urlparse(url)

            # Check HTTPS enforcement
            issues.extend(await self._check_https_enforcement(url, parsed_url))

            # Perform HTTP request for headers analysis
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                try:
                    response = await client.get(url)

                    # Add security metadata
                    metadata.update({
                        "uses_https": parsed_url.scheme == "https",
                        "final_scheme": urlparse(str(response.url)).scheme,
                        "security_headers_count": len([
                            h
                            for h in response.headers.keys()
                            if h.lower().startswith((
                                "x-",
                                "strict-",
                                "content-security",
                            ))
                        ]),
                    })

                    # Analyze security headers
                    issues.extend(await self._check_security_headers(response, url))

                    # SSL/TLS analysis (only for HTTPS)
                    if parsed_url.scheme == "https":
                        ssl_issues, ssl_metadata = await self._check_ssl_certificate(
                            parsed_url.hostname, parsed_url.port or 443
                        )
                        issues.extend(ssl_issues)
                        metadata.update(ssl_metadata)

                except httpx.RequestError as e:
                    issues.append(
                        self.create_issue(
                            issue_type="connection_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to connect for security analysis: {str(e)}",
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

    async def _check_https_enforcement(self, url: str, parsed_url) -> list[Issue]:
        """Check HTTPS enforcement and redirect policies."""
        issues = []

        # Check if using HTTP instead of HTTPS
        if parsed_url.scheme == "http":
            # Try to check if HTTPS is available
            https_url = url.replace("http://", "https://", 1)
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(https_url)
                    if response.status_code < 400:
                        issues.append(
                            self.create_issue(
                                issue_type="http_instead_of_https",
                                severity=Severity.HIGH,
                                message="Site accessible via HTTP but HTTPS is available",
                                location=url,
                                evidence={
                                    "https_available": True,
                                    "https_url": https_url,
                                    "https_status": response.status_code,
                                },
                            )
                        )
            except httpx.RequestError:
                # HTTPS not available - still flag as security concern
                issues.append(
                    self.create_issue(
                        issue_type="no_https_available",
                        severity=Severity.MEDIUM,
                        message="Site only accessible via HTTP (no HTTPS)",
                        location=url,
                        evidence={"https_available": False},
                    )
                )

        return issues

    async def _check_security_headers(
        self, response: httpx.Response, url: str
    ) -> list[Issue]:
        """Check for missing or misconfigured security headers."""
        issues = []
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Critical security headers to check
        security_headers = {
            "strict-transport-security": {
                "severity": Severity.HIGH,
                "message": "Missing HSTS (HTTP Strict Transport Security) header",
                "description": "Prevents protocol downgrade attacks",
            },
            "x-frame-options": {
                "severity": Severity.MEDIUM,
                "message": "Missing X-Frame-Options header",
                "description": "Prevents clickjacking attacks",
            },
            "x-content-type-options": {
                "severity": Severity.MEDIUM,
                "message": "Missing X-Content-Type-Options header",
                "description": "Prevents MIME type sniffing",
            },
            "content-security-policy": {
                "severity": Severity.MEDIUM,
                "message": "Missing Content-Security-Policy header",
                "description": "Prevents XSS and injection attacks",
            },
            "referrer-policy": {
                "severity": Severity.LOW,
                "message": "Missing Referrer-Policy header",
                "description": "Controls referrer information",
            },
            "permissions-policy": {
                "severity": Severity.LOW,
                "message": "Missing Permissions-Policy header",
                "description": "Controls browser features access",
            },
        }

        for header_name, config in security_headers.items():
            if header_name not in headers:
                issues.append(
                    self.create_issue(
                        issue_type=f"missing_{header_name.replace('-', '_')}_header",
                        severity=config["severity"],
                        message=config["message"],
                        location=url,
                        evidence={
                            "header_name": header_name,
                            "description": config["description"],
                            "present_security_headers": list(headers.keys()),
                        },
                    )
                )

        # Check for potentially dangerous headers
        dangerous_headers = {
            "server": "Server header exposes server information",
            "x-powered-by": "X-Powered-By header exposes technology stack",
        }

        for header_name, description in dangerous_headers.items():
            if header_name in headers:
                issues.append(
                    self.create_issue(
                        issue_type=f"information_disclosure_{header_name.replace('-', '_')}",
                        severity=Severity.LOW,
                        message=f"Information disclosure: {description}",
                        location=url,
                        evidence={
                            "header_name": header_name,
                            "header_value": headers[header_name],
                            "description": description,
                        },
                    )
                )

        # Validate HSTS if present
        if "strict-transport-security" in headers:
            hsts_value = headers["strict-transport-security"]
            if "max-age=" not in hsts_value.lower():
                issues.append(
                    self.create_issue(
                        issue_type="invalid_hsts_header",
                        severity=Severity.MEDIUM,
                        message="HSTS header present but missing max-age directive",
                        location=url,
                        evidence={"hsts_value": hsts_value},
                    )
                )
            else:
                # Extract max-age value
                try:
                    max_age_part = [
                        part
                        for part in hsts_value.split(";")
                        if "max-age=" in part.lower()
                    ][0]
                    max_age = int(max_age_part.split("=")[1].strip())
                    if max_age < 31536000:  # 1 year in seconds
                        issues.append(
                            self.create_issue(
                                issue_type="weak_hsts_max_age",
                                severity=Severity.LOW,
                                message=f"HSTS max-age is only {max_age} seconds (recommended: 31536000+)",
                                location=url,
                                evidence={
                                    "hsts_max_age": max_age,
                                    "recommended_min": 31536000,
                                },
                            )
                        )
                except (IndexError, ValueError):
                    issues.append(
                        self.create_issue(
                            issue_type="invalid_hsts_max_age",
                            severity=Severity.MEDIUM,
                            message="HSTS header has invalid max-age value",
                            location=url,
                            evidence={"hsts_value": hsts_value},
                        )
                    )

        return issues

    async def _check_ssl_certificate(
        self, hostname: str, port: int
    ) -> tuple[list[Issue], dict]:
        """Check SSL certificate validity and configuration."""
        issues = []
        metadata = {}

        try:
            # Get SSL certificate info
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Add SSL metadata
                    metadata.update({
                        "ssl_version": version,
                        "ssl_cipher": cipher[0] if cipher else None,
                        "ssl_cipher_strength": cipher[2] if cipher else None,
                        "certificate_subject": dict(
                            x[0] for x in cert.get("subject", [])
                        ),
                        "certificate_issuer": dict(
                            x[0] for x in cert.get("issuer", [])
                        ),
                    })

                    # Check certificate expiry
                    if "notAfter" in cert:
                        not_after_str = cert["notAfter"]
                        # Parse the certificate date (format: 'Oct  1 12:00:00 2024 GMT')
                        try:
                            not_after = datetime.strptime(
                                not_after_str, "%b %d %H:%M:%S %Y %Z"
                            )
                            not_after = not_after.replace(tzinfo=UTC)
                            now = datetime.now(UTC)
                            days_until_expiry = (not_after - now).days

                            metadata["ssl_expires_in_days"] = days_until_expiry
                            metadata["ssl_expiry_date"] = not_after_str

                            if days_until_expiry < 0:
                                issues.append(
                                    self.create_issue(
                                        issue_type="ssl_certificate_expired",
                                        severity=Severity.CRITICAL,
                                        message=f"SSL certificate expired {abs(days_until_expiry)} days ago",
                                        location=f"https://{hostname}",
                                        evidence={
                                            "expiry_date": not_after_str,
                                            "days_expired": abs(days_until_expiry),
                                        },
                                    )
                                )
                            elif days_until_expiry < 30:
                                issues.append(
                                    self.create_issue(
                                        issue_type="ssl_certificate_expiring_soon",
                                        severity=Severity.HIGH,
                                        message=f"SSL certificate expires in {days_until_expiry} days",
                                        location=f"https://{hostname}",
                                        evidence={
                                            "expiry_date": not_after_str,
                                            "days_until_expiry": days_until_expiry,
                                        },
                                    )
                                )
                        except ValueError as e:
                            issues.append(
                                self.create_issue(
                                    issue_type="ssl_certificate_date_parse_error",
                                    severity=Severity.LOW,
                                    message=f"Could not parse SSL certificate expiry date: {e}",
                                    location=f"https://{hostname}",
                                    evidence={"raw_date": not_after_str},
                                )
                            )

                    # Check for weak SSL/TLS versions
                    if version and version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        issues.append(
                            self.create_issue(
                                issue_type="weak_ssl_version",
                                severity=Severity.HIGH,
                                message=f"Weak SSL/TLS version: {version}",
                                location=f"https://{hostname}",
                                evidence={
                                    "ssl_version": version,
                                    "recommended_min": "TLSv1.2",
                                },
                            )
                        )

                    # Check cipher strength
                    if cipher and len(cipher) > 2 and cipher[2] < 128:
                        issues.append(
                            self.create_issue(
                                issue_type="weak_ssl_cipher",
                                severity=Severity.MEDIUM,
                                message=f"Weak SSL cipher strength: {cipher[2]} bits",
                                location=f"https://{hostname}",
                                evidence={
                                    "cipher_name": cipher[0],
                                    "cipher_strength": cipher[2],
                                    "recommended_min": 128,
                                },
                            )
                        )

        except TimeoutError:
            issues.append(
                self.create_issue(
                    issue_type="ssl_connection_timeout",
                    severity=Severity.MEDIUM,
                    message="SSL connection timeout during certificate check",
                    location=f"https://{hostname}",
                    evidence={"timeout_seconds": 10},
                )
            )
        except ssl.SSLError as e:
            issues.append(
                self.create_issue(
                    issue_type="ssl_connection_error",
                    severity=Severity.HIGH,
                    message=f"SSL connection error: {str(e)}",
                    location=f"https://{hostname}",
                    evidence={"ssl_error": str(e)},
                )
            )
        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="ssl_analysis_error",
                    severity=Severity.LOW,
                    message=f"Error during SSL analysis: {str(e)}",
                    location=f"https://{hostname}",
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata
