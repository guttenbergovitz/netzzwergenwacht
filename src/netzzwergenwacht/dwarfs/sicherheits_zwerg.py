"""Sicherheits-Zwerg for security analysis."""

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
import nmap

from .base import (
    AnalysisResult,
    CodeLocation,
    DetailedAnalysisResult,
    DetailedIssue,
    Dwarf,
    Issue,
    SecurityMetrics,
    Severity,
)


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
                            for h in list(response.headers.keys())
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

                    # Advanced security scanning
                    (
                        advanced_issues,
                        advanced_metadata,
                    ) = await self._advanced_security_scan(
                        parsed_url.hostname,
                        parsed_url.port
                        or (443 if parsed_url.scheme == "https" else 80),
                    )
                    issues.extend(advanced_issues)
                    metadata.update(advanced_metadata)

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
        headers = {k.lower(): v for k, v in dict(response.headers).items()}

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

    async def _advanced_security_scan(
        self, hostname: str, port: int
    ) -> tuple[list[Issue], dict]:
        """Perform advanced security scanning including port scanning and vulnerability assessment."""
        issues = []
        metadata = {}

        try:
            # Port scanning
            port_scan_issues, port_metadata = await self._scan_ports(hostname, port)
            issues.extend(port_scan_issues)
            metadata.update(port_metadata)

            # Service enumeration
            service_issues, service_metadata = await self._enumerate_services(
                hostname, port
            )
            issues.extend(service_issues)
            metadata.update(service_metadata)

            # Security misconfiguration checks
            (
                misconfig_issues,
                misconfig_metadata,
            ) = await self._check_security_misconfigurations(hostname, port)
            issues.extend(misconfig_issues)
            metadata.update(misconfig_metadata)

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="advanced_security_scan_failed",
                    severity=Severity.LOW,
                    message=f"Advanced security scan failed: {str(e)}",
                    location=hostname,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def _scan_ports(
        self, hostname: str, target_port: int
    ) -> tuple[list[Issue], dict]:
        """Scan for open ports and potential security issues."""
        issues = []
        metadata = {}

        try:
            # Use nmap for port scanning in executor to avoid blocking
            def run_nmap_scan():
                nm = nmap.PortScanner()
                scan_range = f"{hostname}"
                nm.scan(scan_range, arguments="-sT -T4 --top-ports 100")
                return nm

            nm = await asyncio.get_event_loop().run_in_executor(None, run_nmap_scan)

            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    open_ports.extend(ports)

            metadata["open_ports_count"] = len(open_ports)
            metadata["open_ports"] = sorted(open_ports)

            # Check for potentially dangerous open ports
            dangerous_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                27017: "MongoDB",
                8080: "HTTP-Alt",
                8443: "HTTPS-Alt",
            }

            dangerous_open_ports = []
            for port in open_ports:
                if port in dangerous_ports:
                    dangerous_open_ports.append({
                        "port": port,
                        "service": dangerous_ports[port],
                        "risk_level": "high"
                        if port in [21, 23, 25, 110, 143]
                        else "medium",
                    })

            metadata["dangerous_ports"] = dangerous_open_ports

            # Create issues for dangerous ports
            for port_info in dangerous_open_ports:
                if port_info["risk_level"] == "high":
                    issues.append(
                        self.create_issue(
                            issue_type="dangerous_port_open",
                            severity=Severity.HIGH,
                            message=f"Dangerous port {port_info['port']} ({port_info['service']}) is open",
                            location=hostname,
                            evidence={
                                "port": port_info["port"],
                                "service": port_info["service"],
                                "risk_level": port_info["risk_level"],
                                "recommendation": "Close unnecessary ports or restrict access",
                            },
                        )
                    )
                elif port_info["risk_level"] == "medium":
                    issues.append(
                        self.create_issue(
                            issue_type="potentially_dangerous_port_open",
                            severity=Severity.MEDIUM,
                            message=f"Potentially dangerous port {port_info['port']} ({port_info['service']}) is open",
                            location=hostname,
                            evidence={
                                "port": port_info["port"],
                                "service": port_info["service"],
                                "risk_level": port_info["risk_level"],
                                "recommendation": "Review if this port is necessary",
                            },
                        )
                    )

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="port_scan_failed",
                    severity=Severity.LOW,
                    message=f"Port scanning failed: {str(e)}",
                    location=hostname,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def _enumerate_services(
        self, hostname: str, port: int
    ) -> tuple[list[Issue], dict]:
        """Enumerate services running on the target host."""
        issues = []
        metadata = {}

        try:
            # Try to identify services on common ports
            common_services = {
                80: "HTTP",
                443: "HTTPS",
                22: "SSH",
                21: "FTP",
                25: "SMTP",
                53: "DNS",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                27017: "MongoDB",
                8080: "HTTP-Alt",
                8443: "HTTPS-Alt",
            }

            detected_services = []

            for service_port, service_name in common_services.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((hostname, service_port))
                    sock.close()

                    if result == 0:
                        detected_services.append({
                            "port": service_port,
                            "service": service_name,
                            "status": "open",
                        })

                        # Check for default credentials or misconfigurations
                        if service_name in ["MySQL", "PostgreSQL", "Redis", "MongoDB"]:
                            issues.append(
                                self.create_issue(
                                    issue_type="database_service_exposed",
                                    severity=Severity.HIGH,
                                    message=f"Database service {service_name} is exposed on port {service_port}",
                                    location=hostname,
                                    evidence={
                                        "service": service_name,
                                        "port": service_port,
                                        "recommendation": "Restrict database access to internal networks only",
                                    },
                                )
                            )

                except OSError:
                    # Expected behavior when services are not available
                    continue

            metadata["detected_services"] = detected_services
            metadata["services_count"] = len(detected_services)

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="service_enumeration_failed",
                    severity=Severity.LOW,
                    message=f"Service enumeration failed: {str(e)}",
                    location=hostname,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def _check_security_misconfigurations(
        self, hostname: str, port: int
    ) -> tuple[list[Issue], dict]:
        """Check for common security misconfigurations."""
        issues = []
        metadata = {}

        try:
            # Check for information disclosure
            info_disclosure_checks = [
                {
                    "path": "/robots.txt",
                    "description": "robots.txt file",
                    "severity": Severity.LOW,
                },
                {
                    "path": "/.well-known/security.txt",
                    "description": "security.txt file",
                    "severity": Severity.LOW,
                },
                {
                    "path": "/sitemap.xml",
                    "description": "sitemap.xml file",
                    "severity": Severity.LOW,
                },
                {
                    "path": "/.git/HEAD",
                    "description": "Git repository exposure",
                    "severity": Severity.HIGH,
                },
                {
                    "path": "/.env",
                    "description": "Environment file exposure",
                    "severity": Severity.HIGH,
                },
                {
                    "path": "/wp-config.php",
                    "description": "WordPress configuration exposure",
                    "severity": Severity.HIGH,
                },
                {
                    "path": "/phpinfo.php",
                    "description": "PHP info exposure",
                    "severity": Severity.HIGH,
                },
                {
                    "path": "/server-status",
                    "description": "Apache server status",
                    "severity": Severity.MEDIUM,
                },
            ]

            scheme = "https" if port == 443 else "http"
            base_url = f"{scheme}://{hostname}"

            exposed_files = []

            async with httpx.AsyncClient(timeout=5.0) as client:
                for check in info_disclosure_checks:
                    try:
                        response = await client.get(f"{base_url}{check['path']}")
                        if response.status_code == 200:
                            exposed_files.append({
                                "path": check["path"],
                                "description": check["description"],
                                "severity": check["severity"].value,
                            })

                            issues.append(
                                self.create_issue(
                                    issue_type="information_disclosure",
                                    severity=check["severity"],
                                    message=f"Information disclosure: {check['description']} is accessible",
                                    location=f"{base_url}{check['path']}",
                                    evidence={
                                        "path": check["path"],
                                        "description": check["description"],
                                        "status_code": response.status_code,
                                        "recommendation": "Remove or restrict access to sensitive files",
                                    },
                                )
                            )
                    except httpx.RequestError:
                        continue

            metadata["exposed_files"] = exposed_files
            metadata["exposed_files_count"] = len(exposed_files)

        except Exception as e:
            issues.append(
                self.create_issue(
                    issue_type="misconfiguration_check_failed",
                    severity=Severity.LOW,
                    message=f"Security misconfiguration check failed: {str(e)}",
                    location=hostname,
                    evidence={"error": str(e)},
                )
            )

        return issues, metadata

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL for security issues with detailed context and location information."""
        try:
            detailed_issues = []
            security_metrics = SecurityMetrics()
            raw_data = {}

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                detailed_issues.append(
                    self.create_detailed_issue(
                        issue_type="invalid_url_scheme",
                        severity=Severity.HIGH,
                        message="URL must start with http:// or https://",
                        location=url,
                        category="security",
                        subcategory="url_structure",
                        description="The provided URL does not use a valid HTTP scheme",
                        impact="Cannot perform security analysis without valid scheme.",
                        technical_details={"provided_url": url},
                        recommendations=["Use HTTPS URLs for better security."],
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
                    security_metrics=security_metrics,
                    raw_data=raw_data,
                )

            parsed_url = urlparse(url)
            security_metrics.ssl_enabled = parsed_url.scheme == "https"
            raw_data["parsed_url"] = {
                "scheme": parsed_url.scheme,
                "hostname": parsed_url.hostname,
                "port": parsed_url.port,
                "path": parsed_url.path,
            }

            # Check HTTPS enforcement
            https_issues = await self._check_https_enforcement_detailed(url, parsed_url)
            detailed_issues.extend(https_issues)

            # Perform HTTP request for headers analysis
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                try:
                    response = await client.get(url)
                    raw_data["response_headers"] = dict(response.headers)
                    raw_data["final_url"] = str(response.url)

                    # Security headers analysis
                    (
                        headers_issues,
                        headers_metrics,
                    ) = await self._check_security_headers_detailed(response, url)
                    detailed_issues.extend(headers_issues)
                    security_metrics.hsts_enabled = headers_metrics.get(
                        "hsts_enabled", False
                    )
                    security_metrics.csp_enabled = headers_metrics.get(
                        "csp_enabled", False
                    )
                    security_metrics.x_frame_options = headers_metrics.get(
                        "x_frame_options"
                    )
                    security_metrics.x_content_type_options = headers_metrics.get(
                        "x_content_type_options"
                    )
                    security_metrics.referrer_policy = headers_metrics.get(
                        "referrer_policy"
                    )

                    # SSL/TLS analysis (only for HTTPS)
                    if parsed_url.scheme == "https":
                        (
                            ssl_issues,
                            ssl_metrics,
                        ) = await self._check_ssl_certificate_detailed(
                            parsed_url.hostname, parsed_url.port or 443
                        )
                        detailed_issues.extend(ssl_issues)
                        security_metrics.ssl_version = ssl_metrics.get("ssl_version")
                        security_metrics.certificate_valid = ssl_metrics.get(
                            "certificate_valid", False
                        )
                        security_metrics.certificate_expiry_days = ssl_metrics.get(
                            "certificate_expiry_days"
                        )
                        security_metrics.certificate_issuer = ssl_metrics.get(
                            "certificate_issuer"
                        )
                        raw_data["ssl_info"] = ssl_metrics

                    # Advanced security scanning
                    (
                        advanced_issues,
                        advanced_metrics,
                    ) = await self._advanced_security_scan_detailed(
                        parsed_url.hostname,
                        parsed_url.port
                        or (443 if parsed_url.scheme == "https" else 80),
                    )
                    detailed_issues.extend(advanced_issues)
                    security_metrics.open_ports = advanced_metrics.get("open_ports", [])
                    security_metrics.dangerous_services = advanced_metrics.get(
                        "dangerous_services", []
                    )
                    security_metrics.information_disclosure = advanced_metrics.get(
                        "information_disclosure", []
                    )
                    raw_data["port_scan"] = advanced_metrics

                except httpx.RequestError as e:
                    detailed_issues.append(
                        self.create_detailed_issue(
                            issue_type="connection_failed",
                            severity=Severity.HIGH,
                            message=f"Failed to connect for security analysis: {str(e)}",
                            location=url,
                            category="security",
                            subcategory="connection",
                            description="HTTP request failed during security analysis.",
                            impact="Cannot perform security analysis.",
                            technical_details={"error": str(e)},
                            recommendations=[
                                "Check network connectivity and server status."
                            ],
                            code_location=CodeLocation(
                                resource_type="http", attribute_value=url
                            ),
                            priority_score=1.0,
                        )
                    )

            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                detailed_issues=detailed_issues,
                security_metrics=security_metrics,
                raw_data=raw_data,
            )

        except Exception as e:
            return DetailedAnalysisResult(
                url=url,
                dwarf_name=self.name,
                success=False,
                error_message=str(e),
            )

    async def _check_https_enforcement_detailed(
        self, url: str, parsed_url
    ) -> list[DetailedIssue]:
        """Check HTTPS enforcement with detailed context."""
        issues = []

        if parsed_url.scheme == "http":
            https_url = url.replace("http://", "https://", 1)
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(https_url)
                    if response.status_code < 400:
                        issues.append(
                            self.create_detailed_issue(
                                issue_type="http_instead_of_https",
                                severity=Severity.HIGH,
                                message="Site accessible via HTTP but HTTPS is available",
                                location=url,
                                category="security",
                                subcategory="https_enforcement",
                                description="The site is accessible via insecure HTTP when HTTPS is available.",
                                impact="Data transmission is not encrypted, vulnerable to man-in-the-middle attacks.",
                                technical_details={
                                    "https_available": True,
                                    "https_url": https_url,
                                    "https_status": response.status_code,
                                },
                                recommendations=[
                                    "Redirect HTTP to HTTPS or use HTTPS by default."
                                ],
                                fix_suggestions=[
                                    f"Redirect {url} to {https_url}",
                                    "Configure server to redirect HTTP to HTTPS",
                                    "Update all internal links to use HTTPS",
                                ],
                                code_location=CodeLocation(
                                    resource_type="http", attribute_value=url
                                ),
                                affected_elements=["server_config", "redirects"],
                                priority_score=0.9,
                            )
                        )
            except httpx.RequestError:
                issues.append(
                    self.create_detailed_issue(
                        issue_type="no_https_available",
                        severity=Severity.MEDIUM,
                        message="Site only accessible via HTTP (no HTTPS)",
                        location=url,
                        category="security",
                        subcategory="https_enforcement",
                        description="The site is only accessible via insecure HTTP protocol.",
                        impact="All data transmission is unencrypted and vulnerable to interception.",
                        technical_details={"https_available": False},
                        recommendations=["Implement HTTPS with valid SSL certificate."],
                        fix_suggestions=[
                            "Obtain SSL certificate (Let's Encrypt, commercial CA)",
                            "Configure web server for HTTPS",
                            "Update DNS and internal links to use HTTPS",
                        ],
                        code_location=CodeLocation(
                            resource_type="http", attribute_value=url
                        ),
                        affected_elements=["server_config", "ssl_certificate"],
                        priority_score=0.8,
                    )
                )

        return issues

    async def _check_security_headers_detailed(
        self, response: httpx.Response, url: str
    ) -> tuple[list[DetailedIssue], dict]:
        """Check security headers with detailed context and location information."""
        issues = []
        metrics = {}
        headers = {k.lower(): v for k, v in dict(response.headers).items()}

        security_headers_config = {
            "strict-transport-security": {
                "severity": Severity.HIGH,
                "description": "Prevents protocol downgrade attacks",
                "fix_suggestion": 'Add header: "Strict-Transport-Security: max-age=31536000; includeSubDomains"',
                "impact": "Vulnerable to protocol downgrade attacks",
            },
            "x-frame-options": {
                "severity": Severity.MEDIUM,
                "description": "Prevents clickjacking attacks",
                "fix_suggestion": 'Add header: "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN"',
                "impact": "Vulnerable to clickjacking attacks",
            },
            "x-content-type-options": {
                "severity": Severity.MEDIUM,
                "description": "Prevents MIME type sniffing",
                "fix_suggestion": 'Add header: "X-Content-Type-Options: nosniff"',
                "impact": "Vulnerable to MIME type sniffing attacks",
            },
            "content-security-policy": {
                "severity": Severity.MEDIUM,
                "description": "Prevents XSS and injection attacks",
                "fix_suggestion": "Add header: \"Content-Security-Policy: default-src 'self'; script-src 'self'\"",
                "impact": "Vulnerable to XSS and injection attacks",
            },
            "referrer-policy": {
                "severity": Severity.LOW,
                "description": "Controls referrer information",
                "fix_suggestion": 'Add header: "Referrer-Policy: strict-origin-when-cross-origin"',
                "impact": "May leak sensitive information in referrer",
            },
            "permissions-policy": {
                "severity": Severity.LOW,
                "description": "Controls browser features access",
                "fix_suggestion": 'Add header: "Permissions-Policy: geolocation=(), microphone=()"',
                "impact": "May allow unwanted browser feature access",
            },
        }

        for header_name, config in security_headers_config.items():
            if header_name not in headers:
                issues.append(
                    self.create_detailed_issue(
                        issue_type=f"missing_{header_name.replace('-', '_')}_header",
                        severity=config["severity"],
                        message=f"Missing {header_name.replace('-', ' ').title()} header",
                        location=url,
                        category="security",
                        subcategory="security_headers",
                        description=f"Missing {header_name} security header: {config['description']}",
                        impact=config["impact"],
                        technical_details={
                            "header_name": header_name,
                            "description": config["description"],
                            "present_security_headers": list(headers.keys()),
                        },
                        recommendations=[
                            f"Add {header_name} header to server configuration"
                        ],
                        fix_suggestions=[config["fix_suggestion"]],
                        code_location=CodeLocation(
                            resource_type="http_headers",
                            attribute_name=header_name,
                            url_path=url,
                        ),
                        affected_elements=["server_config", "http_headers"],
                        priority_score=0.7
                        if config["severity"] == Severity.HIGH
                        else 0.5,
                    )
                )
            else:
                # Track present headers
                if header_name == "strict-transport-security":
                    metrics["hsts_enabled"] = True
                elif header_name == "content-security-policy":
                    metrics["csp_enabled"] = True
                elif header_name == "x-frame-options":
                    metrics["x_frame_options"] = headers[header_name]
                elif header_name == "x-content-type-options":
                    metrics["x_content_type_options"] = headers[header_name]
                elif header_name == "referrer-policy":
                    metrics["referrer_policy"] = headers[header_name]

        return issues, metrics

    async def _check_ssl_certificate_detailed(
        self, hostname: str, port: int
    ) -> tuple[list[DetailedIssue], dict]:
        """Check SSL certificate with detailed context."""
        issues = []
        metrics = {}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    metrics["ssl_version"] = ssock.version()
                    metrics["certificate_valid"] = True

                    # Check certificate expiry
                    not_after = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    )
                    days_until_expiry = (not_after - datetime.now(UTC)).days
                    metrics["certificate_expiry_days"] = days_until_expiry
                    metrics["certificate_issuer"] = dict(cert["issuer"])

                    if days_until_expiry < 30:
                        issues.append(
                            self.create_detailed_issue(
                                issue_type="ssl_certificate_expiring_soon",
                                severity=Severity.HIGH,
                                message=f"SSL certificate expires in {days_until_expiry} days",
                                location=f"{hostname}:{port}",
                                category="security",
                                subcategory="ssl_certificate",
                                description=f"SSL certificate will expire on {not_after.strftime('%Y-%m-%d')}",
                                impact="Site will become inaccessible when certificate expires",
                                technical_details={
                                    "expiry_date": not_after.isoformat(),
                                    "days_until_expiry": days_until_expiry,
                                    "issuer": dict(cert["issuer"]),
                                },
                                recommendations=[
                                    "Renew SSL certificate before expiration"
                                ],
                                fix_suggestions=[
                                    "Contact certificate authority to renew certificate",
                                    "Update certificate on server",
                                    "Set up automatic renewal (Let's Encrypt)",
                                ],
                                code_location=CodeLocation(
                                    resource_type="ssl",
                                    attribute_value=f"{hostname}:{port}",
                                ),
                                affected_elements=["ssl_certificate"],
                                priority_score=0.9,
                            )
                        )

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="ssl_certificate_invalid",
                    severity=Severity.CRITICAL,
                    message=f"SSL certificate validation failed: {str(e)}",
                    location=f"{hostname}:{port}",
                    category="security",
                    subcategory="ssl_certificate",
                    description="SSL certificate is invalid or cannot be validated",
                    impact="Site is not secure and may be vulnerable to attacks",
                    technical_details={"error": str(e)},
                    recommendations=["Fix SSL certificate configuration"],
                    fix_suggestions=[
                        "Check certificate validity and expiration",
                        "Verify certificate chain",
                        "Update certificate if expired",
                    ],
                    code_location=CodeLocation(
                        resource_type="ssl",
                        attribute_value=f"{hostname}:{port}",
                    ),
                    affected_elements=["ssl_certificate"],
                    priority_score=1.0,
                )
            )
            metrics["certificate_valid"] = False

        return issues, metrics

    async def _advanced_security_scan_detailed(
        self, hostname: str, port: int
    ) -> tuple[list[DetailedIssue], dict]:
        """Perform advanced security scanning with detailed context."""
        issues = []
        metrics = {
            "open_ports": [],
            "dangerous_services": [],
            "information_disclosure": [],
        }

        # Port scanning
        port_issues, port_metrics = await self._scan_ports_detailed(hostname, port)
        issues.extend(port_issues)
        metrics["open_ports"] = port_metrics.get("open_ports", [])

        # Service enumeration
        service_issues, service_metrics = await self._enumerate_services_detailed(
            hostname, port
        )
        issues.extend(service_issues)
        metrics["dangerous_services"] = service_metrics.get("dangerous_services", [])

        # Security misconfigurations
        (
            config_issues,
            config_metrics,
        ) = await self._check_security_misconfigurations_detailed(hostname, port)
        issues.extend(config_issues)
        metrics["information_disclosure"] = config_metrics.get(
            "information_disclosure", []
        )

        return issues, metrics

    async def _scan_ports_detailed(
        self, hostname: str, target_port: int
    ) -> tuple[list[DetailedIssue], dict]:
        """Scan ports with detailed context."""
        issues = []
        metrics = {"open_ports": []}

        try:

            def run_nmap_scan():
                nm = nmap.PortScanner()
                nm.scan(hostname, str(target_port), arguments="-sT -T4")
                return nm

            loop = asyncio.get_event_loop()
            nm = await loop.run_in_executor(None, run_nmap_scan)

            if hostname in nm.all_hosts():
                for proto in nm[hostname].all_protocols():
                    ports = nm[hostname][proto].keys()
                    for port in ports:
                        state = nm[hostname][proto][port]["state"]
                        if state == "open":
                            metrics["open_ports"].append(port)

                            # Check for dangerous ports
                            dangerous_ports = {
                                21: "FTP",
                                22: "SSH",
                                23: "Telnet",
                                25: "SMTP",
                                53: "DNS",
                                80: "HTTP",
                                110: "POP3",
                                143: "IMAP",
                                443: "HTTPS",
                                3306: "MySQL",
                                5432: "PostgreSQL",
                                6379: "Redis",
                                27017: "MongoDB",
                            }

                            if port in dangerous_ports:
                                issues.append(
                                    self.create_detailed_issue(
                                        issue_type="potentially_dangerous_port_open",
                                        severity=Severity.MEDIUM,
                                        message=f"Potentially dangerous port {port} ({dangerous_ports[port]}) is open",
                                        location=f"{hostname}:{port}",
                                        category="security",
                                        subcategory="port_scanning",
                                        description=f"Port {port} ({dangerous_ports[port]}) is accessible from the internet",
                                        impact="May expose sensitive services or be vulnerable to attacks",
                                        technical_details={
                                            "port": port,
                                            "service": dangerous_ports[port],
                                            "risk_level": "medium",
                                        },
                                        recommendations=[
                                            "Review if this port is necessary and secure it"
                                        ],
                                        fix_suggestions=[
                                            f"Close port {port} if not needed",
                                            f"Configure firewall to block port {port}",
                                            f"Secure {dangerous_ports[port]} service with authentication",
                                        ],
                                        code_location=CodeLocation(
                                            resource_type="network",
                                            attribute_value=f"{hostname}:{port}",
                                        ),
                                        affected_elements=[
                                            "firewall",
                                            "network_config",
                                        ],
                                        priority_score=0.6,
                                    )
                                )

        except Exception as e:
            issues.append(
                self.create_detailed_issue(
                    issue_type="port_scan_failed",
                    severity=Severity.LOW,
                    message=f"Port scanning failed: {str(e)}",
                    location=f"{hostname}:{target_port}",
                    category="security",
                    subcategory="port_scanning",
                    description="Could not perform port scanning",
                    impact="Some security vulnerabilities may not be detected",
                    technical_details={"error": str(e)},
                    recommendations=["Check nmap installation and permissions"],
                    code_location=CodeLocation(
                        resource_type="network",
                        attribute_value=f"{hostname}:{target_port}",
                    ),
                    priority_score=0.3,
                )
            )

        return issues, metrics

    async def _enumerate_services_detailed(
        self, hostname: str, port: int
    ) -> tuple[list[DetailedIssue], dict]:
        """Enumerate services with detailed context."""
        # TODO: Implement detailed service enumeration
        return [], {"dangerous_services": []}

    async def _check_security_misconfigurations_detailed(
        self, hostname: str, port: int
    ) -> tuple[list[DetailedIssue], dict]:
        """Check for security misconfigurations with detailed context."""
        # TODO: Implement detailed security misconfiguration checks
        return [], {"information_disclosure": []}
