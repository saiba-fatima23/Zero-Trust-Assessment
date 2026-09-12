"""
Lightweight, rule-based web security scanner.

Checks a target's HTTP response headers, TLS certificate, and basic
transport-security posture, then produces a 0-100 risk score.
This is a heuristic assessment tool for educational use, not a
substitute for a professional penetration test.
"""

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 6
MAX_REDIRECTS = 5

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 20,
        "advice": "Add HSTS to force browsers to always use HTTPS for this domain.",
    },
    "Content-Security-Policy": {
        "weight": 20,
        "advice": "Add a Content-Security-Policy to restrict script/style sources and reduce XSS impact.",
    },
    "X-Frame-Options": {
        "weight": 12,
        "advice": "Add X-Frame-Options (or frame-ancestors in CSP) to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "weight": 8,
        "advice": "Add X-Content-Type-Options: nosniff to stop MIME-type sniffing.",
    },
    "Referrer-Policy": {
        "weight": 5,
        "advice": "Add a Referrer-Policy to limit referrer information leakage.",
    },
    "Permissions-Policy": {
        "weight": 5,
        "advice": "Add a Permissions-Policy to restrict access to sensitive browser features.",
    },
}


class ScanError(Exception):
    pass


def _normalize_target(raw_target: str) -> str:
    raw_target = raw_target.strip()
    if not raw_target:
        raise ScanError("Please provide a target URL or domain.")
    if "://" not in raw_target:
        raw_target = "https://" + raw_target
    return raw_target


def _assert_public_host(hostname: str):
    """Block scanning of loopback / private / link-local / cloud-metadata targets."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ScanError(f"Could not resolve host: {hostname}")

    for info in infos:
        ip_str = info[4][0]
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or str(ip) == "169.254.169.254"  # cloud metadata endpoint
        ):
            raise ScanError(
                "Scanning private, loopback, or link-local addresses is not allowed."
            )


def _check_headers(headers) -> list:
    findings = []
    # requests' headers object is case-insensitive
    for name, meta in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append({
                "check": f"Missing header: {name}",
                "severity": "high" if meta["weight"] >= 15 else "medium",
                "detail": meta["advice"],
                "weight": meta["weight"],
            })

    server = headers.get("Server")
    if server:
        findings.append({
            "check": "Server header discloses software/version",
            "severity": "low",
            "detail": f"Server responded with '{server}'. Consider suppressing or genericizing this header.",
            "weight": 3,
        })

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        findings.append({
            "check": "X-Powered-By header discloses backend technology",
            "severity": "low",
            "detail": f"X-Powered-By: {powered_by}. Consider removing this header.",
            "weight": 3,
        })

    return findings


def _check_https_redirect(parsed_url) -> list:
    findings = []
    if parsed_url.scheme != "https":
        try:
            resp = requests.get(
                f"http://{parsed_url.netloc}",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code not in (301, 302, 307, 308) or not resp.headers.get(
                "Location", ""
            ).startswith("https://"):
                findings.append({
                    "check": "No automatic HTTP -> HTTPS redirect",
                    "severity": "high",
                    "detail": "Plain HTTP requests are not redirected to HTTPS, so traffic can be sent unencrypted.",
                    "weight": 15,
                })
        except requests.RequestException:
            pass
    return findings


def _check_tls_certificate(hostname: str) -> list:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (not_after - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append({
                        "check": "TLS certificate expired",
                        "severity": "high",
                        "detail": f"Certificate expired on {not_after.date()}.",
                        "weight": 20,
                    })
                elif days_left < 14:
                    findings.append({
                        "check": "TLS certificate expiring soon",
                        "severity": "medium",
                        "detail": f"Certificate expires in {days_left} day(s) ({not_after.date()}).",
                        "weight": 8,
                    })
    except ssl.SSLCertVerificationError as exc:
        findings.append({
            "check": "TLS certificate could not be verified",
            "severity": "high",
            "detail": str(exc),
            "weight": 20,
        })
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        findings.append({
            "check": "Could not establish an HTTPS/TLS connection on port 443",
            "severity": "medium",
            "detail": "The site may not support HTTPS at all, which is itself a significant risk.",
            "weight": 15,
        })
    return findings


def run_scan(raw_target: str) -> dict:
    """Run the scan and return a dict with score, level, and findings."""
    target = _normalize_target(raw_target)
    parsed = urlparse(target)
    hostname = parsed.hostname
    if not hostname:
        raise ScanError("That doesn't look like a valid URL or domain.")

    _assert_public_host(hostname)

    try:
        response = requests.get(
            target,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except requests.exceptions.SSLError:
        raise ScanError("TLS/SSL handshake failed — the certificate may be invalid or self-signed.")
    except requests.exceptions.ConnectionError:
        raise ScanError(f"Could not connect to {target}.")
    except requests.exceptions.Timeout:
        raise ScanError(f"Connection to {target} timed out.")
    except requests.RequestException as exc:
        raise ScanError(f"Request failed: {exc}")

    findings = []
    findings += _check_headers(response.headers)
    findings += _check_https_redirect(parsed)
    findings += _check_tls_certificate(hostname)

    total_weight = sum(f["weight"] for f in findings)
    risk_score = max(0, 100 - total_weight)

    if risk_score >= 85:
        risk_level = "Low"
    elif risk_score >= 60:
        risk_level = "Medium"
    elif risk_score >= 35:
        risk_level = "High"
    else:
        risk_level = "Critical"

    findings.sort(key=lambda f: f["weight"], reverse=True)

    return {
        "target": target,
        "final_url": response.url,
        "status_code": response.status_code,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
