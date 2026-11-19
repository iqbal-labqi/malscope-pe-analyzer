"""
MalScope (PE-Sentry) - Static String & IOC Extractor
Member 4: IOC Extractor

Extracts printable ASCII and UTF-16LE (Unicode) strings from a PE binary and
uses regular expressions + validation filters to identify Indicators of
Compromise (IOCs): IPv4 addresses, URLs, domain names, and Windows Registry keys.
"""

import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, List


ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,10})\b"
)
REGISTRY_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|"
    r"HKEY_USERS|HKU|HKEY_CURRENT_CONFIG)\\[^\s\"'<>]+",
    re.IGNORECASE,
)

# Ignore common binary/file extensions so DLLs or filenames are not mistaken for domains
IGNORED_TLDS = {
    "dll",
    "exe",
    "sys",
    "drv",
    "ocx",
    "cpl",
    "scr",
    "pdb",
    "obj",
    "lib",
    "txt",
    "log",
    "ini",
    "cfg",
    "xml",
    "json",
    "manifest",
    "bin",
    "dat",
}


def extract_printable_strings(raw_bytes: bytes) -> List[str]:
    """Extract printable ASCII and UTF-16LE strings (length >= 4) from raw bytes."""
    strings: List[str] = []

    for match in ASCII_STRING_RE.finditer(raw_bytes):
        strings.append(match.group(0).decode("ascii", errors="ignore"))

    for match in UTF16_STRING_RE.finditer(raw_bytes):
        strings.append(match.group(0).decode("utf-16le", errors="ignore"))

    return strings


def find_valid_ipv4s(text: str) -> List[str]:
    """Extract syntactically valid IPv4 addresses from a string."""
    valid_ips: List[str] = []
    for candidate in IPV4_RE.findall(text):
        try:
            ipaddress.IPv4Address(candidate)
            valid_ips.append(candidate)
        except ValueError:
            continue
    return valid_ips


def find_domains(text: str) -> List[str]:
    """Extract domain names while filtering out PE filenames/DLL extensions."""
    domains: List[str] = []
    for candidate in DOMAIN_RE.findall(text):
        tld = candidate.rsplit(".", 1)[-1].lower()
        if tld not in IGNORED_TLDS:
            domains.append(candidate.lower())
    return domains


def extract_iocs(file_path: str) -> Dict[str, Any]:
    """
    Scan a PE file for printable strings and extract unique IOCs:
    IPv4 addresses, URLs, domains, and Windows Registry keys.
    """
    try:
        raw_bytes = Path(file_path).read_bytes()
    except OSError as exc:
        return {
            "status": "error",
            "error": f"Failed to read file: {exc}",
        }

    strings = extract_printable_strings(raw_bytes)
    combined_text = "\n".join(strings)

    urls = sorted(set(URL_RE.findall(combined_text)))
    ipv4s = sorted(set(find_valid_ipv4s(combined_text)))
    domains = sorted(set(find_domains(combined_text)))
    registry_keys = sorted(set(REGISTRY_RE.findall(combined_text)))

    total_iocs = len(urls) + len(ipv4s) + len(domains) + len(registry_keys)

    return {
        "status": "ok",
        "total_strings_extracted": len(strings),
        "total_iocs": total_iocs,
        "urls": urls,
        "ipv4s": ipv4s,
        "domains": domains,
        "registry_keys": registry_keys,
    }


def print_ioc_summary(ioc_data: Dict[str, Any]) -> None:
    """Print a formatted terminal summary of extracted strings and IOCs."""
    if ioc_data.get("status") != "ok":
        print(f"[-] IOC Extraction Error: {ioc_data.get('error', 'Unknown error')}")
        return

    print("\n--- Extracted IOCs Summary ---")
    print(f"  Printable Strings : {ioc_data['total_strings_extracted']}")
    print(f"  Total IOCs Found  : {ioc_data['total_iocs']}")

    categories = [
        ("URLs", ioc_data["urls"]),
        ("IPv4 Addresses", ioc_data["ipv4s"]),
        ("Domains", ioc_data["domains"]),
        ("Registry Keys", ioc_data["registry_keys"]),
    ]

    for label, items in categories:
        print(f"  {label:<18}: {len(items)}")
        for item in items:
            print(f"      - {item}")
