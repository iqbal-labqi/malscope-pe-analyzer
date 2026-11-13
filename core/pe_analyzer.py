"""
MalScope (PE-Sentry) - PE Structure & Entropy Analyzer
Member 2: PE Structure & Entropy

Parses DOS, NT (COFF + Optional), and Section headers using pefile,
and computes Shannon entropy per section to flag potential packing or obfuscation.
"""

from collections import Counter
from datetime import datetime, timezone
import math
from typing import Any, Dict, List

import pefile


MACHINE_TYPES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

SUBSYSTEM_TYPES = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console (CUI)",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
}


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy (bits per byte, 0.0 to 8.0) for a byte sequence.
    Values above 7.0 often indicate compressed, packed, or encrypted data.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def classify_entropy(entropy: float) -> str:
    """Return a human-readable assessment for a section's Shannon entropy."""
    if entropy >= 7.0:
        return "HIGH (Possibly packed/encrypted)"
    if entropy <= 1.0:
        return "LOW (Sparse/padding)"
    return "NORMAL"


def format_timestamp(timestamp: int) -> str:
    """Convert a PE COFF Unix timestamp to a UTC ISO-8601 string."""
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return f"Invalid ({timestamp})"


def parse_dos_header(pe: pefile.PE) -> Dict[str, Any]:
    """Extract key fields from the DOS header."""
    return {
        "e_magic": hex(pe.DOS_HEADER.e_magic),
        "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
    }


def parse_nt_headers(pe: pefile.PE) -> Dict[str, Any]:
    """Extract key fields from the COFF File Header and Optional Header."""
    file_hdr = pe.FILE_HEADER
    opt_hdr = pe.OPTIONAL_HEADER

    machine_label = MACHINE_TYPES.get(file_hdr.Machine, f"Unknown ({hex(file_hdr.Machine)})")
    subsystem_label = SUBSYSTEM_TYPES.get(
        opt_hdr.Subsystem, f"Unknown ({opt_hdr.Subsystem})"
    )
    pe_format = "PE32+ (64-bit)" if opt_hdr.Magic == 0x20B else "PE32 (32-bit)"

    return {
        "signature": hex(pe.NT_HEADERS.Signature),
        "machine": machine_label,
        "number_of_sections": file_hdr.NumberOfSections,
        "timestamp": format_timestamp(file_hdr.TimeDateStamp),
        "characteristics": hex(file_hdr.Characteristics),
        "pe_format": pe_format,
        "entry_point": hex(opt_hdr.AddressOfEntryPoint),
        "image_base": hex(opt_hdr.ImageBase),
        "subsystem": subsystem_label,
    }


def parse_sections(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parse section headers and compute Shannon entropy for each section."""
    sections = []
    for section in pe.sections:
        raw_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        raw_data = section.get_data()
        entropy = calculate_shannon_entropy(raw_data)

        sections.append(
            {
                "name": raw_name or "<unnamed>",
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": hex(section.Characteristics),
                "entropy": entropy,
                "entropy_assessment": classify_entropy(entropy),
            }
        )
    return sections


def analyze_pe(file_path: str) -> Dict[str, Any]:
    """
    Analyze a PE file and return DOS header, NT headers, and section entropy data.
    Always closes the pefile handle cleanly.
    """
    pe = None
    try:
        pe = pefile.PE(file_path, fast_load=False)
        dos_header = parse_dos_header(pe)
        nt_headers = parse_nt_headers(pe)
        sections = parse_sections(pe)

        high_entropy_sections = [s["name"] for s in sections if s["entropy"] >= 7.0]

        return {
            "status": "ok",
            "dos_header": dos_header,
            "nt_headers": nt_headers,
            "sections": sections,
            "high_entropy_sections": high_entropy_sections,
        }
    except pefile.PEFormatError as exc:
        return {
            "status": "error",
            "error": f"Invalid PE format: {exc}",
        }
    finally:
        if pe is not None:
            pe.close()


def print_pe_summary(pe_data: Dict[str, Any]) -> None:
    """Print a formatted terminal summary of the PE analysis."""
    if pe_data.get("status") != "ok":
        print(f"[-] PE Analysis Error: {pe_data.get('error', 'Unknown error')}")
        return

    dos = pe_data["dos_header"]
    nt = pe_data["nt_headers"]
    sections = pe_data["sections"]

    print("\n--- PE Header Summary ---")
    print(f"  DOS Magic     : {dos['e_magic']} (e_lfanew: {dos['e_lfanew']})")
    print(f"  Format        : {nt['pe_format']} | Machine: {nt['machine']}")
    print(f"  Subsystem     : {nt['subsystem']}")
    print(f"  Entry Point   : {nt['entry_point']} | Image Base: {nt['image_base']}")
    print(f"  Compile Time  : {nt['timestamp']}")
    print(f"  Sections ({nt['number_of_sections']})  :")

    print(f"  {'Name':<10} {'VirtAddr':<10} {'RawSize':<10} {'Entropy':<8} {'Assessment'}")
    print("  " + "-" * 64)
    for sec in sections:
        print(
            f"  {sec['name']:<10} {sec['virtual_address']:<10} "
            f"{sec['raw_size']:<10} {sec['entropy']:<8.4f} {sec['entropy_assessment']}"
        )
