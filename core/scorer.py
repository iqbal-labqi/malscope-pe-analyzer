"""
MalScope (PE-Sentry) - Risk Scorer & Local Report Generator
Member 5: Scoring & Docs

Aggregates findings from PE header/entropy analysis, suspicious API checks,
and IOC extraction into a heuristic risk score (0-100) and classification
(LOW / MEDIUM / HIGH). Saves clearly labeled JSON and TXT reports locally
in the designated output directory without any external data exfiltration.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


SAFE_TEST_INDICATORS = {"127.0.0.1", "localhost", "example.com"}


def compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Calculate MD5 and SHA-256 hashes of the target binary."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    try:
        data = Path(file_path).read_bytes()
        md5_hash.update(data)
        sha256_hash.update(data)
        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
        }
    except OSError:
        return {"md5": "unavailable", "sha256": "unavailable"}


def is_safe_test_ioc(value: str) -> bool:
    """Return True if an IOC belongs to standard loopback/example test ranges."""
    lowered = value.lower()
    return any(safe in lowered for safe in SAFE_TEST_INDICATORS)


def calculate_risk_score(results: Dict[str, Any]) -> Tuple[int, str, List[str]]:
    """
    Compute a heuristic risk score (0-100), risk rating (LOW/MEDIUM/HIGH),
    and human-readable scoring reasons from pipeline results.
    """
    score = 0
    reasons: List[str] = []

    # 1. PE Structure & Section Entropy (Member 2)
    pe_data = results.get("pe_analysis") or {}
    if pe_data.get("status") == "ok":
        high_entropy = pe_data.get("high_entropy_sections", [])
        if high_entropy:
            pts = min(len(high_entropy) * 25, 50)
            score += pts
            reasons.append(
                f"+{pts} pts: High-entropy section(s) detected ({', '.join(high_entropy)})"
            )

    # 2. Suspicious APIs, MITRE Combos & IAT Anomalies (Member 3)
    api_data = results.get("api_checks") or {}
    if api_data.get("status") == "ok":
        for combo in api_data.get("detected_combos", []):
            pts = 30 if combo.get("severity") == "HIGH" else 15
            score += pts
            reasons.append(
                f"+{pts} pts: MITRE ATT&CK chain '{combo['name']}' ({combo['mitre_id']})"
            )

        flagged_count = api_data.get("flagged_count", 0)
        if flagged_count > 0:
            pts = min(flagged_count * 5, 30)
            score += pts
            reasons.append(f"+{pts} pts: {flagged_count} suspicious Windows API import(s)")

        anomalies = api_data.get("import_anomalies", [])
        if anomalies:
            pts = len(anomalies) * 10
            score += pts
            reasons.append(f"+{pts} pts: {len(anomalies)} Import Address Table anomaly/anomalies")

    # 3. Extracted IOCs (Member 4)
    ioc_data = results.get("iocs") or {}
    if ioc_data.get("status") == "ok":
        reg_keys = ioc_data.get("registry_keys", [])
        if reg_keys:
            pts = min(len(reg_keys) * 5, 20)
            score += pts
            reasons.append(f"+{pts} pts: {len(reg_keys)} Windows Registry key indicator(s)")

        net_iocs = (
            ioc_data.get("urls", [])
            + ioc_data.get("ipv4s", [])
            + ioc_data.get("domains", [])
        )
        external_iocs = [item for item in net_iocs if not is_safe_test_ioc(item)]
        safe_iocs = [item for item in net_iocs if is_safe_test_ioc(item)]

        if external_iocs:
            pts = min(len(external_iocs) * 10, 30)
            score += pts
            reasons.append(f"+{pts} pts: {len(external_iocs)} external network IOC(s)")

        if safe_iocs:
            pts = min(len(safe_iocs) * 2, 6)
            score += pts
            reasons.append(
                f"+{pts} pts: {len(safe_iocs)} benign loopback/example test IOC(s)"
            )

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("0 pts: No high-risk indicators detected.")

    return score, level, reasons


def format_text_report(report: Dict[str, Any]) -> str:
    """Build a human-readable plain-text analysis report."""
    lines = [
        "=" * 68,
        "  MALSCOPE (PE-SENTRY) - LOCAL STATIC ANALYSIS REPORT",
        "  CONFIDENTIAL - AUTHORIZED LAB / EDUCATIONAL USE ONLY",
        "=" * 68,
        f"Generated (UTC) : {report['timestamp_utc']}",
        f"Target File     : {report['target']}",
        f"MD5             : {report['hashes']['md5']}",
        f"SHA-256         : {report['hashes']['sha256']}",
        f"Risk Score      : {report['risk_score']} / 100 ({report['risk_level']})",
        "",
        "[Scoring Breakdown]",
    ]
    for reason in report["reasons"]:
        lines.append(f"  - {reason}")

    pe_info = report.get("pe_analysis") or {}
    if pe_info.get("status") == "ok":
        nt = pe_info["nt_headers"]
        lines.extend(
            [
                "",
                "[PE Header & Sections]",
                f"  Format / Arch : {nt['pe_format']} | {nt['machine']}",
                f"  Entry Point   : {nt['entry_point']} | Image Base: {nt['image_base']}",
                f"  Compile Time  : {nt['timestamp']}",
            ]
        )
        for sec in pe_info.get("sections", []):
            lines.append(
                f"  Section {sec['name']:<8}: Entropy={sec['entropy']:.4f} ({sec['entropy_assessment']})"
            )

    api_info = report.get("api_checks") or {}
    if api_info.get("status") == "ok":
        lines.extend(
            [
                "",
                "[Suspicious APIs & Behavioral Chains]",
                f"  Total Imports : {api_info['total_imports']} | Flagged APIs: {api_info['flagged_count']}",
                f"  Attack Chains : {api_info.get('combo_count', 0)}",
            ]
        )
        for anomaly in api_info.get("import_anomalies", []):
            lines.append(f"  IAT Anomaly   : {anomaly}")

    ioc_info = report.get("iocs") or {}
    if ioc_info.get("status") == "ok":
        lines.extend(
            [
                "",
                "[Extracted Indicators of Compromise (IOCs)]",
                f"  URLs          : {', '.join(ioc_info['urls']) or 'None'}",
                f"  IPv4s         : {', '.join(ioc_info['ipv4s']) or 'None'}",
                f"  Domains       : {', '.join(ioc_info['domains']) or 'None'}",
                f"  Registry Keys : {', '.join(ioc_info['registry_keys']) or 'None'}",
            ]
        )

    lines.append("=" * 68)
    return "\n".join(lines) + "\n"


def score_and_save(results: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """
    Compute the final risk score and save timestamped JSON and TXT reports
    locally inside output_dir.
    """
    target_path = results.get("target", "unknown")
    target_stem = Path(target_path).stem
    now_utc = datetime.now(timezone.utc)
    timestamp_str = now_utc.strftime("%Y%m%d_%H%M%S")

    hashes = compute_file_hashes(target_path)
    score, level, reasons = calculate_risk_score(results)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    json_file = out_path / f"malscope_report_{target_stem}_{timestamp_str}.json"
    txt_file = out_path / f"malscope_report_{target_stem}_{timestamp_str}.txt"

    full_report = {
        "report_label": "MALSCOPE_LOCAL_STATIC_ANALYSIS",
        "timestamp_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "target": target_path,
        "hashes": hashes,
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "pe_analysis": results.get("pe_analysis"),
        "api_checks": results.get("api_checks"),
        "iocs": results.get("iocs"),
    }

    json_file.write_text(json.dumps(full_report, indent=2), encoding="utf-8")
    txt_file.write_text(format_text_report(full_report), encoding="utf-8")

    return {
        "status": "ok",
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "hashes": hashes,
        "json_report": str(json_file),
        "txt_report": str(txt_file),
    }


def print_score_summary(score_data: Dict[str, Any]) -> None:
    """Print the final risk rating, score breakdown, and saved report paths."""
    if score_data.get("status") != "ok":
        print("[-] Scoring Error: Unable to compute risk score.")
        return

    print("\n--- Final Risk Assessment & Local Report ---")
    print(f"  SHA-256 Hash    : {score_data['hashes']['sha256']}")
    print(f"  Risk Score      : {score_data['risk_score']} / 100")
    print(f"  Risk Rating     : {score_data['risk_level']}")
    print("  Score Breakdown :")
    for reason in score_data["reasons"]:
        print(f"      * {reason}")
    print(f"  Saved JSON      : {score_data['json_report']}")
    print(f"  Saved TXT       : {score_data['txt_report']}")
