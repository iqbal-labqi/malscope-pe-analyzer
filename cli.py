"""
MalScope (PE-Sentry) - Static PE Header Inspector & IOC Extractor
Member 1: CLI & Ethics Engine

This module provides the command-line interface, startup legal disclaimer,
authorized scope enforcement, safe defaults, dry-run mode, and a clean
Ctrl+C kill switch.
"""

import argparse
import signal
import sys
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _name):
            return ""

    Fore = Style = _NoColor()


DEFAULT_TARGET = Path("samples") / "dummy_test.exe"
DEFAULT_SCOPE = Path("samples")
DEFAULT_OUTPUT = Path("output")


def handle_kill_switch(_signum, _frame):
    """Handle Ctrl+C (SIGINT) to abort execution cleanly."""
    print(f"\n{Fore.YELLOW}[!] Kill switch activated (Ctrl+C). Aborting cleanly...")
    sys.exit(130)


def setup_signal_handler():
    """Register the SIGINT handler for clean interruption."""
    signal.signal(signal.SIGINT, handle_kill_switch)


def display_banner():
    """Print the tool banner."""
    print(f"{Fore.CYAN}{Style.BRIGHT}" + "=" * 62)
    print("  MalScope (PE-Sentry) - Static PE Analyzer & IOC Extractor")
    print("  IKB31603 Ethical Hacking | Category 7: Malware (Static)")
    print("=" * 62 + f"{Style.RESET_ALL}")


def confirm_authorization() -> bool:
    """
    Display the legal disclaimer referencing Malaysia's Computer Crimes Act 1997
    and require explicit user confirmation before proceeding.
    """
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[LEGAL DISCLAIMER & AUTHORIZATION]{Style.RESET_ALL}")
    print(
        "This tool performs offline static analysis on Portable Executable (PE) files.\n"
        "Unauthorized access, tampering, or analysis of systems/files without explicit\n"
        "permission may violate Malaysia's Computer Crimes Act 1997 (Act 563) and\n"
        "applicable local laws.\n"
    )
    print(
        "By continuing, you confirm that:\n"
        "  1. You have explicit authorization to analyze the target file.\n"
        "  2. You are operating within an approved educational/lab scope.\n"
        "  3. No sensitive data will be exfiltrated.\n"
    )

    try:
        response = input("Do you confirm you have authorization to proceed? (yes/no): ").strip().lower()
    except EOFError:
        return False

    return response in {"yes", "y"}


def validate_target_and_scope(target_path: Path, scope_dir: Path) -> bool:
    """
    Verify that the target file exists, is within the authorized scope directory,
    and starts with a valid PE DOS header ('MZ').
    """
    resolved_scope = scope_dir.resolve()
    resolved_target = target_path.resolve()

    if not resolved_scope.exists() or not resolved_scope.is_dir():
        print(f"{Fore.RED}[-] Authorized scope directory does not exist: {resolved_scope}")
        return False

    try:
        resolved_target.relative_to(resolved_scope)
    except ValueError:
        print(
            f"{Fore.RED}[-] Scope violation: '{resolved_target}' is outside the "
            f"authorized scope '{resolved_scope}'."
        )
        print(f"{Fore.YELLOW}[i] Tip: Place test files inside '{scope_dir}' or update --scope.")
        return False

    if not resolved_target.exists() or not resolved_target.is_file():
        print(f"{Fore.RED}[-] Target file not found: {resolved_target}")
        return False

    with resolved_target.open("rb") as f:
        magic = f.read(2)

    if magic != b"MZ":
        print(f"{Fore.RED}[-] Invalid PE file: '{resolved_target.name}' does not start with 'MZ'.")
        return False

    return True


def run_pipeline(target_path: Path, output_dir: Path, dry_run: bool):
    """
    Execute the static analysis pipeline.
    Gracefully reports pending modules until Members 2-5 implement them.
    """
    print(f"\n{Fore.GREEN}[+] Target validated: {target_path.resolve()}")
    print(f"{Fore.GREEN}[+] Output directory: {output_dir.resolve()}")

    if dry_run:
        print(f"\n{Fore.CYAN}[DRY-RUN] Validation succeeded. No analysis or file writes performed.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    results = {
        "target": str(target_path),
        "pe_analysis": None,
        "api_checks": None,
        "iocs": None,
        "score": None,
    }

    # Member 2: PE Structure & Entropy
    try:
        from core.pe_analyzer import analyze_pe, print_pe_summary  # type: ignore

        results["pe_analysis"] = analyze_pe(str(target_path))
        print(f"{Fore.GREEN}[+] PE Structure & Entropy analysis complete.")
        print_pe_summary(results["pe_analysis"])
    except ImportError:
        print(f"{Fore.YELLOW}[PENDING] core/pe_analyzer.py (Member 2) not implemented yet.")

    # Member 3: Suspicious API Checker
    try:
        from core.api_checker import check_suspicious_apis  # type: ignore

        results["api_checks"] = check_suspicious_apis(str(target_path))
        print(f"{Fore.GREEN}[+] Suspicious API check complete.")
    except ImportError:
        print(f"{Fore.YELLOW}[PENDING] core/api_checker.py (Member 3) not implemented yet.")

    # Member 4: IOC Extractor
    try:
        from core.ioc_extractor import extract_iocs  # type: ignore

        results["iocs"] = extract_iocs(str(target_path))
        print(f"{Fore.GREEN}[+] IOC extraction complete.")
    except ImportError:
        print(f"{Fore.YELLOW}[PENDING] core/ioc_extractor.py (Member 4) not implemented yet.")

    # Member 5: Scoring & Report Output
    try:
        from core.scorer import score_and_save  # type: ignore

        results["score"] = score_and_save(results, str(output_dir))
        print(f"{Fore.GREEN}[+] Risk scoring & local report saved to {output_dir}.")
    except ImportError:
        print(f"{Fore.YELLOW}[PENDING] core/scorer.py (Member 5) not implemented yet.")


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments with usage examples."""
    examples = (
        "Examples:\n"
        "  python cli.py\n"
        "  python cli.py --target samples/dummy_test.exe\n"
        "  python cli.py --target samples/dummy_test.exe --dry-run\n"
        "  python cli.py -t samples/dummy_test.exe -s samples -o output\n"
    )
    parser = argparse.ArgumentParser(
        prog="malscope",
        description="MalScope (PE-Sentry): Offline Static PE Header Inspector & IOC Extractor.",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--target",
        type=Path,
        default=DEFAULT_TARGET,
        help=f"Path to target PE file (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "-s",
        "--scope",
        type=Path,
        default=DEFAULT_SCOPE,
        help=f"Authorized directory scope for target files (default: {DEFAULT_SCOPE})",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Local directory for analysis reports (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate authorization, scope, and target file without running analysis.",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point for the MalScope CLI."""
    setup_signal_handler()
    args = parse_arguments()
    display_banner()

    if not confirm_authorization():
        print(f"{Fore.RED}[-] Authorization not confirmed. Exiting safely.")
        return 1

    if not validate_target_and_scope(args.target, args.scope):
        return 1

    run_pipeline(args.target, args.output, args.dry_run)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        handle_kill_switch(None, None)
