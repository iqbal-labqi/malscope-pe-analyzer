"""
MalScope (PE-Sentry) - Suspicious Windows API Checker
Member 3: Suspicious API Checker

Parses the PE Import Table (DIRECTORY_ENTRY_IMPORT) using pefile and flags
high-risk Windows APIs commonly associated with process injection, persistence,
anti-analysis, networking/C2, and credential access.
"""

from typing import Any, Dict, List

import pefile


SUSPICIOUS_API_CATEGORIES: Dict[str, Dict[str, str]] = {
    "Process Injection & Memory": {
        "VirtualAlloc": "Allocates executable/writable memory",
        "VirtualAllocEx": "Allocates memory in a remote process",
        "VirtualProtect": "Changes memory protection (e.g., RWX)",
        "VirtualProtectEx": "Changes memory protection in a remote process",
        "WriteProcessMemory": "Writes data into another process's memory",
        "ReadProcessMemory": "Reads memory from another process",
        "CreateRemoteThread": "Executes code in a remote process",
        "CreateRemoteThreadEx": "Executes code in a remote process (extended)",
        "NtCreateThreadEx": "Low-level thread creation for injection",
        "OpenProcess": "Opens a handle to another running process",
        "QueueUserAPC": "Queues an APC for code injection",
        "SetThreadContext": "Modifies thread registers (e.g., process hollowing)",
    },
    "Execution & Persistence": {
        "CreateProcessA": "Launches a new process (ANSI)",
        "CreateProcessW": "Launches a new process (Unicode)",
        "ShellExecuteA": "Executes an external file or command (ANSI)",
        "ShellExecuteW": "Executes an external file or command (Unicode)",
        "WinExec": "Legacy API to run an external program",
        "RegSetValueExA": "Modifies Windows Registry values (ANSI)",
        "RegSetValueExW": "Modifies Windows Registry values (Unicode)",
        "RegCreateKeyExA": "Creates/opens Windows Registry keys (ANSI)",
        "RegCreateKeyExW": "Creates/opens Windows Registry keys (Unicode)",
        "CreateServiceA": "Installs a Windows service for persistence (ANSI)",
        "CreateServiceW": "Installs a Windows service for persistence (Unicode)",
    },
    "Anti-Analysis & Evasion": {
        "IsDebuggerPresent": "Checks if the process is being debugged",
        "CheckRemoteDebuggerPresent": "Detects remote debugger attachment",
        "NtQueryInformationProcess": "Queries process internals / debugger flags",
        "GetTickCount": "Timing check used to detect sandboxes",
        "Sleep": "Delays execution to evade sandbox timeouts",
    },
    "Network & C2": {
        "InternetOpenA": "Initializes WinINet network session (ANSI)",
        "InternetOpenW": "Initializes WinINet network session (Unicode)",
        "InternetOpenUrlA": "Opens a remote URL (ANSI)",
        "InternetOpenUrlW": "Opens a remote URL (Unicode)",
        "HttpSendRequestA": "Sends an HTTP request (ANSI)",
        "HttpSendRequestW": "Sends an HTTP request (Unicode)",
        "URLDownloadToFileA": "Downloads a remote file to disk (ANSI)",
        "URLDownloadToFileW": "Downloads a remote file to disk (Unicode)",
        "WSAStartup": "Initializes Windows Sockets",
        "connect": "Establishes a raw socket connection",
        "send": "Sends data over a socket",
        "recv": "Receives data from a socket",
    },
    "Spyware & Credential Access": {
        "SetWindowsHookExA": "Installs a hook (often used for keylogging)",
        "SetWindowsHookExW": "Installs a hook (often used for keylogging)",
        "GetAsyncKeyState": "Polls keyboard state (keylogging)",
        "GetKeyState": "Checks virtual key status",
        "CryptUnprotectData": "Decrypts DPAPI-protected data/credentials",
    },
}


def build_api_lookup() -> Dict[str, Dict[str, str]]:
    """Flatten SUSPICIOUS_API_CATEGORIES into an O(1) lookup table by API name."""
    lookup: Dict[str, Dict[str, str]] = {}
    for category, apis in SUSPICIOUS_API_CATEGORIES.items():
        for api_name, description in apis.items():
            lookup[api_name] = {
                "category": category,
                "description": description,
            }
    return lookup


def extract_imports(pe: pefile.PE) -> List[Dict[str, str]]:
    """Extract all imported DLL and function name pairs from a PE file."""
    imports: List[Dict[str, str]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "<unknown>"
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode("utf-8", errors="replace")
            else:
                func_name = f"Ordinal_{imp.ordinal}"
            imports.append({"dll": dll_name, "function": func_name})

    return imports


def check_suspicious_apis(file_path: str) -> Dict[str, Any]:
    """
    Inspect a PE file's import table and flag any suspicious Windows APIs.
    Returns a structured dictionary with counts and categorized findings.
    """
    pe = None
    try:
        pe = pefile.PE(file_path, fast_load=False)
        all_imports = extract_imports(pe)
        lookup = build_api_lookup()

        flagged_apis: List[Dict[str, str]] = []
        for item in all_imports:
            func = item["function"]
            if func in lookup:
                flagged_apis.append(
                    {
                        "dll": item["dll"],
                        "function": func,
                        "category": lookup[func]["category"],
                        "description": lookup[func]["description"],
                    }
                )

        imported_dlls = sorted({item["dll"] for item in all_imports})

        return {
            "status": "ok",
            "imported_dlls": imported_dlls,
            "total_imports": len(all_imports),
            "flagged_count": len(flagged_apis),
            "flagged_apis": flagged_apis,
        }
    except pefile.PEFormatError as exc:
        return {
            "status": "error",
            "error": f"Invalid PE format: {exc}",
        }
    finally:
        if pe is not None:
            pe.close()


def print_api_summary(api_data: Dict[str, Any]) -> None:
    """Print a formatted terminal summary of imported and suspicious APIs."""
    if api_data.get("status") != "ok":
        print(f"[-] API Check Error: {api_data.get('error', 'Unknown error')}")
        return

    print("\n--- Suspicious API Summary ---")
    print(f"  Imported DLLs   : {len(api_data['imported_dlls'])}")
    print(f"  Total Imports   : {api_data['total_imports']}")
    print(f"  Flagged APIs    : {api_data['flagged_count']}")

    if api_data["flagged_apis"]:
        print(f"  {'Function':<26} {'DLL':<16} {'Category'}")
        print("  " + "-" * 68)
        for api in api_data["flagged_apis"]:
            print(f"  {api['function']:<26} {api['dll']:<16} {api['category']}")
    else:
        print("  [+] No suspicious Windows APIs detected in import table.")
