"""
MalScope (PE-Sentry) - Suspicious Windows API Checker
Member 3: Suspicious API & Behavioral Combo Checker

Parses the PE Import Table (DIRECTORY_ENTRY_IMPORT) using pefile, flags
high-risk Windows APIs, detects multi-API malicious attack chains mapped to
MITRE ATT&CK techniques, and checks for minimal/packed import table anomalies.
"""

from typing import Any, Dict, List, Set

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
        "NtUnmapViewOfSection": "Unmaps a section from a target process (hollowing)",
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
        "LoadLibraryA": "Dynamically loads a DLL at runtime (ANSI)",
        "LoadLibraryW": "Dynamically loads a DLL at runtime (Unicode)",
        "GetProcAddress": "Resolves API addresses dynamically to hide imports",
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

# Behavioral API chains mapped to MITRE ATT&CK techniques.
# Each rule defines groups of equivalent APIs where at least one from each group must be present.
API_BEHAVIOR_RULES: List[Dict[str, Any]] = [
    {
        "name": "Classic Remote Process Injection",
        "mitre_id": "T1055",
        "severity": "HIGH",
        "required_groups": [
            {"OpenProcess"},
            {"VirtualAllocEx"},
            {"WriteProcessMemory"},
            {"CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx"},
        ],
        "description": "Allocates memory and executes a remote thread inside another process.",
    },
    {
        "name": "Process Hollowing",
        "mitre_id": "T1055.012",
        "severity": "HIGH",
        "required_groups": [
            {"CreateProcessA", "CreateProcessW"},
            {"NtUnmapViewOfSection"},
            {"WriteProcessMemory"},
            {"SetThreadContext"},
        ],
        "description": "Spawns a suspended legitimate process and replaces its memory image.",
    },
    {
        "name": "Remote Payload Dropper & Executor",
        "mitre_id": "T1105",
        "severity": "HIGH",
        "required_groups": [
            {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW"},
            {"WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"},
        ],
        "description": "Downloads a second-stage payload from a remote URL and executes it.",
    },
    {
        "name": "Keyboard Hook / Input Logging",
        "mitre_id": "T1056.001",
        "severity": "MEDIUM",
        "required_groups": [
            {"SetWindowsHookExA", "SetWindowsHookExW"},
            {"GetAsyncKeyState", "GetKeyState"},
        ],
        "description": "Installs system hooks and polls key states to capture user keystrokes.",
    },
    {
        "name": "Dynamic API Resolution (Import Obfuscation)",
        "mitre_id": "T1027.007",
        "severity": "MEDIUM",
        "required_groups": [
            {"LoadLibraryA", "LoadLibraryW"},
            {"GetProcAddress"},
        ],
        "description": "Resolves Windows APIs dynamically at runtime to evade static IAT inspection.",
    },
]


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


def detect_api_combos(imported_functions: Set[str]) -> List[Dict[str, Any]]:
    """
    Evaluate imported function sets against known multi-API malicious behavioral chains.
    Returns a list of matched MITRE ATT&CK technique patterns.
    """
    matched_combos: List[Dict[str, Any]] = []

    for rule in API_BEHAVIOR_RULES:
        matched_apis: List[str] = []
        all_groups_satisfied = True

        for group in rule["required_groups"]:
            overlap = sorted(imported_functions.intersection(group))
            if overlap:
                matched_apis.extend(overlap)
            else:
                all_groups_satisfied = False
                break

        if all_groups_satisfied:
            matched_combos.append(
                {
                    "name": rule["name"],
                    "mitre_id": rule["mitre_id"],
                    "severity": rule["severity"],
                    "matched_apis": matched_apis,
                    "description": rule["description"],
                }
            )

    return matched_combos


def check_import_anomalies(total_imports: int, has_import_dir: bool) -> List[str]:
    """Flag structural anomalies in the Import Address Table (e.g., packed binaries)."""
    anomalies: List[str] = []
    if not has_import_dir or total_imports == 0:
        anomalies.append(
            "No Import Address Table (IAT) found — binary may be heavily packed or corrupt."
        )
    elif total_imports < 5:
        anomalies.append(
            f"Unusually low import count ({total_imports} APIs) — strong indicator of packing/obfuscation."
        )
    return anomalies


def check_suspicious_apis(file_path: str) -> Dict[str, Any]:
    """
    Inspect a PE file's import table and flag suspicious Windows APIs,
    multi-API behavioral chains, and import table anomalies.
    """
    pe = None
    try:
        pe = pefile.PE(file_path, fast_load=False)
        has_import_dir = hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        all_imports = extract_imports(pe)
        lookup = build_api_lookup()

        flagged_apis: List[Dict[str, str]] = []
        imported_func_set: Set[str] = set()

        for item in all_imports:
            func = item["function"]
            imported_func_set.add(func)
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
        detected_combos = detect_api_combos(imported_func_set)
        anomalies = check_import_anomalies(len(all_imports), has_import_dir)

        return {
            "status": "ok",
            "imported_dlls": imported_dlls,
            "total_imports": len(all_imports),
            "flagged_count": len(flagged_apis),
            "flagged_apis": flagged_apis,
            "combo_count": len(detected_combos),
            "detected_combos": detected_combos,
            "import_anomalies": anomalies,
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
    """Print a formatted terminal summary of imported APIs, combos, and anomalies."""
    if api_data.get("status") != "ok":
        print(f"[-] API Check Error: {api_data.get('error', 'Unknown error')}")
        return

    print("\n--- Suspicious API Summary ---")
    print(f"  Imported DLLs   : {len(api_data['imported_dlls'])}")
    print(f"  Total Imports   : {api_data['total_imports']}")
    print(f"  Flagged APIs    : {api_data['flagged_count']}")
    print(f"  Attack Chains   : {api_data.get('combo_count', 0)}")

    for anomaly in api_data.get("import_anomalies", []):
        print(f"  [!] IAT Anomaly : {anomaly}")

    if api_data.get("detected_combos"):
        print("\n  [!] Detected Behavioral API Chains (MITRE ATT&CK):")
        for combo in api_data["detected_combos"]:
            apis_str = " + ".join(combo["matched_apis"])
            print(f"      - [{combo['severity']}] {combo['name']} ({combo['mitre_id']}): {apis_str}")

    if api_data["flagged_apis"]:
        print(f"\n  {'Function':<26} {'DLL':<16} {'Category'}")
        print("  " + "-" * 68)
        for api in api_data["flagged_apis"]:
            print(f"  {api['function']:<26} {api['dll']:<16} {api['category']}")
    else:
        print("  [+] No suspicious Windows APIs detected in import table.")