#!/usr/bin/env python3
"""Generate the README KQL catalog from source query files.

The repository keeps query files as the source of truth. This script discovers
query-like files, groups them into practical investigation categories, and
replaces only the README block between the generated markers.
"""

from __future__ import annotations

import argparse
import html
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


START_MARKER = "<!-- BEGIN GENERATED KQL CATALOG -->"
END_MARKER = "<!-- END GENERATED KQL CATALOG -->"

CATEGORY_ORDER = [
    "Identity",
    "Mailbox",
    "Endpoint",
    "Network",
    "Defender",
    "Azure",
    "Parser / Helper",
    "Other",
]

USE_CASES = {
    "Identity": "Identity investigation / phishing triage",
    "Mailbox": "Mailbox investigation / phishing triage",
    "Endpoint": "Endpoint investigation / host triage",
    "Network": "Network investigation / IP and scanning triage",
    "Defender": "Defender / endpoint protection triage",
    "Azure": "Azure control-plane investigation",
    "Parser / Helper": "Parsing / normalization helper",
    "Other": "General hunting",
}

TITLE_OVERRIDES = {
    "AiTMphishingCaseDectection.kql": "AiTM Phishing Case Detection",
    "Alertonnewadminpermission.kql": "Alert on New Admin Permission",
    "Azure-VM-RunCommand-Execution-With-MDE-Evidence.kql": "Azure VM Run Command Execution With MDE Evidence",
    "DetectMaliciousorunwantedSoftware.kql": "Detect Malicious or Unwanted Software",
    "IPinvestigation.kql": "IP Investigation",
    "MaliciouSignIn-from-BlacklistedIP.kql": "Malicious Sign-In from Blacklisted IP",
    "Portscanfromipusersignedin.kql": "Port Scan from IP with Signed-In Users",
    "UAL-MaliciousMailAccess.kql": "UAL Malicious Mail Access",
    "addlocaladmin.kql": "Add Local Admin",
    "detectDisableRealtimeMonitoring.kql": "Detect Disable Realtime Monitoring",
    "detectavexclutions.kql": "Detect AV Exclusions",
    "detectectmanyavdetections.kql": "Detect Many AV Detections",
    "detectfwbypass.kql": "Detect Firewall Bypass",
    "detectmacrodocuments.kql": "Detect Macro Documents",
    "findbotnetipinevent.kql": "Find Botnet IP in Event",
    "localrecondetect.kql": "Local Reconnaissance Detection",
    "malmfareg.kql": "MFA Registration After Risky Sign-In",
    "malnetconnect.kql": "Malicious Network Connection",
    "malurlclick.kql": "Malicious URL Click",
    "malurldetected.kql": "Malicious URL Detected",
    "nmapactivitydetected.kql": "Nmap Activity Detected",
    "nmapvulnscan.kql": "Nmap Vulnerability Scan",
    "oauth_suspicious_redirect_callback_uri.kql": "OAuth Suspicious Redirect Callback URI",
    "possible-linux-reverse-shell-scriptcontent.kql": "Possible Linux Reverse Shell Script Content",
    "potentialspoofingmail.kql": "Potential Spoofing Mail",
    "realtimeprotectionoff.kql": "Realtime Protection Off",
    "risky_or_vip_user_security_info_change.kql": "Risky or VIP User Security Info Change",
    "defenderservicetampering": "Defender Service Tampering",
    "executionofmaliciousfiletype": "Execution of Malicious File Type",
    "suspiciousregkey": "Suspicious Registry Key",
    "parser/UAL-MailsAccessed.kql": "UAL Mail Items Accessed",
    "parser/UAL-Signins.kql": "UAL Sign-Ins",
    "BasicAuthBruteforceApache_Syslog": "Basic Auth Brute Force Apache Syslog",
    "DirBruteforceApache_Syslog": "Directory Brute Force Apache Syslog",
}

DESCRIPTION_HINTS = [
    (re.compile(r"aitm.*phishing", re.I), "Correlates suspicious email and attachment activity that may indicate adversary-in-the-middle phishing."),
    (re.compile(r"admin.*permission|role", re.I), "Flags directory role assignment activity that grants administrative privileges."),
    (re.compile(r"azure.*run command|run command", re.I), "Correlates Azure VM Run Command activity with endpoint-side execution evidence."),
    (re.compile(r"malicious or unwanted software", re.I), "Hunts for known malicious or unwanted process names on endpoints."),
    (re.compile(r"\bip investigation\b", re.I), "Pivots a source IP across identity, email, endpoint, and cloud telemetry."),
    (re.compile(r"blacklisted ip|blocked ip", re.I), "Matches sign-in activity against a curated blacklist of known-bad IP addresses."),
    (re.compile(r"port scan|nmap", re.I), "Detects network scanning behavior and ties it back to signed-in users when available."),
    (re.compile(r"apache syslog|brute force", re.I), "Detects repeated Apache 401 responses consistent with brute-force probing."),
    (re.compile(r"malicious network connection", re.I), "Identifies endpoint connections to known-bad IP addresses."),
    (re.compile(r"mail access", re.I), "Surfaces mailbox item access from UAL MailItemsAccessed records."),
    (re.compile(r"local admin", re.I), "Detects users added to the local Administrators group."),
    (re.compile(r"realtime monitoring", re.I), "Detects Windows Defender realtime monitoring being disabled."),
    (re.compile(r"realtime protection off", re.I), "Detects hosts where Windows Defender realtime protection is not active."),
    (re.compile(r"exclusion", re.I), "Detects changes to Windows Defender exclusion paths and ASR exclusions."),
    (re.compile(r"av detections?", re.I), "Flags endpoints with unusually high counts of antivirus detections."),
    (re.compile(r"firewall bypass", re.I), "Surfaces firewall-disabling commands, registry changes, and PowerShell activity."),
    (re.compile(r"macro", re.I), "Flags Office processes interacting with macro-enabled file types."),
    (re.compile(r"botnet", re.I), "Matches known botnet IP reputation data across identity, email, and endpoint telemetry."),
    (re.compile(r"recon", re.I), "Detects common Windows discovery and local reconnaissance commands."),
    (re.compile(r"mfa", re.I), "Correlates risky sign-ins with subsequent MFA method registration."),
    (re.compile(r"url click", re.I), "Flags URL click activity from known-bad IP addresses."),
    (re.compile(r"url detected|urlhaus", re.I), "Searches endpoint telemetry for contact with malicious URLs from URLHaus."),
    (re.compile(r"nmap activity detected", re.I), "Detects Nmap-driven outbound network activity from endpoints."),
    (re.compile(r"vuln scan", re.I), "Detects Nmap scanning patterns that look like vulnerability enumeration."),
    (re.compile(r"reverse shell", re.I), "Finds script content consistent with a possible Linux reverse shell."),
    (re.compile(r"spoofing", re.I), "Flags email authentication failures that may indicate domain spoofing."),
    (re.compile(r"security info change", re.I), "Correlates risky or VIP users with recent security-info changes."),
    (re.compile(r"service tampering", re.I), "Surfaces attempts to stop, disable, or remove Windows Defender services."),
    (re.compile(r"malicious file type", re.I), "Flags suspicious double-extension file execution patterns."),
    (re.compile(r"registry key", re.I), "Detects suspicious Winlogon AutoAdminLogon registry changes."),
    (re.compile(r"redirect callback uri|oauth", re.I), "Finds OAuth redirect URIs that resemble callback or listener infrastructure."),
]

KNOWN_TABLES = [
    "SigninLogs",
    "AADNonInteractiveUserSignInLogs",
    "AADSignInEventsBeta",
    "AADSpnSignInEventsBeta",
    "AADServicePrincipalSignInLogs",
    "AADUserRiskEvents",
    "AuditLogs",
    "CloudAppEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "IdentityDirectoryEvents",
    "EmailEvents",
    "EmailUrlInfo",
    "EmailAttachmentInfo",
    "UrlClickEvents",
    "OfficeActivity",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceEvents",
    "DeviceLogonEvents",
    "DeviceTvmSecureConfigurationAssessment",
    "SecurityEvent",
    "SecurityAlert",
    "AzureActivity",
    "CommonSecurityLog",
    "Syslog",
    "AlertInfo",
    "AlertEvidence",
    "BehaviorAnalytics",
    "MicrosoftGraphActivityLogs",
    "UAL",
    "ApacheHTTPServer_CL",
    "_Im_NetworkSession",
]

KQL_MARKERS = [
    "| where",
    "| extend",
    "| summarize",
    "| project",
    "| join",
    "| union",
    "| mv-",
    "let ",
    "externaldata(",
    "search in (",
    "datatable(",
]

IGNORED_DIRS = {
    ".git",
    ".github",
    ".venv",
    "__pycache__",
    "node_modules",
    "scripts",
}

IGNORED_NAMES = {
    "README.md",
    "logo.png",
}

CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

ACRONYMS = {
    "aad": "AAD",
    "api": "API",
    "aitm": "AiTM",
    "av": "AV",
    "dns": "DNS",
    "ip": "IP",
    "mde": "MDE",
    "mfa": "MFA",
    "mpssvc": "MpsSvc",
    "oauth": "OAuth",
    "ual": "UAL",
    "url": "URL",
    "vm": "VM",
    "vip": "VIP",
}

WORD_FIXES = {
    "dectection": "Detection",
    "exclutions": "Exclusions",
    "bruteforce": "Brute Force",
    "signin": "Sign-In",
    "signins": "Sign-Ins",
    "sign in": "Sign-In",
    "realtime": "Realtime",
    "maliciou": "Malicious",
    "malware": "Malware",
    "mfareg": "MFA Registration",
    "fwbypass": "Firewall Bypass",
    "rewind": "Rewind",
}


@dataclass(frozen=True)
class QueryEntry:
    path: Path
    title: str
    category: str
    description: str
    tables: tuple[str, ...]
    use_case: str


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def humanize_stem(stem: str) -> str:
    parts = CAMEL_SPLIT_RE.split(stem.replace("_", " ").replace("-", " "))
    parts = normalize_whitespace(" ".join(parts)).split(" ")
    words: list[str] = []
    for raw in parts:
        if not raw:
            continue
        lowered = raw.lower()
        if lowered in ACRONYMS:
            words.append(ACRONYMS[lowered])
            continue
        fixed = WORD_FIXES.get(lowered, raw)
        if fixed in ACRONYMS.values():
            words.append(fixed)
            continue
        if fixed.isupper() or fixed.isdigit():
            words.append(fixed)
            continue
        if " " in fixed:
            words.extend(fixed.split(" "))
            continue
        words.append(fixed[:1].upper() + fixed[1:])

    title = normalize_whitespace(" ".join(words))
    title = re.sub(r"\bOrunwanted\b", "Or Unwanted", title, flags=re.I)
    title = re.sub(r"\bMaliciou\b", "Malicious", title, flags=re.I)
    title = re.sub(r"\bBruteforce\b", "Brute Force", title, flags=re.I)
    title = re.sub(r"\bSign In\b", "Sign-In", title, flags=re.I)
    title = re.sub(r"\bMfa\b", "MFA", title)
    title = re.sub(r"\bOauth\b", "OAuth", title)
    title = re.sub(r"\bIp\b", "IP", title)
    return title


def derive_title(path: Path) -> str:
    key = path.as_posix()
    if key in TITLE_OVERRIDES:
        return TITLE_OVERRIDES[key]
    if path.name in TITLE_OVERRIDES:
        return TITLE_OVERRIDES[path.name]
    return humanize_stem(path.stem)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def looks_like_kql(text: str) -> bool:
    lowered = text.lower()
    score = 0
    for marker in KQL_MARKERS:
        if marker in lowered:
            score += 1
    if score >= 2:
        return True
    if "|" in text and any(table.lower() in lowered for table in KNOWN_TABLES):
        return True
    return False


def is_query_candidate(path: Path) -> bool:
    if not path.is_file():
        return False
    if any(part in IGNORED_DIRS for part in path.parts):
        return False
    if path.name in IGNORED_NAMES:
        return False

    suffix = path.suffix.lower()
    if suffix == ".kql":
        return True
    if suffix:
        return False

    try:
        text = read_text(path)
    except OSError:
        return False
    return looks_like_kql(text)


def discover_queries(root: Path) -> list[Path]:
    candidates = []
    for path in root.rglob("*"):
        if is_query_candidate(path):
            candidates.append(path)
    return sorted(candidates, key=lambda p: p.as_posix().lower())


def infer_tables(text: str) -> tuple[str, ...]:
    found: list[str] = []
    for table in KNOWN_TABLES:
        if re.search(rf"\b{re.escape(table)}\b", text):
            found.append(table)
    return tuple(found)


def infer_category(path: Path, title: str, tables: tuple[str, ...]) -> str:
    rel = path.as_posix().lower()
    title_l = title.lower()
    table_set = set(tables)

    if rel.startswith("parser/"):
        return "Parser / Helper"

    if "azureactivity" in table_set or "azure" in rel or "run command" in title_l:
        return "Azure"

    if any(
        token in title_l
        for token in [
            "defender",
            "firewall",
            "realtime protection",
            "realtime monitoring",
            "av exclusions",
            "av detections",
            "service tampering",
            "windows defender",
        ]
    ) or "DeviceTvmSecureConfigurationAssessment" in table_set:
        return "Defender"

    if any(
        token in title_l
        for token in [
            "ip investigation",
            "botnet",
            "port scan",
            "nmap",
            "network connection",
            "malicious network",
            "url detected",
            "urlhaus",
            "brute force",
            "apache syslog",
        ]
    ) or table_set.intersection(
        {
            "DeviceNetworkEvents",
            "CommonSecurityLog",
            "Syslog",
            "ApacheHTTPServer_CL",
            "_Im_NetworkSession",
        }
    ):
        return "Network"

    if any(
        token in title_l
        for token in [
            "signin",
            "sign-in",
            "mfa",
            "oauth",
            "security info",
            "admin permission",
            "vip",
            "risky",
            "identity",
        ]
    ) or table_set.intersection(
        {
            "SigninLogs",
            "AADNonInteractiveUserSignInLogs",
            "AADSignInEventsBeta",
            "AADSpnSignInEventsBeta",
            "AADServicePrincipalSignInLogs",
            "AADUserRiskEvents",
            "AuditLogs",
            "CloudAppEvents",
            "BehaviorAnalytics",
            "IdentityLogonEvents",
            "IdentityQueryEvents",
            "IdentityDirectoryEvents",
        }
    ):
        return "Identity"

    if any(
        token in title_l
        for token in [
            "mail",
            "phish",
            "spoof",
            "url click",
            "url clicked",
            "malicious url click",
        ]
    ) or table_set.intersection(
        {"EmailEvents", "EmailUrlInfo", "EmailAttachmentInfo", "UrlClickEvents", "OfficeActivity", "UAL"}
    ):
        return "Mailbox"

    if table_set.intersection(
        {
            "DeviceProcessEvents",
            "DeviceFileEvents",
            "DeviceEvents",
            "DeviceRegistryEvents",
            "DeviceLogonEvents",
            "SecurityEvent",
        }
    ):
        return "Endpoint"

    return "Other"


def infer_description(path: Path, title: str, category: str, tables: tuple[str, ...]) -> str:
    text = f"{path.as_posix()} {title} {' '.join(tables)}"
    for pattern, description in DESCRIPTION_HINTS:
        if pattern.search(text):
            return description

    if category == "Identity":
        return "Surfaces identity activity relevant to sign-ins, MFA, role changes, or token and session abuse."
    if category == "Mailbox":
        return "Looks for mailbox, phishing, and email access activity that warrants investigation."
    if category == "Endpoint":
        return "Hunts for host and process activity associated with malware, persistence, or reconnaissance."
    if category == "Network":
        return "Flags network activity related to scanning, malicious IPs, or suspicious external infrastructure."
    if category == "Defender":
        return "Surfaces Windows Defender or endpoint protection tampering activity."
    if category == "Azure":
        return "Correlates Azure control-plane activity with endpoint evidence."
    if category == "Parser / Helper":
        return "Normalizes UAL data for downstream hunting and investigation."
    return "General hunting query."


def category_order_key(category: str) -> int:
    try:
        return CATEGORY_ORDER.index(category)
    except ValueError:
        return len(CATEGORY_ORDER)


def discover_entries(root: Path) -> list[QueryEntry]:
    entries: list[QueryEntry] = []
    for path in discover_queries(root):
        rel_path = path.relative_to(root)
        text = read_text(path)
        title = derive_title(rel_path)
        tables = infer_tables(text)
        category = infer_category(rel_path, title, tables)
        description = infer_description(path, title, category, tables)
        entries.append(
            QueryEntry(
                path=rel_path,
                title=title,
                category=category,
                description=description,
                tables=tables,
                use_case=USE_CASES[category],
            )
        )
    return entries


def render_entry(entry: QueryEntry, root: Path) -> str:
    source_label = html.escape(entry.path.name)
    source_link = f"[`{source_label}`](./{entry.path.as_posix()})"
    title = html.escape(entry.title)
    description = html.escape(entry.description)
    lines = [
        "<details>",
        f"<summary><strong>{title}</strong><br><sub>{description}</sub></summary>",
        "",
        "<br>",
        "",
            f"**Source:** {source_link}",
    ]
    if entry.tables:
        tables = ", ".join(f"`{table}`" for table in entry.tables)
        lines.append(f"**Tables:** {tables}")
    lines.extend(
        [
            f"**Use case:** {entry.use_case}",
            "",
            "```kusto",
            read_text(root / entry.path),
            "```",
            "",
            "</details>",
        ]
    )
    return "\n".join(lines)


def render_catalog(entries: Iterable[QueryEntry], root: Path) -> str:
    grouped: dict[str, list[QueryEntry]] = {category: [] for category in CATEGORY_ORDER}
    for entry in entries:
        grouped.setdefault(entry.category, []).append(entry)

    blocks: list[str] = []
    for category in CATEGORY_ORDER:
        bucket = grouped.get(category, [])
        if not bucket:
            continue
        bucket = sorted(bucket, key=lambda entry: entry.title.lower())
        blocks.append(f"### {category}")
        blocks.append("")
        for index, entry in enumerate(bucket):
            blocks.append(render_entry(entry, root))
            if index != len(bucket) - 1:
                blocks.append("")
        blocks.append("")

    return "\n".join(blocks).rstrip() + "\n"


def update_readme(readme_path: Path, generated: str) -> None:
    original = readme_path.read_text(encoding="utf-8", errors="replace")
    if START_MARKER not in original or END_MARKER not in original:
        raise SystemExit("README is missing generated catalog markers.")

    prefix, rest = original.split(START_MARKER, 1)
    middle, suffix = rest.split(END_MARKER, 1)
    _ = middle  # Deliberately replaced.

    updated = (
        prefix
        + START_MARKER
        + "\n\n"
        + generated.rstrip("\n")
        + "\n\n"
        + END_MARKER
        + suffix
    )
    readme_path.write_text(updated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Only verify whether README is up to date.")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    readme_path = root / "README.md"
    entries = discover_entries(root)
    generated = render_catalog(entries, root)

    if args.check:
        original = readme_path.read_text(encoding="utf-8", errors="replace")
        if START_MARKER not in original or END_MARKER not in original:
            raise SystemExit("README is missing generated catalog markers.")
        prefix, rest = original.split(START_MARKER, 1)
        _, suffix = rest.split(END_MARKER, 1)
        expected = prefix + START_MARKER + "\n\n" + generated.rstrip("\n") + "\n\n" + END_MARKER + suffix
        if expected != original:
            raise SystemExit("README catalog is out of date.")
        print(f"README catalog is up to date for {len(entries)} queries.")
        return 0

    update_readme(readme_path, generated)
    print(f"Updated README catalog for {len(entries)} queries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
