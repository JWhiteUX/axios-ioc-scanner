#!/usr/bin/env python3
"""
axios npm Supply Chain Compromise — IoC Scanner
Source: Huntress blog (2026-03-31)
https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package

Checks for filesystem artifacts, registry persistence (Windows),
network indicators, npm lockfile references, and running processes
tied to the axios/plain-crypto-js RAT campaign (attributed to DPRK/UNC1069).

Run as root/admin for full coverage. Safe to run unprivileged — it just
reports what it can't access.
"""

import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ─── IoC definitions ───────────────────────────────────────────────────────────

C2_DOMAINS = ["sfrclak.com", "calltan.com", "callnrwise.com"]
C2_IPS = ["142.11.206.73"]
C2_PORT = 8000
C2_PATH = "/6202033"
C2_USER_AGENT = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"

MALICIOUS_PACKAGES = {
    "axios": ["1.14.1", "0.30.4"],
    "plain-crypto-js": ["4.2.0", "4.2.1"],
}

PAYLOAD_HASHES_SHA256 = {
    "windows_stage1": "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd",
    "windows_stage2": "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101",
    "macos_binary":   "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a",
    "linux_script":   "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf",
}

PACKAGE_HASHES_SHA1 = {
    "axios@1.14.1":         "2553649f2322049666871cea80a5d0d6adc700ca",
    "axios@0.30.4":         "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71",
    "plain-crypto-js@4.2.1": "07d889e2dadce6f3910dcbc253317d28ca61c766",
}

ATTACKER_EMAILS = ["ifstap@proton.me", "nrwise@proton.me"]

# Platform-specific filesystem paths
FS_INDICATORS = {
    "darwin": [
        "/Library/Caches/com.apple.act.mond",
    ],
    "win32": [
        os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "wt.exe"),
        os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "system.bat"),
    ],
    "linux": [
        "/tmp/ld.py",
    ],
}

# ─── Helpers ───────────────────────────────────────────────────────────────────

RED = "\033[91m"
YEL = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"
RST = "\033[0m"
BOLD = "\033[1m"

findings = []


def finding(severity, category, detail, path=None):
    entry = {"severity": severity, "category": category, "detail": detail}
    if path:
        entry["path"] = str(path)
    findings.append(entry)
    color = RED if severity == "CRITICAL" else YEL if severity == "WARNING" else CYN
    prefix = f"[{color}{severity}{RST}]"
    loc = f" ({path})" if path else ""
    print(f"  {prefix} [{category}] {detail}{loc}")


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


def run_cmd(cmd, shell=False):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, shell=shell
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ─── Checks ────────────────────────────────────────────────────────────────────

def check_filesystem():
    print(f"\n{BOLD}[1/7] Filesystem artifacts{RST}")
    plat = sys.platform
    paths = FS_INDICATORS.get(plat, [])
    # Also check all platforms for node_modules/plain-crypto-js
    if not paths and plat not in FS_INDICATORS:
        print(f"  Platform '{plat}' — skipping platform-specific FS checks")

    hit = False
    for p in paths:
        if os.path.exists(p):
            finding("CRITICAL", "filesystem", f"Malicious artifact found: {p}", p)
            h = sha256_file(p)
            if h:
                known = any(h == v for v in PAYLOAD_HASHES_SHA256.values())
                tag = " (MATCHES KNOWN PAYLOAD)" if known else ""
                finding("CRITICAL" if known else "WARNING", "hash",
                        f"SHA-256: {h}{tag}", p)
            hit = True
        else:
            print(f"  {GRN}[OK]{RST} Not found: {p}")

    # Windows temp files (transient but worth checking)
    if plat == "win32":
        temp = os.environ.get("TEMP", "")
        for name in ["6202033.vbs", "6202033.ps1"]:
            tp = os.path.join(temp, name)
            if os.path.exists(tp):
                finding("CRITICAL", "filesystem", f"Transient dropper artifact: {tp}", tp)
                hit = True

    if not hit:
        print(f"  {GRN}[OK]{RST} No platform-specific RAT artifacts detected")


def check_registry():
    print(f"\n{BOLD}[2/7] Registry persistence (Windows){RST}")
    if sys.platform != "win32":
        print("  Skipping — not Windows")
        return

    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    out = run_cmd(["reg", "query", key, "/v", "MicrosoftUpdate"])
    if "MicrosoftUpdate" in out and "system.bat" in out.lower():
        finding("CRITICAL", "registry",
                f"MicrosoftUpdate Run key points to system.bat", key)
    else:
        print(f"  {GRN}[OK]{RST} No MicrosoftUpdate persistence key found")


def check_node_modules():
    print(f"\n{BOLD}[3/7] node_modules scan for plain-crypto-js{RST}")
    search_roots = set()

    # Common locations
    home = Path.home()
    search_roots.add(home)
    for d in ["/opt", "/var", "/srv", "/usr/local"]:
        if os.path.isdir(d):
            search_roots.add(Path(d))
    if sys.platform == "win32":
        for drive in "CDEF":
            p = Path(f"{drive}:\\")
            if p.exists():
                search_roots.add(p)
    # Also CWD
    search_roots.add(Path.cwd())

    hit = False
    checked = 0
    print(f"  Searching under: {', '.join(str(r) for r in sorted(search_roots))}")
    for root in sorted(search_roots):
        for dirpath, dirnames, _files in os.walk(root, topdown=True):
            # Prune to avoid excessive crawling
            dirnames[:] = [
                d for d in dirnames
                if d not in {".git", "__pycache__", ".cache", "venv", ".venv"}
                and not d.startswith(".")
            ]
            checked += 1
            if checked > 500_000:
                print(f"  {YEL}[WARN]{RST} Hit directory limit, stopping crawl")
                break

            nm = os.path.join(dirpath, "node_modules", "plain-crypto-js")
            if os.path.isdir(nm):
                finding("CRITICAL", "npm",
                        "plain-crypto-js directory found in node_modules", nm)
                # Check if package.json was swapped (anti-forensics indicator)
                pj = os.path.join(nm, "package.json")
                if os.path.isfile(pj):
                    try:
                        with open(pj) as f:
                            data = json.load(f)
                        ver = data.get("version", "")
                        has_postinstall = "postinstall" in json.dumps(
                            data.get("scripts", {})
                        )
                        if ver == "4.2.0" and not has_postinstall:
                            finding("WARNING", "npm",
                                    "package.json appears swapped to clean v4.2.0 stub "
                                    "(anti-forensics indicator)", pj)
                        elif ver in ("4.2.0", "4.2.1"):
                            finding("CRITICAL", "npm",
                                    f"plain-crypto-js version {ver} found", pj)
                    except Exception:
                        pass
                hit = True

    if not hit:
        print(f"  {GRN}[OK]{RST} No plain-crypto-js directories found")


def check_lockfiles():
    print(f"\n{BOLD}[4/7] Lockfile scan (package-lock.json / yarn.lock / pnpm-lock.yaml){RST}")
    home = Path.home()
    lockfile_names = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    hit = False

    for root, dirs, files in os.walk(home, topdown=True):
        dirs[:] = [d for d in dirs if d not in {
            "node_modules", ".git", ".cache", "__pycache__", "venv", ".venv"
        } and not d.startswith(".")]

        for lf in lockfile_names:
            if lf in files:
                fp = os.path.join(root, lf)
                try:
                    with open(fp, "r", errors="ignore") as f:
                        content = f.read()
                except (PermissionError, OSError):
                    continue

                # Check for malicious package versions
                for pkg, versions in MALICIOUS_PACKAGES.items():
                    for ver in versions:
                        patterns = [
                            f'"{pkg}": "{ver}"',
                            f'"{pkg}@{ver}"',
                            f"{pkg}@{ver}",
                            f'"version": "{ver}"',
                        ]
                        # More targeted: look for package + version proximity
                        if pkg in content:
                            for pat in patterns:
                                if pat in content:
                                    finding("CRITICAL", "lockfile",
                                            f"References {pkg}@{ver}", fp)
                                    hit = True
                                    break

                # Check for plain-crypto-js anywhere
                if "plain-crypto-js" in content:
                    finding("CRITICAL", "lockfile",
                            "Contains reference to plain-crypto-js", fp)
                    hit = True

    if not hit:
        print(f"  {GRN}[OK]{RST} No malicious package references in lockfiles")


def check_network():
    print(f"\n{BOLD}[5/7] Active network connections{RST}")
    hit = False

    if sys.platform == "win32":
        out = run_cmd(["netstat", "-ano"])
    else:
        out = run_cmd(["ss", "-tunap"]) or run_cmd(["netstat", "-tunap"])

    for ip in C2_IPS:
        if ip in out:
            finding("CRITICAL", "network",
                    f"Active connection to C2 IP {ip}")
            hit = True

    # Check DNS cache (Windows)
    if sys.platform == "win32":
        dns_out = run_cmd(["ipconfig", "/displaydns"])
        for domain in C2_DOMAINS:
            if domain in dns_out:
                finding("WARNING", "network",
                        f"C2 domain {domain} found in DNS cache")
                hit = True

    # Check /etc/hosts or hosts file for blocks already in place
    hosts_path = (r"C:\Windows\System32\drivers\etc\hosts" if sys.platform == "win32"
                  else "/etc/hosts")
    try:
        with open(hosts_path) as f:
            hosts = f.read()
        for domain in C2_DOMAINS:
            if domain in hosts:
                print(f"  {CYN}[INFO]{RST} {domain} found in hosts file (may be blocked)")
    except (PermissionError, FileNotFoundError):
        pass

    if not hit:
        print(f"  {GRN}[OK]{RST} No active connections to known C2 infrastructure")


def check_processes():
    print(f"\n{BOLD}[6/7] Running processes{RST}")
    hit = False

    suspicious_patterns = [
        "com.apple.act.mond",   # macOS RAT binary
        "wt.exe",               # Renamed powershell.exe on Windows
        "ld.py",                # Linux RAT script
        "plain-crypto-js",      # Dropper remnants
        "setup.js",             # Dropper script
        "6202033",              # Campaign identifier in filenames
        "sfrclak",              # C2 domain in args
        "calltan",              # Related C2
        "callnrwise",           # Related C2
    ]

    if sys.platform == "win32":
        out = run_cmd(["wmic", "process", "get",
                        "ProcessId,Name,CommandLine", "/format:list"])
        if not out:
            out = run_cmd(
                ["powershell", "-c",
                 "Get-Process | Select-Object Id,ProcessName,Path | Format-List"],
            )
    else:
        out = run_cmd(["ps", "auxww"])

    for pat in suspicious_patterns:
        matches = [line for line in out.splitlines() if pat.lower() in line.lower()]
        for m in matches:
            # wt.exe needs extra validation — it's also legit Windows Terminal
            if pat == "wt.exe":
                m_lower = m.lower()
                if "programdata" in m_lower or "\\programdata\\" in m_lower:
                    finding("CRITICAL", "process",
                            f"wt.exe running from ProgramData (likely renamed powershell): {m.strip()}")
                    hit = True
                # Legit wt.exe is in WindowsApps — skip those
                continue
            finding("CRITICAL", "process", f"Suspicious process: {m.strip()}")
            hit = True

    if not hit:
        print(f"  {GRN}[OK]{RST} No suspicious processes detected")


def check_npm_cache():
    print(f"\n{BOLD}[7/7] npm cache{RST}")
    hit = False

    # npm cache location
    cache_dir = run_cmd(["npm", "config", "get", "cache"]) if (
        subprocess.run(["which", "npm"] if sys.platform != "win32" else ["where", "npm"],
                       capture_output=True).returncode == 0
    ) else ""

    if not cache_dir or not os.path.isdir(cache_dir):
        print(f"  {CYN}[INFO]{RST} npm not found or cache dir inaccessible — skipping")
        return

    content_v2 = os.path.join(cache_dir, "_cacache", "content-v2")
    if os.path.isdir(content_v2):
        # Walk the content-addressed store looking for known hashes
        all_hashes = set(PAYLOAD_HASHES_SHA256.values())
        for root, _dirs, files in os.walk(content_v2):
            for fname in files:
                # content-v2 stores files by sha512, but we can hash them
                fp = os.path.join(root, fname)
                h = sha256_file(fp)
                if h and h in all_hashes:
                    finding("CRITICAL", "npm-cache",
                            f"Cached malicious payload (SHA-256 match): {h}", fp)
                    hit = True
    else:
        print(f"  {CYN}[INFO]{RST} npm content cache not found at expected path")

    if not hit:
        print(f"  {GRN}[OK]{RST} No known malicious payloads in npm cache")


# ─── Report ────────────────────────────────────────────────────────────────────

def print_summary():
    print(f"\n{'='*70}")
    crits = [f for f in findings if f["severity"] == "CRITICAL"]
    warns = [f for f in findings if f["severity"] == "WARNING"]

    if crits:
        print(f"{RED}{BOLD}COMPROMISED — {len(crits)} critical finding(s){RST}")
        print(f"\nImmediate actions:")
        print(f"  1. Isolate affected system(s) from the network")
        print(f"  2. Do NOT attempt to clean in place — rebuild from known-good image")
        print(f"  3. Rotate ALL credentials accessible from this system:")
        print(f"     npm tokens, SSH keys, AWS/cloud keys, .env secrets, API keys,")
        print(f"     OAuth tokens, CI/CD secrets")
        print(f"  4. Block C2 at network perimeter:")
        for d in C2_DOMAINS:
            print(f"     - {d}")
        for ip in C2_IPS:
            print(f"     - {ip}:{C2_PORT}")
        print(f"  5. Pin axios to safe version: 1.14.0 (1.x) or 0.30.3 (0.x)")
        print(f"  6. Run: rm -rf node_modules/plain-crypto-js && npm ci")
        print(f"  7. npm cache clean --force")
    elif warns:
        print(f"{YEL}{BOLD}SUSPICIOUS — {len(warns)} warning(s), review manually{RST}")
    else:
        print(f"{GRN}{BOLD}CLEAN — No indicators of compromise detected{RST}")

    print(f"\nScan completed: {datetime.now(timezone.utc).isoformat()}")
    print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})")

    # JSON output
    report_path = Path.home() / "axios_ioc_report.json"
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "findings": findings,
        "summary": {
            "critical": len(crits),
            "warning": len(warns),
            "status": "COMPROMISED" if crits else "SUSPICIOUS" if warns else "CLEAN",
        },
    }
    try:
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report: {report_path}")
    except OSError as e:
        print(f"\n{YEL}Could not write JSON report: {e}{RST}")


def main():
    print(f"""
{BOLD}═══════════════════════════════════════════════════════════════════════
  axios npm Supply Chain Compromise — IoC Scanner
  Campaign: plain-crypto-js RAT (2026-03-31) / UNC1069 / DPRK
  Source:   Huntress
═══════════════════════════════════════════════════════════════════════{RST}
""")

    check_filesystem()
    check_registry()
    check_node_modules()
    check_lockfiles()
    check_network()
    check_processes()
    check_npm_cache()
    print_summary()

    sys.exit(1 if any(f["severity"] == "CRITICAL" for f in findings) else 0)


if __name__ == "__main__":
    main()
