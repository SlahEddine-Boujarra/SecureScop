"""
SecureScope Nmap Custom Profile Builder.

Goal:
- Remove the forced "Step 2" Nmap scan.
- Let the user choose exactly what Nmap scan he wants from the UI.
- Always generate a safe command preview before execution.
- Save XML output for parsing into the inventory table.

Important:
- OS detection is `-O`.
- `-sO` is IP protocol scan, not OS detection.
- Use this only on authorized targets.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class NmapOption:
    flag: str
    label: str
    category: str
    description: str
    requires_admin: bool = False
    advanced: bool = False
    dangerous_if_misused: bool = False


NMAP_OPTIONS: List[NmapOption] = [
    # Host discovery
    NmapOption(
        "-sn", "Ping discovery only", "Host discovery", "Discover live hosts without port scanning."
    ),
    NmapOption(
        "-Pn",
        "Treat hosts as online",
        "Host discovery",
        "Skip host discovery. Useful when ICMP is blocked, but can be slow.",
    ),
    NmapOption(
        "-n", "No DNS resolution", "Performance", "Disable reverse DNS resolution for faster scans."
    ),
    NmapOption("-R", "Always resolve DNS", "Host discovery", "Always do reverse DNS resolution."),
    NmapOption(
        "-PR",
        "ARP discovery",
        "Host discovery",
        "ARP discovery on local Ethernet/LAN. Good for MAC/vendor inventory.",
    ),
    NmapOption("-PE", "ICMP echo discovery", "Host discovery", "ICMP Echo ping discovery."),
    NmapOption("-PP", "ICMP timestamp discovery", "Host discovery", "ICMP timestamp discovery."),
    NmapOption("-PM", "ICMP netmask discovery", "Host discovery", "ICMP netmask discovery."),
    NmapOption(
        "-PS",
        "TCP SYN discovery",
        "Host discovery",
        "TCP SYN ping discovery. Can be combined with ports, e.g. -PS22,80,443.",
        advanced=True,
    ),
    NmapOption(
        "-PA",
        "TCP ACK discovery",
        "Host discovery",
        "TCP ACK ping discovery. Can be combined with ports, e.g. -PA80,443.",
        advanced=True,
    ),
    # Scan techniques
    NmapOption(
        "-sS",
        "TCP SYN scan",
        "Scan technique",
        "Fast TCP SYN scan. Requires admin/Npcap privileges.",
        requires_admin=True,
    ),
    NmapOption(
        "-sT",
        "TCP connect scan",
        "Scan technique",
        "TCP connect scan. Works without raw packet privileges.",
    ),
    NmapOption("-sU", "UDP scan", "Scan technique", "UDP port scan. Slower than TCP scans."),
    NmapOption(
        "-sO",
        "IP protocol scan",
        "Scan technique",
        "Scans supported IP protocols. This is not OS detection.",
        requires_admin=True,
        advanced=True,
    ),
    NmapOption(
        "-sA",
        "TCP ACK scan",
        "Scan technique",
        "Firewall ruleset mapping; does not identify open ports directly.",
        requires_admin=True,
        advanced=True,
    ),
    NmapOption(
        "-sW",
        "TCP Window scan",
        "Scan technique",
        "Advanced TCP window scan.",
        requires_admin=True,
        advanced=True,
    ),
    NmapOption(
        "-sM",
        "TCP Maimon scan",
        "Scan technique",
        "Advanced TCP Maimon scan.",
        requires_admin=True,
        advanced=True,
    ),
    NmapOption(
        "-sN",
        "TCP Null scan",
        "Scan technique",
        "Advanced stealth scan. May be unreliable on Windows targets.",
        requires_admin=True,
        advanced=True,
    ),
    NmapOption(
        "-sF",
        "TCP FIN scan",
        "Scan technique",
        "Advanced stealth scan. May be unreliable on Windows targets.",
        requires_admin=True,
        advanced=True,
    ),
    NmapOption(
        "-sX",
        "TCP Xmas scan",
        "Scan technique",
        "Advanced stealth scan. May be unreliable on Windows targets.",
        requires_admin=True,
        advanced=True,
    ),
    # Detection
    NmapOption(
        "-sV", "Service/version detection", "Detection", "Detect service and application versions."
    ),
    NmapOption(
        "--version-light",
        "Light version detection",
        "Detection",
        "Faster but less exhaustive version detection.",
    ),
    NmapOption(
        "--version-all",
        "Full version detection",
        "Detection",
        "More complete but slower version detection.",
        advanced=True,
    ),
    NmapOption(
        "-O",
        "OS detection",
        "Detection",
        "Operating system detection. Requires admin/Npcap privileges.",
        requires_admin=True,
    ),
    NmapOption(
        "--osscan-limit",
        "Limit OS scan to promising hosts",
        "Detection",
        "Only run OS detection when useful open/closed ports exist.",
    ),
    NmapOption(
        "--osscan-guess",
        "Guess OS more aggressively",
        "Detection",
        "Guess OS even when match is not perfect.",
        advanced=True,
    ),
    NmapOption(
        "-A",
        "Aggressive scan",
        "Detection",
        "Enables OS detection, version detection, default scripts, and traceroute.",
        requires_admin=True,
    ),
    NmapOption("-sC", "Default NSE scripts", "NSE scripts", "Run default safe-ish NSE scripts."),
    NmapOption("--traceroute", "Traceroute", "Detection", "Trace network path to host."),
    # Ports
    NmapOption("-F", "Fast mode", "Ports", "Scan fewer ports than the default scan."),
    NmapOption("--open", "Show open ports only", "Ports", "Only show open or possibly open ports."),
    NmapOption(
        "--top-ports",
        "Top ports",
        "Ports",
        "Scan the most common N ports. Requires a number, e.g. --top-ports 1000.",
    ),
    NmapOption("-p", "Port selection", "Ports", "Choose ports, e.g. -p 22,80,443 or -p-."),
    NmapOption("-p-", "All TCP ports", "Ports", "Scan all TCP ports 1-65535. Can be slow."),
    # Timing/performance
    NmapOption("-T2", "Timing T2 polite", "Timing", "Slower and gentler scan."),
    NmapOption("-T3", "Timing T3 normal", "Timing", "Default-like balanced timing."),
    NmapOption("-T4", "Timing T4 fast", "Timing", "Faster scan on reliable networks."),
    NmapOption(
        "-T5",
        "Timing T5 insane",
        "Timing",
        "Very aggressive timing. Can miss results or overload networks.",
        advanced=True,
        dangerous_if_misused=True,
    ),
    NmapOption(
        "--max-retries",
        "Maximum retries",
        "Timing",
        "Limit probe retransmissions. Requires a number.",
    ),
    NmapOption(
        "--host-timeout",
        "Host timeout",
        "Timing",
        "Stop scanning a host after a time, e.g. 5m or 900s.",
    ),
    NmapOption(
        "--min-rate",
        "Minimum packet rate",
        "Timing",
        "Force minimum packets per second. Advanced.",
        advanced=True,
    ),
    NmapOption(
        "--max-rate",
        "Maximum packet rate",
        "Timing",
        "Limit maximum packets per second. Good for safe throttling.",
    ),
    # Scripts
    NmapOption(
        "--script",
        "NSE script selection",
        "NSE scripts",
        "Run selected NSE scripts, e.g. default,safe,vuln,ntp-info.",
    ),
    NmapOption(
        "--script-args",
        "NSE script arguments",
        "NSE scripts",
        "Pass arguments to NSE scripts.",
        advanced=True,
    ),
    # Output
    NmapOption("-oX", "XML output", "Output", "Write XML output. Needed for SecureScope parser."),
    NmapOption("-oN", "Normal output", "Output", "Write normal human-readable output."),
    NmapOption(
        "-oA", "All outputs", "Output", "Write normal, grepable, and XML outputs with one basename."
    ),
    NmapOption("-v", "Verbose", "Output", "Increase verbosity."),
    NmapOption("-vv", "Very verbose", "Output", "More verbose output."),
]


PROFILE_PRESETS: Dict[str, Dict[str, Any]] = {
    "Discovery only - fast inventory": {
        "description": "Find live hosts only. Good first step for asset inventory.",
        "options": ["-sn", "-n", "-PR", "--reason"],
        "ports": "",
        "scripts": "",
    },
    "Fast service inventory": {
        "description": "Scan common ports and detect service versions on selected targets.",
        "options": [
            "-n",
            "-T4",
            "--top-ports",
            "--open",
            "-sV",
            "--version-light",
            "--max-retries",
            "--host-timeout",
        ],
        "top_ports": 1000,
        "max_retries": 2,
        "host_timeout": "5m",
        "ports": "",
        "scripts": "",
    },
    "Balanced asset inspection": {
        "description": "Balanced TCP scan with service detection and OS detection.",
        "options": [
            "-n",
            "-T3",
            "--top-ports",
            "--open",
            "-sV",
            "--version-light",
            "-O",
            "--osscan-limit",
            "--max-retries",
            "--host-timeout",
        ],
        "top_ports": 2000,
        "max_retries": 2,
        "host_timeout": "10m",
        "ports": "",
        "scripts": "",
    },
    "Aggressive scan": {
        "description": "Aggressive Nmap scan: OS, version, scripts, traceroute.",
        "options": ["-A", "-T4", "--max-retries", "--host-timeout"],
        "max_retries": 2,
        "host_timeout": "10m",
        "ports": "",
        "scripts": "",
    },
    "Full TCP ports selected host": {
        "description": "Deep scan of all TCP ports. Use on selected hosts only.",
        "options": [
            "-n",
            "-T3",
            "-p-",
            "-sV",
            "--version-light",
            "--max-retries",
            "--host-timeout",
        ],
        "max_retries": 2,
        "host_timeout": "20m",
        "ports": "",
        "scripts": "",
    },
    "UDP NTP check": {
        "description": "Check UDP/123 NTP service for ISO clock synchronization evidence.",
        "options": ["-n", "-sU", "-p", "--script", "--max-retries", "--host-timeout"],
        "ports": "123",
        "scripts": "ntp-info",
        "max_retries": 1,
        "host_timeout": "5m",
    },
    "IP protocol scan (-sO)": {
        "description": "Scan supported IP protocols. Advanced. This is not OS detection.",
        "options": ["-n", "-sO", "--max-retries", "--host-timeout"],
        "max_retries": 1,
        "host_timeout": "5m",
        "ports": "",
        "scripts": "",
    },
    "Custom from UI": {
        "description": "Start empty and choose exactly the options you want.",
        "options": ["-n"],
        "ports": "",
        "scripts": "",
    },
}


def option_by_flag(flag: str) -> Optional[NmapOption]:
    for opt in NMAP_OPTIONS:
        if opt.flag == flag:
            return opt
    return None


def grouped_options(include_advanced: bool = True) -> Dict[str, List[NmapOption]]:
    groups: Dict[str, List[NmapOption]] = {}
    for opt in NMAP_OPTIONS:
        if not include_advanced and opt.advanced:
            continue
        groups.setdefault(opt.category, []).append(opt)
    return groups


def validate_target_text(target_text: str) -> Tuple[bool, str]:
    target = (target_text or "").strip()
    if not target:
        return False, "Target is empty."

    # Allow Nmap target syntaxes broadly, but block obvious shell metacharacters.
    blocked = [";", "&", "|", "`", "$(", ">", "<"]
    if any(x in target for x in blocked):
        return False, "Target contains blocked shell metacharacters."

    # Do not block hostname/CIDR/ranges; Nmap supports many target formats.
    return True, "OK"


def split_custom_args(text: str) -> List[str]:
    if not text.strip():
        return []
    return shlex.split(text, posix=False)


def build_nmap_command(
    *,
    target: str,
    selected_flags: Iterable[str],
    output_xml: str,
    top_ports: Optional[int] = None,
    ports: str = "",
    scripts: str = "",
    max_retries: Optional[int] = None,
    host_timeout: str = "",
    custom_args: str = "",
    nmap_binary: str = "nmap",
) -> List[str]:
    args: List[str] = [nmap_binary]

    flags = list(dict.fromkeys(selected_flags))  # preserve order, remove duplicates

    for flag in flags:
        if flag in {
            "--top-ports",
            "-p",
            "--script",
            "--max-retries",
            "--host-timeout",
            "-oX",
            "-oN",
            "-oA",
        }:
            continue
        args.append(flag)

    if "--top-ports" in flags and top_ports:
        args += ["--top-ports", str(top_ports)]

    if "-p" in flags and ports:
        args += ["-p", ports]

    if "--script" in flags and scripts:
        args += ["--script", scripts]

    if "--max-retries" in flags and max_retries is not None:
        args += ["--max-retries", str(max_retries)]

    if "--host-timeout" in flags and host_timeout:
        args += ["--host-timeout", host_timeout]

    args += split_custom_args(custom_args)

    # Always provide XML for SecureScope parsing unless user explicitly added output.
    output_flags = {"-oX", "-oN", "-oA", "-oG", "-oS"}
    if not any(flag in args for flag in output_flags):
        args += ["-oX", output_xml]

    args.append(target)
    return args


def command_to_display(args: List[str]) -> str:
    # Good enough for PowerShell display.
    out = []
    for a in args:
        if re.search(r"\s", a):
            out.append(f'"{a}"')
        else:
            out.append(a)
    return " ".join(out)


def run_nmap(args: List[str], timeout_seconds: int = 1800) -> Dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": "Nmap executable not found. Install Nmap and make sure nmap.exe is in PATH.",
            "duration_seconds": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": f"Nmap timed out after {timeout_seconds} seconds.",
            "duration_seconds": round(time.time() - started, 2),
        }

    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "duration_seconds": round(time.time() - started, 2),
    }


def parse_nmap_xml(xml_path: str) -> List[Dict[str, Any]]:
    path = Path(xml_path)
    if not path.exists():
        return []

    tree = ET.parse(path)
    root = tree.getroot()

    assets: List[Dict[str, Any]] = []

    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.get("state") if status_el is not None else None

        addresses = {}
        vendors = {}
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype") or "unknown"
            addresses[addr_type] = addr.get("addr")
            if addr.get("vendor"):
                vendors[addr_type] = addr.get("vendor")

        hostnames = []
        hns = host.find("hostnames")
        if hns is not None:
            for hn in hns.findall("hostname"):
                if hn.get("name"):
                    hostnames.append(hn.get("name"))

        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")
                ports.append(
                    {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": state_el.get("state") if state_el is not None else None,
                        "service": service_el.get("name") if service_el is not None else None,
                        "product": service_el.get("product") if service_el is not None else None,
                        "version": service_el.get("version") if service_el is not None else None,
                        "extrainfo": (
                            service_el.get("extrainfo") if service_el is not None else None
                        ),
                    }
                )

        os_matches = []
        os_el = host.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch"):
                os_matches.append(
                    {
                        "name": match.get("name"),
                        "accuracy": match.get("accuracy"),
                    }
                )

        assets.append(
            {
                "ip": addresses.get("ipv4") or addresses.get("ipv6"),
                "mac_address": addresses.get("mac"),
                "mac_vendor": vendors.get("mac"),
                "status": status,
                "hostnames": hostnames,
                "hostname": hostnames[0] if hostnames else None,
                "ports": ports,
                "open_ports": [p for p in ports if p.get("state") == "open"],
                "os_matches": os_matches,
                "os_guess": os_matches[0]["name"] if os_matches else None,
                "source": "nmap_custom_profile",
            }
        )

    return assets


def infer_asset_classification(asset: Dict[str, Any]) -> Dict[str, Any]:
    open_ports = asset.get("open_ports") or []
    port_numbers = {str(p.get("port")) for p in open_ports}
    services = {str(p.get("service") or "").lower() for p in open_ports}

    device_type = "Unknown"
    criticality = "Medium"
    classification = "Internal Use"

    if {"5432", "3306", "1433", "1521"} & port_numbers:
        device_type = "Database server"
        criticality = "High"
        classification = "Restricted"
    elif {"80", "443", "8080", "8443"} & port_numbers:
        device_type = "Web server"
        criticality = "High"
        classification = "Confidential"
    elif {"3389", "445"} & port_numbers:
        device_type = "Windows host"
        criticality = "Medium"
        classification = "Internal Use"
    elif {"22"} & port_numbers:
        device_type = "Linux/Unix host"
        criticality = "Medium"
        classification = "Internal Use"
    elif {"123"} & port_numbers or "ntp" in services:
        device_type = "NTP/time service"
        criticality = "Medium"
        classification = "Internal Use"

    return {
        "device_type": device_type,
        "criticality": criticality,
        "information_classification": classification,
    }
