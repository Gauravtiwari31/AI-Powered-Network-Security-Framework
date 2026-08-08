# config.py
# Author: Gaurav Tiwari
"""Central configuration for the AI-Powered Network Security Framework.

Every tunable lives here so the detection engine stays policy-free and the
same rules apply identically to the Linux (NetfilterQueue) and Windows
(WinDivert) front-ends.
"""

import re

# ---------------------------------------------------------------------------
# Phase 1 -- Static rules
# ---------------------------------------------------------------------------

BLOCKED_IPS = [
    "8.8.8.8",
    "192.168.1.100",
]

BLOCKED_PORTS = [
    22,    # SSH
    23,    # Telnet
    8080,  # Common proxy / alt-HTTP
]

# Traffic that must NEVER be dropped, evaluated before every other phase.
# Without this an over-eager ML verdict can cut the box off the network --
# including the SSH session you are using to turn the firewall back off.
ALLOWLISTED_IPS = [
    "127.0.0.1",
    "::1",
]

ALLOWLISTED_CIDRS = [
    "127.0.0.0/8",     # loopback
    "169.254.0.0/16",  # link-local / APIPA
    "224.0.0.0/4",     # multicast (mDNS, SSDP, IGMP)
]

# Ports that keep the machine usable and reachable. DHCP/DNS/NTP failures look
# exactly like an outage, so these bypass the probabilistic layers.
ALLOWLISTED_PORTS = [
    53,   # DNS      (still entropy-checked for tunnelling, see below)
    67,   # DHCP server
    68,   # DHCP client
    123,  # NTP
]

# ---------------------------------------------------------------------------
# Phase 2 -- Deep packet inspection signatures
# ---------------------------------------------------------------------------

# Each entry is (compiled_pattern, human_label, severity 0-100).
# Severity feeds the threat score; anything >= BLOCK_THRESHOLD is dropped.
MALICIOUS_SIGNATURES = [
    # --- SQL injection ---------------------------------------------------
    (re.compile(rb"union\s*(?:/\*.*?\*/)?\s*select", re.I | re.S), "SQLi: UNION SELECT", 90),
    (re.compile(rb"(?:'|%27)\s*(?:or|and)\s*(?:'?\d+'?\s*=\s*'?\d+|'[^']*'\s*=\s*')", re.I), "SQLi: tautology", 85),
    # WAITFOR DELAY takes no parentheses, unlike sleep()/benchmark().
    (re.compile(rb"\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b", re.I), "SQLi: time-based blind", 85),
    (re.compile(rb"\binto\s+(?:out|dump)file\b", re.I), "SQLi: file write", 95),
    (re.compile(rb"\b(?:information_schema|sysobjects|pg_catalog)\b", re.I), "SQLi: schema probe", 70),

    # --- Cross-site scripting -------------------------------------------
    (re.compile(rb"<\s*script[^>]*>", re.I), "XSS: script tag", 85),
    (re.compile(rb"\bon(?:error|load|click|mouseover|focus)\s*=", re.I), "XSS: inline event handler", 75),
    (re.compile(rb"javascript\s*:", re.I), "XSS: javascript URI", 70),
    (re.compile(rb"<\s*(?:img|svg|iframe|body)[^>]+on\w+\s*=", re.I), "XSS: tag with handler", 85),

    # --- Command injection / RCE ----------------------------------------
    (re.compile(rb"(?:;|\||&&|\$\(|`)\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|bash|sh)\b", re.I), "RCE: shell metacharacter", 90),
    (re.compile(rb"\(\s*\)\s*\{\s*:\s*;\s*\}\s*;", re.I), "RCE: Shellshock (CVE-2014-6271)", 100),
    (re.compile(rb"\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop)://", re.I), "RCE: Log4Shell (CVE-2021-44228)", 100),
    # No \b before the dash: a space followed by "-" is not a word boundary,
    # so "\b-enc" can never match "powershell.exe -enc".
    (re.compile(rb"\bpowershell(?:\.exe)?\b.{0,80}?[\s;|&]-(?:enc\w*|nop\w*|w\s+hidden|windowstyle\s+hidden|ep\s+bypass|executionpolicy\s+bypass)\b", re.I | re.S), "RCE: obfuscated PowerShell", 95),
    (re.compile(rb"\b(?:wget|curl)\s+(?:-\S+\s+)*https?://", re.I), "RCE: remote payload fetch", 75),
    (re.compile(rb"\bnc(?:at)?\s+(?:-\w+\s+)*-\w*[le]", re.I), "RCE: netcat listener/exec", 90),
    (re.compile(rb"\bexec\s*\(", re.I), "RCE: exec() call", 65),

    # --- Path traversal / LFI -------------------------------------------
    (re.compile(rb"(?:\.\.[\\/]){2,}", re.I), "Traversal: ../ sequence", 85),
    (re.compile(rb"(?:%2e%2e(?:%2f|%5c)){2,}", re.I), "Traversal: URL-encoded ../", 90),
    (re.compile(rb"/etc/(?:passwd|shadow)\b", re.I), "LFI: /etc/passwd", 90),
    (re.compile(rb"\bboot\.ini\b|\bwin\.ini\b", re.I), "LFI: Windows system file", 80),

    # --- SSRF / cloud metadata ------------------------------------------
    (re.compile(rb"169\.254\.169\.254", re.I), "SSRF: cloud metadata endpoint", 90),
    (re.compile(rb"\bfile://|\bgopher://|\bdict://", re.I), "SSRF: dangerous URI scheme", 75),

    # --- Scanners / recon -------------------------------------------------
    (re.compile(rb"User-Agent:\s*(?:Nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus)", re.I), "Recon: scanner user-agent", 80),
]

# Backwards compatibility: older code imported a flat list of patterns.
MALICIOUS_REGEX_PATTERNS = [sig[0] for sig in MALICIOUS_SIGNATURES]

# ---------------------------------------------------------------------------
# Phase 3 -- TLS / JA3
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_JA3_HASHES = [
    "60c73e03126780ee6df54162e071ff1e",
    "e270e5b7c7b897f903a45a6c11b0e386",
    "0f878a2e128147d3d23d8393e25b62b1",
    "73b87968e7b172a27572352882a98f1f",
    "f18830113f98e7bb664cc0854d9b626e",
    "9bf75c324c0e6e8e84d4b267104b281f",
]

# ---------------------------------------------------------------------------
# Phase 4 -- Behavioural heuristics
# ---------------------------------------------------------------------------

# Port scanning: N distinct destination ports from one source inside a window.
PORT_SCAN_WINDOW = 10.0        # seconds
PORT_SCAN_THRESHOLD = 15       # distinct ports before we call it a scan

# SYN flood: half-open connection attempts from one source inside a window.
SYN_FLOOD_WINDOW = 5.0         # seconds
SYN_FLOOD_THRESHOLD = 100      # SYNs before we call it a flood

# DNS tunnelling: high-entropy, oversized DNS payloads carry encoded data.
DNS_TUNNEL_MIN_LEN = 100       # bytes of DNS payload before we bother scoring
DNS_TUNNEL_ENTROPY = 4.2       # Shannon bits/byte; English text sits near 3.5

# Generic payload entropy. Encrypted/compressed data approaches 8.0, so this
# only flags *unencrypted* ports carrying high-entropy blobs (packed malware).
HIGH_ENTROPY_THRESHOLD = 7.2
ENTROPY_MIN_PAYLOAD = 256      # ignore short payloads; entropy is noisy there
ENTROPY_EXEMPT_PORTS = [443, 22, 993, 995, 465, 587, 636, 989, 990, 8443]

# IP fragmentation
FRAGMENT_TIMEOUT = 5           # seconds before an incomplete fragment set expires
MIN_FIRST_FRAGMENT_SIZE = 28   # tiny first fragments are a classic IDS evasion
MAX_FRAGMENTS_PER_FLOW = 64    # cap memory per fragment set

# ---------------------------------------------------------------------------
# Phase 5 -- Machine learning
# ---------------------------------------------------------------------------

MODEL_DIR = "./trained_models"

# The bundled models were trained on CICFlowMeter *flow* records, so a verdict
# is meaningless until a flow has accumulated real timing/directionality data.
# Below this packet count the ML layer abstains entirely.
ML_MIN_PACKETS = 8

# Both models must exceed their threshold before ML contributes to a block.
# Requiring agreement (AND) rather than either-or (OR) is what keeps the
# false-positive rate survivable -- see tests/test_detection.py.
ML_RF_THRESHOLD = 0.80
ML_LR_THRESHOLD = 0.90
ML_REQUIRE_CONSENSUS = True

# ML runs in monitor-only mode by default: it logs and scores but never drops
# on its own. Flip to True once you have validated the models on YOUR traffic.
ML_ENFORCE = False
ML_SCORE = 60                  # threat-score contribution when ML fires

# ---------------------------------------------------------------------------
# Scoring & policy
# ---------------------------------------------------------------------------

# A packet is dropped once its accumulated threat score reaches this value.
BLOCK_THRESHOLD = 80

# What to do when the engine itself raises an unexpected exception.
#   "open"   -> accept the packet (availability first, the original behaviour)
#   "closed" -> drop the packet    (security first)
FAILURE_MODE = "open"

# Cap on tracked state, so a spoofed-source flood cannot exhaust memory.
MAX_TRACKED_FLOWS = 20000
FLOW_TIMEOUT = 120.0           # seconds of inactivity before a flow is evicted

# Reassembly window used to catch signatures split across TCP segments.
STREAM_REASSEMBLY_BYTES = 4096
