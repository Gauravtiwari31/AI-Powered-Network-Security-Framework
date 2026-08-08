# detection_engine.py
# Author: Gaurav Tiwari
"""Platform-independent detection core.

Both front-ends -- `dpi_firewall.py` (Linux / NetfilterQueue) and
`windows_active_firewall.py` (Windows / WinDivert) -- feed raw packet bytes
into `inspect()` and act on the returned `Verdict`. Keeping the logic here
means Linux and Windows cannot drift apart, and it means the detection layers
are importable and testable without a packet-capture driver installed.

Detection layers, cheapest first:

    0. Allowlist          never drop the traffic that keeps the box reachable
    1. Static rules       IP / port blacklists
    2. Fragment sanity    tiny-first-fragment evasion, fragment floods
    3. Signature DPI      regex over reassembled streams, not lone packets
    4. Heuristics         DNS tunnelling, packed payloads (Shannon entropy)
    5. Behaviour          port scans, SYN floods
    6. JA3                TLS client fingerprinting against known-bad hashes
    7. Machine learning   flow-level RF + LR consensus

Layers 1-7 contribute to a threat score; the packet is dropped once the score
reaches `config.BLOCK_THRESHOLD`. Scoring replaces the old any-single-layer
veto, which let one weak signal (an over-eager ML label) drop good traffic.
"""

import ipaddress
import logging
import os
import time

import config
from flow_tracker import (
    ML_FEATURE_COLUMNS,
    BehaviourTracker,
    FlowTracker,
    shannon_entropy,
)

log = logging.getLogger("firewall")

# Scapy is required; sklearn/joblib are optional (ML degrades to disabled).
from scapy.all import IP, IPv6, TCP, UDP, ICMP

try:
    import joblib
    import numpy as np
    _ML_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the install
    joblib = None
    np = None
    _ML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

class Verdict:
    """The engine's decision about one packet."""

    __slots__ = ('block', 'score', 'reasons', 'summary')

    def __init__(self):
        self.block = False
        self.score = 0
        self.reasons = []
        self.summary = ""

    def add(self, layer, detail, score):
        """Record a detection. Returns True once the block threshold is met."""
        self.score += score
        self.reasons.append((layer, detail, score))
        if self.score >= config.BLOCK_THRESHOLD:
            self.block = True
        return self.block

    def finish(self, summary=""):
        if summary:
            self.summary = summary
        elif self.reasons:
            layer, detail, _ = self.reasons[0]
            extra = f" (+{len(self.reasons) - 1} more)" if len(self.reasons) > 1 else ""
            self.summary = f"[{layer}] {detail}{extra} score={self.score}"
        return self

    def __bool__(self):
        return self.block

    def __repr__(self):
        state = "BLOCK" if self.block else "ALLOW"
        return f"<Verdict {state} score={self.score} {self.summary}>"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DetectionEngine:

    def __init__(self, load_models=True):
        self.flows = FlowTracker()
        self.behaviour = BehaviourTracker()
        self.fragments = {}          # (src, dst, ip_id) -> {'parts': [], 'ts': float}

        self.rf_model = None
        self.lr_model = None
        self.scaler = None
        self.ml_enabled = False

        self._allow_networks = []
        for cidr in config.ALLOWLISTED_CIDRS:
            try:
                self._allow_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("Ignoring malformed allowlist CIDR: %s", cidr)

        self.stats = {
            'inspected': 0, 'blocked': 0, 'allowed': 0, 'errors': 0,
            'ml_evaluated': 0, 'ml_flagged': 0,
        }

        if load_models:
            self.load_models()

    # -- model loading -----------------------------------------------------

    def load_models(self):
        """Load RF / LR / scaler. ML stays disabled on any failure."""
        if not _ML_AVAILABLE:
            log.warning("scikit-learn/joblib unavailable - ML layer disabled.")
            return False

        paths = {
            'rf': os.path.join(config.MODEL_DIR, 'random_forest_model.pkl'),
            'lr': os.path.join(config.MODEL_DIR, 'logistic_regression_model.pkl'),
            'scaler': os.path.join(config.MODEL_DIR, 'scaler.pkl'),
        }
        missing = [p for p in paths.values() if not os.path.exists(p)]
        if missing:
            log.warning("ML models not found (%s) - ML layer disabled.",
                        ", ".join(missing))
            return False

        try:
            self.rf_model = joblib.load(paths['rf'])
            self.lr_model = joblib.load(paths['lr'])
            self.scaler = joblib.load(paths['scaler'])
        except Exception as exc:
            log.error("Failed to load ML models: %s - ML layer disabled.", exc)
            self.rf_model = self.lr_model = self.scaler = None
            return False

        # Guard against a model/feature-list mismatch silently producing
        # garbage predictions on a shifted feature vector.
        expected = getattr(self.rf_model, 'n_features_in_', len(ML_FEATURE_COLUMNS))
        if expected != len(ML_FEATURE_COLUMNS):
            log.error("Model expects %d features but %d are defined - "
                      "ML layer disabled.", expected, len(ML_FEATURE_COLUMNS))
            self.rf_model = self.lr_model = self.scaler = None
            return False

        self.ml_enabled = True
        mode = "ENFORCING" if config.ML_ENFORCE else "monitor-only"
        log.info("ML models loaded (%d features, %s).", expected, mode)
        return True

    # -- allowlist ---------------------------------------------------------

    def _is_allowlisted(self, src_ip, dst_ip, src_port, dst_port):
        if src_ip in config.ALLOWLISTED_IPS or dst_ip in config.ALLOWLISTED_IPS:
            return True
        for ip in (src_ip, dst_ip):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for net in self._allow_networks:
                if addr.version == net.version and addr in net:
                    return True
        return False

    # -- packet parsing ----------------------------------------------------

    @staticmethod
    def parse(raw_bytes):
        """Parse raw bytes as IPv4 or IPv6.

        The previous code called `IP(raw)` unconditionally. Handing it an IPv6
        packet produced src/dst of 0.0.0.0 and every check silently passed, so
        IPv6 traffic bypassed the firewall completely.
        """
        if not raw_bytes:
            return None
        version = raw_bytes[0] >> 4
        try:
            if version == 4:
                return IP(bytes(raw_bytes))
            if version == 6:
                return IPv6(bytes(raw_bytes))
        except Exception as exc:
            log.debug("Unparseable packet: %s", exc)
            return None
        log.debug("Unknown IP version %s", version)
        return None

    @staticmethod
    def _tcp_flag_map(tcp_layer):
        f = tcp_layer.flags
        return {
            'F': bool(f.F), 'S': bool(f.S), 'R': bool(f.R), 'P': bool(f.P),
            'A': bool(f.A), 'U': bool(f.U), 'C': bool(f.C), 'E': bool(f.E),
        }

    # -- main entry point --------------------------------------------------

    def inspect(self, raw_bytes, now=None):
        """Inspect one packet. Always returns a Verdict, never raises."""
        now = time.time() if now is None else now
        self.stats['inspected'] += 1
        verdict = Verdict()

        try:
            self._inspect_inner(raw_bytes, now, verdict)
        except Exception as exc:
            self.stats['errors'] += 1
            log.error("Detection error (%s: %s) - failing %s.",
                      type(exc).__name__, exc, config.FAILURE_MODE, exc_info=True)
            if config.FAILURE_MODE == "closed":
                verdict.block = True
                verdict.summary = f"[ERROR] fail-closed: {type(exc).__name__}"
            else:
                verdict.block = False
                verdict.summary = f"[ERROR] fail-open: {type(exc).__name__}"
            return verdict

        verdict.finish()
        if verdict.block:
            self.stats['blocked'] += 1
        else:
            self.stats['allowed'] += 1
        return verdict

    def _inspect_inner(self, raw_bytes, now, verdict):
        pkt = self.parse(raw_bytes)
        if pkt is None:
            # Unparseable: nothing to inspect, defer to the failure policy.
            if config.FAILURE_MODE == "closed":
                verdict.add("PARSE", "unparseable packet", 100)
            return

        is_v6 = IPv6 in pkt
        ip_layer = pkt[IPv6] if is_v6 else pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if is_v6:
            proto = ip_layer.nh
            ip_len = len(pkt)
            header_len = 40
        else:
            proto = ip_layer.proto
            ip_len = ip_layer.len if ip_layer.len else len(pkt)
            header_len = (ip_layer.ihl or 5) * 4

        src_port = dst_port = None
        flags = None
        window = None
        payload = b""
        proto_name = "OTHER"

        if TCP in pkt:
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            flags = self._tcp_flag_map(tcp)
            window = tcp.window
            payload = bytes(tcp.payload)
            header_len += (tcp.dataofs or 5) * 4
            proto_name = "TCP"
        elif UDP in pkt:
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            payload = bytes(udp.payload)
            header_len += 8
            proto_name = "UDP"
        elif ICMP in pkt:
            proto_name = "ICMP"

        # --- Layer 0: allowlist ------------------------------------------
        if self._is_allowlisted(src_ip, dst_ip, src_port, dst_port):
            verdict.summary = "[ALLOWLIST] exempt endpoint"
            return

        # --- Layer 1: static rules ---------------------------------------
        if src_ip in config.BLOCKED_IPS:
            if verdict.add("RULE", f"source IP blacklisted: {src_ip} -> {dst_ip}", 100):
                return
        if dst_ip in config.BLOCKED_IPS:
            if verdict.add("RULE", f"destination IP blacklisted: {src_ip} -> {dst_ip}", 100):
                return
        if proto_name in ("TCP", "UDP"):
            if src_port in config.BLOCKED_PORTS or dst_port in config.BLOCKED_PORTS:
                blocked = src_port if src_port in config.BLOCKED_PORTS else dst_port
                if verdict.add("RULE",
                               f"port {blocked} blacklisted: {src_ip}:{src_port} -> "
                               f"{dst_ip}:{dst_port} ({proto_name})", 100):
                    return

        # --- Layer 2: fragment sanity ------------------------------------
        if not is_v6 and self._is_fragment(ip_layer):
            if self._check_fragment(ip_layer, now, verdict):
                return
            # Non-initial fragments carry no usable headers; stop here.
            if ip_layer.frag != 0:
                return

        # --- Flow bookkeeping (drives stream reassembly and the ML layer) --
        flow = None
        forward = True
        if proto_name in ("TCP", "UDP"):
            flow, forward = self.flows.get_or_create(
                src_ip, src_port, dst_ip, dst_port, proto, now)
            flow.update(now, forward, ip_len, header_len, payload, flags, window)

        # --- Layer 3: signature DPI over the reassembled stream -----------
        # Matching the flow buffer instead of the lone packet is what catches
        # a signature deliberately split across two TCP segments.
        haystack = payload
        if flow is not None and payload:
            haystack = bytes(flow.stream_fwd if forward else flow.stream_bwd)

        if haystack:
            for pattern, label, severity in config.MALICIOUS_SIGNATURES:
                if pattern.search(haystack):
                    if verdict.add("DPI", label, severity):
                        return

        # --- Layer 4: entropy heuristics ---------------------------------
        if payload:
            self._check_entropy(payload, src_port, dst_port, proto_name, verdict)
            if verdict.block:
                return

        # --- Layer 5: behavioural (scans, floods) -------------------------
        if flags and flags['S'] and not flags['A']:
            is_scan, is_flood, detail = self.behaviour.record_syn(src_ip, dst_port, now)
            if is_scan and verdict.add("SCAN", f"port scan from {src_ip}: {detail}", 85):
                return
            if is_flood and verdict.add("FLOOD", f"SYN flood from {src_ip}: {detail}", 85):
                return

        # --- Layer 6: JA3 TLS fingerprinting ------------------------------
        if proto_name == "TCP" and payload:
            ja3 = compute_ja3(payload)
            if ja3 and ja3 in config.KNOWN_MALICIOUS_JA3_HASHES:
                if verdict.add("JA3", f"known-malicious TLS fingerprint {ja3}", 95):
                    return

        # --- Layer 7: machine learning ------------------------------------
        if flow is not None:
            self._check_ml(flow, verdict)

    # -- layer 2 helpers ---------------------------------------------------

    @staticmethod
    def _is_fragment(ip_layer):
        # bit 0 of IP flags is MF (More Fragments).
        return bool(int(ip_layer.flags) & 0x1) or ip_layer.frag != 0

    def _check_fragment(self, ip_layer, now, verdict):
        """Fragment bookkeeping. Returns True if the packet was blocked.

        The original code referenced a FRAGMENT_BUFFER global that was never
        defined anywhere in the module, so the first fragmented packet raised
        NameError inside the handler.
        """
        expired = [k for k, v in self.fragments.items()
                   if now - v['ts'] > config.FRAGMENT_TIMEOUT]
        for k in expired:
            del self.fragments[k]

        key = (ip_layer.src, ip_layer.dst, ip_layer.id)
        entry = self.fragments.setdefault(key, {'parts': 0, 'ts': now})
        entry['parts'] += 1
        entry['ts'] = now

        if entry['parts'] > config.MAX_FRAGMENTS_PER_FLOW:
            del self.fragments[key]
            return verdict.add("FRAG",
                               f"fragment flood: >{config.MAX_FRAGMENTS_PER_FLOW} "
                               f"fragments for IP id {ip_layer.id}", 90)

        # A first fragment too small to hold the transport header is a classic
        # way to push the interesting bytes past a stateless inspector.
        if ip_layer.frag == 0 and ip_layer.len and ip_layer.len < config.MIN_FIRST_FRAGMENT_SIZE:
            del self.fragments[key]
            return verdict.add("FRAG",
                               f"tiny first fragment (len={ip_layer.len}) for "
                               f"IP id {ip_layer.id}", 90)
        return False

    # -- layer 4 helpers ---------------------------------------------------

    def _check_entropy(self, payload, src_port, dst_port, proto_name, verdict):
        # DNS tunnelling: exfiltration encodes data into oversized,
        # high-entropy query names.
        if proto_name == "UDP" and 53 in (src_port, dst_port):
            if len(payload) >= config.DNS_TUNNEL_MIN_LEN:
                entropy = shannon_entropy(payload)
                if entropy >= config.DNS_TUNNEL_ENTROPY:
                    verdict.add("TUNNEL",
                                f"probable DNS tunnelling: {len(payload)}B payload, "
                                f"entropy {entropy:.2f}", 85)
            return

        # High-entropy payload on a port that should not be carrying ciphertext
        # suggests a packed or encrypted stage being pulled in the clear.
        if len(payload) >= config.ENTROPY_MIN_PAYLOAD:
            if src_port in config.ENTROPY_EXEMPT_PORTS or dst_port in config.ENTROPY_EXEMPT_PORTS:
                return
            entropy = shannon_entropy(payload)
            if entropy >= config.HIGH_ENTROPY_THRESHOLD:
                verdict.add("ENTROPY",
                            f"high-entropy payload on cleartext port {dst_port}: "
                            f"{entropy:.2f} bits/byte over {len(payload)}B", 55)

    # -- layer 7 helpers ---------------------------------------------------

    def _check_ml(self, flow, verdict):
        if not self.ml_enabled:
            return
        # A flow-trained model has nothing to say about a two-packet flow.
        if flow.packet_count < config.ML_MIN_PACKETS:
            return
        # Re-score only as the flow actually grows.
        if flow.packets_at_last_ml == flow.packet_count:
            return
        flow.packets_at_last_ml = flow.packet_count

        try:
            features = np.array(flow.to_features(), dtype=float).reshape(1, -1)
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

            rf_prob = float(self.rf_model.predict_proba(features)[0][1])
            lr_prob = float(self.lr_model.predict_proba(self.scaler.transform(features))[0][1])
        except Exception as exc:
            log.error("ML prediction failed: %s", exc)
            return

        self.stats['ml_evaluated'] += 1
        rf_hit = rf_prob >= config.ML_RF_THRESHOLD
        lr_hit = lr_prob >= config.ML_LR_THRESHOLD
        fired = (rf_hit and lr_hit) if config.ML_REQUIRE_CONSENSUS else (rf_hit or lr_hit)

        if not fired:
            return

        self.stats['ml_flagged'] += 1
        detail = (f"flow classified malicious (RF={rf_prob:.3f}, LR={lr_prob:.3f}, "
                  f"{flow.packet_count} pkts)")

        if config.ML_ENFORCE:
            verdict.add("ML", detail, config.ML_SCORE)
        else:
            # Monitor mode: record it for the log, contribute nothing to the
            # drop decision. These models have not been validated on live
            # traffic, so they do not get a vote until you validate them.
            log.info("ML (monitor-only, not blocking): %s", detail)
            verdict.reasons.append(("ML-MONITOR", detail, 0))


# ---------------------------------------------------------------------------
# JA3 -- computed from raw TLS bytes
# ---------------------------------------------------------------------------

def _is_grease(value):
    """GREASE values (RFC 8701) are random padding and must be excluded."""
    return (value & 0x0f0f) == 0x0a0a and (value >> 8) == (value & 0xff)


def compute_ja3(payload):
    """Return the JA3 MD5 for a TLS ClientHello, or None.

    Parsed straight from the wire rather than via Scapy's TLS layer: that
    layer is only bound after an explicit `load_layer("tls")`, so the original
    `TLSClientHello in packet` test was essentially never true and the JA3
    check never ran.

    The original implementation also *sorted* the cipher and extension lists.
    JA3 is defined over wire order -- sorting produces hashes that cannot
    match any published threat feed, which is the entire point of JA3.
    """
    import hashlib
    try:
        # TLS record: type(1) version(2) length(2)
        if len(payload) < 45 or payload[0] != 0x16:
            return None
        # Handshake: type(1) length(3) version(2) random(32)
        if payload[5] != 0x01:
            return None

        pos = 9                      # start of handshake body
        client_version = int.from_bytes(payload[pos:pos + 2], 'big')
        pos += 2 + 32                # version + random

        session_id_len = payload[pos]
        pos += 1 + session_id_len

        cipher_len = int.from_bytes(payload[pos:pos + 2], 'big')
        pos += 2
        ciphers = [
            int.from_bytes(payload[pos + i:pos + i + 2], 'big')
            for i in range(0, cipher_len, 2)
        ]
        pos += cipher_len

        comp_len = payload[pos]
        pos += 1 + comp_len

        extensions, curves, point_formats = [], [], []
        if pos + 2 <= len(payload):
            ext_total = int.from_bytes(payload[pos:pos + 2], 'big')
            pos += 2
            end = min(pos + ext_total, len(payload))
            while pos + 4 <= end:
                ext_type = int.from_bytes(payload[pos:pos + 2], 'big')
                ext_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
                body = payload[pos + 4:pos + 4 + ext_len]
                pos += 4 + ext_len
                extensions.append(ext_type)

                if ext_type == 0x000a and len(body) >= 2:      # supported_groups
                    n = int.from_bytes(body[0:2], 'big')
                    curves = [
                        int.from_bytes(body[2 + i:4 + i], 'big')
                        for i in range(0, min(n, len(body) - 2), 2)
                    ]
                elif ext_type == 0x000b and len(body) >= 1:    # ec_point_formats
                    n = body[0]
                    point_formats = list(body[1:1 + n])

        def joined(values, filter_grease=True):
            if filter_grease:
                values = [v for v in values if not _is_grease(v)]
            return "-".join(str(v) for v in values)

        ja3_string = ",".join([
            str(client_version),
            joined(ciphers),
            joined(extensions),
            joined(curves),
            joined(point_formats, filter_grease=False),
        ])
        return hashlib.md5(ja3_string.encode('ascii')).hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Module-level convenience singleton
# ---------------------------------------------------------------------------

_engine = None


def get_engine():
    """Lazily construct the shared engine."""
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine
