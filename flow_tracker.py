# flow_tracker.py
# Author: Gaurav Tiwari
"""Bidirectional flow state for the AI-Powered Network Security Framework.

Why this module exists
----------------------
The bundled Random Forest / Logistic Regression models were trained on
CSE-CIC-IDS2018 records produced by CICFlowMeter. Every one of those records
describes a *flow*: dozens of packets summarised into timing, directionality
and volume statistics.

The original engine handed those models a single packet with 53 of the 70
features hardcoded to 0.0. That is not a hard problem for the model, it is an
impossible one -- the columns carrying the signal were all constant. Measured
behaviour of the old path:

    Random Forest        fired on   0 / 10 packets (never contributed)
    Logistic Regression  fired on any payload >= ~64 bytes at p = 1.000

In other words the "AI" layer had degenerated into a payload-size threshold.

This module reconstructs genuine flow records from live packets so the models
are asked the question they were actually trained to answer.

Units follow CICFlowMeter: all durations and inter-arrival times are in
MICROSECONDS, lengths in bytes.
"""

import math
import time
from collections import OrderedDict, deque

import config

# CICFlowMeter splits a flow into "active" and "idle" spans at a 5s gap.
ACTIVITY_TIMEOUT_US = 5_000_000.0

# A bulk transfer is declared after this many consecutive payload-bearing
# packets in one direction (CICFlowMeter uses 4).
BULK_PACKET_THRESHOLD = 4

# The exact 70 columns the bundled models expect, in training order.
# Verified against RandomForestClassifier.feature_names_in_.
ML_FEATURE_COLUMNS = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
    'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
    'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Init Fwd Win Byts',
    'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]


# ---------------------------------------------------------------------------
# Small statistics helpers (avoid a numpy round-trip on the hot path)
# ---------------------------------------------------------------------------

def _mean(values):
    return sum(values) / len(values) if values else 0.0


def _std(values):
    """Population standard deviation, matching CICFlowMeter."""
    if len(values) < 2:
        return 0.0
    mu = _mean(values)
    return math.sqrt(sum((v - mu) ** 2 for v in values) / len(values))


def _max(values):
    return max(values) if values else 0.0


def _min(values):
    return min(values) if values else 0.0


def shannon_entropy(data):
    """Shannon entropy in bits per byte (0.0 - 8.0).

    Used for DNS-tunnelling and packed-payload detection. English text sits
    around 3.5-4.0; encrypted or compressed data approaches 8.0.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def flow_key(src_ip, src_port, dst_ip, dst_port, proto):
    """Direction-independent key, plus whether this packet is 'forward'.

    The endpoint that sent the first packet defines the forward direction, so
    both halves of a conversation land in the same Flow object.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (a, b, proto), True
    return (b, a, proto), False


# ---------------------------------------------------------------------------
# Flow
# ---------------------------------------------------------------------------

class Flow:
    """Accumulates the statistics CICFlowMeter emits for one conversation."""

    __slots__ = (
        'key', 'protocol', 'dst_port', 'start_time', 'last_seen',
        'fwd_lengths', 'bwd_lengths', 'fwd_header_bytes', 'bwd_header_bytes',
        'fwd_times', 'bwd_times', 'all_times',
        'fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'cwe', 'ece',
        'fwd_psh', 'bwd_psh', 'fwd_urg', 'bwd_urg',
        'init_fwd_win', 'init_bwd_win', 'fwd_act_data_pkts', 'fwd_seg_size_min',
        'active_periods', 'idle_periods', 'last_activity_end',
        'fwd_bulk_state', 'bwd_bulk_state',
        'stream_fwd', 'stream_bwd', 'ml_verdict_cache', 'packets_at_last_ml',
    )

    def __init__(self, key, protocol, dst_port, now):
        self.key = key
        self.protocol = protocol
        self.dst_port = dst_port
        self.start_time = now
        self.last_seen = now

        self.fwd_lengths = []
        self.bwd_lengths = []
        self.fwd_header_bytes = 0
        self.bwd_header_bytes = 0

        self.fwd_times = []
        self.bwd_times = []
        self.all_times = []

        self.fin = self.syn = self.rst = self.psh = 0
        self.ack = self.urg = self.cwe = self.ece = 0
        self.fwd_psh = self.bwd_psh = self.fwd_urg = self.bwd_urg = 0

        self.init_fwd_win = -1
        self.init_bwd_win = -1
        self.fwd_act_data_pkts = 0
        self.fwd_seg_size_min = 0

        self.active_periods = []
        self.idle_periods = []
        self.last_activity_end = now

        # (bulk_count, bulk_bytes, bulk_packets, consecutive, last_ts, duration)
        self.fwd_bulk_state = [0, 0, 0, 0, 0.0, 0.0]
        self.bwd_bulk_state = [0, 0, 0, 0, 0.0, 0.0]

        # Rolling payload buffers so signatures split across TCP segments are
        # still caught (the old stateless matcher missed those entirely).
        self.stream_fwd = bytearray()
        self.stream_bwd = bytearray()

        self.ml_verdict_cache = None
        self.packets_at_last_ml = 0

    # -- ingest ------------------------------------------------------------

    @property
    def packet_count(self):
        return len(self.fwd_lengths) + len(self.bwd_lengths)

    def update(self, now, forward, ip_len, header_len, payload, flags, window):
        """Fold one packet into the flow."""
        gap = (now - self.last_seen) * 1_000_000.0  # microseconds
        if self.packet_count > 0:
            if gap > ACTIVITY_TIMEOUT_US:
                self.active_periods.append(
                    (self.last_seen - self.last_activity_end) * 1_000_000.0)
                self.idle_periods.append(gap)
                self.last_activity_end = now
            self.all_times.append(gap)

        self.last_seen = now

        if forward:
            if self.fwd_lengths:
                self.fwd_times.append(gap)
            self.fwd_lengths.append(ip_len)
            self.fwd_header_bytes += header_len
            if self.init_fwd_win < 0 and window is not None:
                self.init_fwd_win = window
            if payload:
                self.fwd_act_data_pkts += 1
                seg = len(payload)
                if self.fwd_seg_size_min == 0 or seg < self.fwd_seg_size_min:
                    self.fwd_seg_size_min = seg
                if len(self.stream_fwd) < config.STREAM_REASSEMBLY_BYTES:
                    self.stream_fwd.extend(payload)
            self._update_bulk(self.fwd_bulk_state, now, payload)
        else:
            if self.bwd_lengths:
                self.bwd_times.append(gap)
            self.bwd_lengths.append(ip_len)
            self.bwd_header_bytes += header_len
            if self.init_bwd_win < 0 and window is not None:
                self.init_bwd_win = window
            if payload and len(self.stream_bwd) < config.STREAM_REASSEMBLY_BYTES:
                self.stream_bwd.extend(payload)
            self._update_bulk(self.bwd_bulk_state, now, payload)

        if flags:
            self.fin += 1 if flags.get('F') else 0
            self.syn += 1 if flags.get('S') else 0
            self.rst += 1 if flags.get('R') else 0
            self.psh += 1 if flags.get('P') else 0
            self.ack += 1 if flags.get('A') else 0
            self.urg += 1 if flags.get('U') else 0
            self.cwe += 1 if flags.get('C') else 0
            self.ece += 1 if flags.get('E') else 0
            if flags.get('P'):
                if forward:
                    self.fwd_psh += 1
                else:
                    self.bwd_psh += 1
            if flags.get('U'):
                if forward:
                    self.fwd_urg += 1
                else:
                    self.bwd_urg += 1

    def _update_bulk(self, state, now, payload):
        """Track bulk-transfer runs (>=4 consecutive payload packets)."""
        if not payload:
            state[3] = 0
            return
        state[3] += 1
        if state[3] == BULK_PACKET_THRESHOLD:
            state[0] += 1
            state[1] += len(payload) * BULK_PACKET_THRESHOLD
            state[2] += BULK_PACKET_THRESHOLD
            state[4] = now
        elif state[3] > BULK_PACKET_THRESHOLD:
            state[1] += len(payload)
            state[2] += 1
            state[5] += max(now - state[4], 0.0)
            state[4] = now

    # -- feature extraction ------------------------------------------------

    def _bulk_stats(self, state):
        """Return (bytes/bulk, packets/bulk, bulk rate)."""
        if state[0] == 0:
            return 0.0, 0.0, 0.0
        bytes_avg = state[1] / state[0]
        pkts_avg = state[2] / state[0]
        rate = state[1] / state[5] if state[5] > 0 else 0.0
        return bytes_avg, pkts_avg, rate

    def to_features(self):
        """Build the 70-column CICFlowMeter feature vector for this flow."""
        duration_us = max((self.last_seen - self.start_time) * 1_000_000.0, 0.0)
        all_lengths = self.fwd_lengths + self.bwd_lengths

        n_fwd = len(self.fwd_lengths)
        n_bwd = len(self.bwd_lengths)
        tot_fwd_bytes = sum(self.fwd_lengths)
        tot_bwd_bytes = sum(self.bwd_lengths)

        fwd_b_avg, fwd_p_avg, fwd_rate = self._bulk_stats(self.fwd_bulk_state)
        bwd_b_avg, bwd_p_avg, bwd_rate = self._bulk_stats(self.bwd_bulk_state)

        pkt_len_mean = _mean(all_lengths)
        pkt_len_std = _std(all_lengths)

        features = {
            'Dst Port': self.dst_port,
            'Protocol': self.protocol,
            'Flow Duration': duration_us,
            'Tot Fwd Pkts': n_fwd,
            'Tot Bwd Pkts': n_bwd,
            'TotLen Fwd Pkts': tot_fwd_bytes,
            'TotLen Bwd Pkts': tot_bwd_bytes,

            'Fwd Pkt Len Max': _max(self.fwd_lengths),
            'Fwd Pkt Len Min': _min(self.fwd_lengths),
            'Fwd Pkt Len Mean': _mean(self.fwd_lengths),
            'Fwd Pkt Len Std': _std(self.fwd_lengths),
            'Bwd Pkt Len Max': _max(self.bwd_lengths),
            'Bwd Pkt Len Min': _min(self.bwd_lengths),
            'Bwd Pkt Len Mean': _mean(self.bwd_lengths),
            'Bwd Pkt Len Std': _std(self.bwd_lengths),

            'Flow IAT Mean': _mean(self.all_times),
            'Flow IAT Std': _std(self.all_times),
            'Flow IAT Max': _max(self.all_times),
            'Flow IAT Min': _min(self.all_times),

            'Fwd IAT Tot': sum(self.fwd_times),
            'Fwd IAT Mean': _mean(self.fwd_times),
            'Fwd IAT Std': _std(self.fwd_times),
            'Fwd IAT Max': _max(self.fwd_times),
            'Fwd IAT Min': _min(self.fwd_times),
            'Bwd IAT Tot': sum(self.bwd_times),
            'Bwd IAT Mean': _mean(self.bwd_times),
            'Bwd IAT Std': _std(self.bwd_times),
            'Bwd IAT Max': _max(self.bwd_times),
            'Bwd IAT Min': _min(self.bwd_times),

            'Fwd PSH Flags': self.fwd_psh,
            'Bwd PSH Flags': self.bwd_psh,
            'Fwd URG Flags': self.fwd_urg,
            'Bwd URG Flags': self.bwd_urg,
            'Fwd Header Len': self.fwd_header_bytes,
            'Bwd Header Len': self.bwd_header_bytes,

            'Pkt Len Min': _min(all_lengths),
            'Pkt Len Max': _max(all_lengths),
            'Pkt Len Mean': pkt_len_mean,
            'Pkt Len Std': pkt_len_std,
            'Pkt Len Var': pkt_len_std ** 2,

            'FIN Flag Cnt': self.fin,
            'SYN Flag Cnt': self.syn,
            'RST Flag Cnt': self.rst,
            'PSH Flag Cnt': self.psh,
            'ACK Flag Cnt': self.ack,
            'URG Flag Cnt': self.urg,
            'CWE Flag Count': self.cwe,
            'ECE Flag Cnt': self.ece,

            'Down/Up Ratio': (n_bwd / n_fwd) if n_fwd else 0.0,
            'Pkt Size Avg': pkt_len_mean,
            'Fwd Seg Size Avg': _mean(self.fwd_lengths),
            'Bwd Seg Size Avg': _mean(self.bwd_lengths),

            'Fwd Byts/b Avg': fwd_b_avg,
            'Fwd Pkts/b Avg': fwd_p_avg,
            'Fwd Blk Rate Avg': fwd_rate,
            'Bwd Byts/b Avg': bwd_b_avg,
            'Bwd Pkts/b Avg': bwd_p_avg,
            'Bwd Blk Rate Avg': bwd_rate,

            'Init Fwd Win Byts': self.init_fwd_win,
            'Init Bwd Win Byts': self.init_bwd_win,
            'Fwd Act Data Pkts': self.fwd_act_data_pkts,
            'Fwd Seg Size Min': self.fwd_seg_size_min,

            'Active Mean': _mean(self.active_periods),
            'Active Std': _std(self.active_periods),
            'Active Max': _max(self.active_periods),
            'Active Min': _min(self.active_periods),
            'Idle Mean': _mean(self.idle_periods),
            'Idle Std': _std(self.idle_periods),
            'Idle Max': _max(self.idle_periods),
            'Idle Min': _min(self.idle_periods),
        }

        return [float(features[col]) for col in ML_FEATURE_COLUMNS]


# ---------------------------------------------------------------------------
# FlowTracker
# ---------------------------------------------------------------------------

class FlowTracker:
    """Bounded, self-expiring table of active flows.

    The bound matters: without it a spoofed-source flood creates one Flow per
    forged address and exhausts memory -- turning the firewall itself into the
    denial-of-service vector.
    """

    def __init__(self, max_flows=None, timeout=None):
        self.flows = OrderedDict()
        self.max_flows = max_flows or config.MAX_TRACKED_FLOWS
        self.timeout = timeout or config.FLOW_TIMEOUT
        self._last_sweep = 0.0
        self.evictions = 0

    def get_or_create(self, src_ip, src_port, dst_ip, dst_port, proto, now=None):
        now = time.time() if now is None else now
        key, forward = flow_key(src_ip, src_port, dst_ip, dst_port, proto)

        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(key, proto, dst_port if forward else src_port, now)
            self.flows[key] = flow
            self._enforce_bounds(now)
        else:
            self.flows.move_to_end(key)
        return flow, forward

    def _enforce_bounds(self, now):
        # Sweep expired flows at most once a second.
        if now - self._last_sweep > 1.0:
            self._last_sweep = now
            cutoff = now - self.timeout
            stale = [k for k, f in self.flows.items() if f.last_seen < cutoff]
            for k in stale:
                del self.flows[k]

        # Hard cap: evict least-recently-used.
        while len(self.flows) > self.max_flows:
            self.flows.popitem(last=False)
            self.evictions += 1

    def __len__(self):
        return len(self.flows)


# ---------------------------------------------------------------------------
# BehaviourTracker -- port scans and SYN floods
# ---------------------------------------------------------------------------

class BehaviourTracker:
    """Per-source sliding windows for scan and flood detection."""

    def __init__(self):
        self.scan_windows = {}   # src_ip -> deque[(ts, dst_port)]
        self.syn_windows = {}    # src_ip -> deque[ts]
        self.flagged_scanners = {}
        self.flagged_flooders = {}

    def record_syn(self, src_ip, dst_port, now):
        """Record a SYN. Returns (is_scan, is_flood, detail)."""
        ports = self.scan_windows.setdefault(src_ip, deque())
        ports.append((now, dst_port))
        cutoff = now - config.PORT_SCAN_WINDOW
        while ports and ports[0][0] < cutoff:
            ports.popleft()

        syns = self.syn_windows.setdefault(src_ip, deque())
        syns.append(now)
        syn_cutoff = now - config.SYN_FLOOD_WINDOW
        while syns and syns[0] < syn_cutoff:
            syns.popleft()

        distinct_ports = len({p for _, p in ports})
        is_scan = distinct_ports >= config.PORT_SCAN_THRESHOLD
        is_flood = len(syns) >= config.SYN_FLOOD_THRESHOLD

        detail = ""
        if is_scan:
            self.flagged_scanners[src_ip] = now
            detail = (f"{distinct_ports} distinct ports in "
                      f"{config.PORT_SCAN_WINDOW:.0f}s")
        elif is_flood:
            self.flagged_flooders[src_ip] = now
            detail = (f"{len(syns)} SYNs in "
                      f"{config.SYN_FLOOD_WINDOW:.0f}s")

        return is_scan, is_flood, detail

    def prune(self, now):
        """Drop per-source state that has gone quiet, bounding memory."""
        cutoff = now - max(config.PORT_SCAN_WINDOW, config.SYN_FLOOD_WINDOW) * 4
        for table in (self.scan_windows, self.syn_windows):
            for ip in [k for k, v in table.items()
                       if not v or (v[-1][0] if isinstance(v[-1], tuple) else v[-1]) < cutoff]:
                del table[ip]
        for table in (self.flagged_scanners, self.flagged_flooders):
            for ip in [k for k, ts in table.items() if ts < cutoff]:
                del table[ip]
