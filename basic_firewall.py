# basic_firewall.py
# Author: Gaurav Tiwari
"""Minimal rule-only firewall -- the teaching example.

This is deliberately the simplest thing that works: IP and port blacklists,
nothing else. It exists to show the NetfilterQueue plumbing on its own,
before DPI, heuristics and ML are layered on top in `dpi_firewall.py`.

Rules come from `config.py` so this file and the full engine can never
disagree about what is blocked.

    sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
    sudo python3 basic_firewall.py
"""

import sys

from scapy.all import IP, IPv6, TCP, UDP

from config import ALLOWLISTED_IPS, BLOCKED_IPS, BLOCKED_PORTS


def parse_packet(raw_bytes):
    """Parse as IPv4 or IPv6 based on the version nibble.

    Calling IP() on an IPv6 packet yields src/dst of 0.0.0.0 and every rule
    silently passes -- which is how IPv6 traffic used to walk straight past
    this firewall.
    """
    if not raw_bytes:
        return None
    version = raw_bytes[0] >> 4
    try:
        if version == 4:
            return IP(bytes(raw_bytes))
        if version == 6:
            return IPv6(bytes(raw_bytes))
    except Exception:
        return None
    return None


def evaluate(packet):
    """Return a block reason, or None to accept."""
    layer = packet[IPv6] if IPv6 in packet else packet[IP]
    src_ip, dst_ip = layer.src, layer.dst

    if src_ip in ALLOWLISTED_IPS or dst_ip in ALLOWLISTED_IPS:
        return None

    if src_ip in BLOCKED_IPS:
        return f"source IP {src_ip} is blacklisted"
    if dst_ip in BLOCKED_IPS:
        return f"destination IP {dst_ip} is blacklisted"

    for proto, name in ((TCP, "TCP"), (UDP, "UDP")):
        if proto in packet:
            sport, dport = packet[proto].sport, packet[proto].dport
            if sport in BLOCKED_PORTS:
                return f"source {name} port {sport} is blacklisted"
            if dport in BLOCKED_PORTS:
                return f"destination {name} port {dport} is blacklisted"
            break

    return None


def packet_handler(pkt):
    """NetfilterQueue callback: inspect, then accept or drop."""
    packet = parse_packet(pkt.get_payload())
    if packet is None:
        # Unparseable traffic is accepted rather than silently dropped, so a
        # protocol this example does not understand cannot break the host.
        pkt.accept()
        return

    reason = evaluate(packet)
    if reason:
        print(f"[DROPPED] {reason}")
        pkt.drop()
    else:
        pkt.accept()


def run_firewall(queue_num=0):
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        print("[-] NetfilterQueue is not installed (Linux only).")
        print("[-] Try: sudo apt install build-essential python3-dev "
              "libnetfilter-queue-dev && pip install NetfilterQueue")
        return 1

    nfqueue = NetfilterQueue()
    bound = False
    try:
        nfqueue.bind(queue_num, packet_handler)
        bound = True
        print(f"[*] Basic firewall listening on NFQUEUE {queue_num}. Ctrl+C to stop.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Firewall stopped by user.")
    except Exception as exc:
        print(f"[!] Error: {exc}")
        print("[!] Ensure you are running as root with the iptables rule loaded.")
        return 1
    finally:
        if bound:
            try:
                nfqueue.unbind()
            except Exception:
                pass
        print("[*] NetfilterQueue unbound.")

    return 0


if __name__ == "__main__":
    sys.exit(run_firewall())
