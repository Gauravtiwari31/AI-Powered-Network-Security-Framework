# demo_sniffer.py
# Author: Gaurav Tiwari
"""Passive demonstration mode -- observe and classify, never block.

This is the safe way to see the engine work: it sniffs live traffic with
Scapy and prints what each detection layer would have decided, without
touching a single packet. Nothing is dropped, so it needs no WinDivert
driver and no iptables rules -- only permission to capture.

    python demo_sniffer.py                 # all traffic
    python demo_sniffer.py --filter "tcp"  # BPF filter
    python demo_sniffer.py --quiet         # only show detections

On Windows, capture requires Npcap and an Administrator prompt. On Linux,
run with sudo or grant CAP_NET_RAW.
"""

import argparse
import logging
import sys
import time

import config

try:
    from scapy.all import sniff
except ImportError:
    print("[-] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

from detection_engine import DetectionEngine

logging.basicConfig(level=logging.WARNING,
                    format="%(asctime)s - %(levelname)s - %(message)s")


def build_callback(engine, quiet):
    def on_packet(scapy_packet):
        # Strip the link layer; the engine works on the IP packet.
        from scapy.all import IP, IPv6
        if IP in scapy_packet:
            raw = bytes(scapy_packet[IP])
        elif IPv6 in scapy_packet:
            raw = bytes(scapy_packet[IPv6])
        else:
            return

        verdict = engine.inspect(raw)

        if verdict.block:
            print(f"[WOULD BLOCK] {verdict.summary}")
            for layer, detail, score in verdict.reasons:
                print(f"              - {layer}: {detail} (+{score})")
        elif not quiet:
            if verdict.reasons:
                print(f"[allow] {verdict.summary}")
            else:
                print(f"[allow] {len(raw)}B packet")

    return on_packet


def main():
    parser = argparse.ArgumentParser(
        description="Passive demonstration sniffer -- classifies, never blocks")
    parser.add_argument("--filter", default=None, help="BPF capture filter")
    parser.add_argument("--count", type=int, default=0,
                        help="stop after N packets (0 = unlimited)")
    parser.add_argument("--quiet", action="store_true",
                        help="print detections only")
    args = parser.parse_args()

    print("\n" + "=" * 62)
    print("      AI-Powered Network Security Framework - Demo Sniffer")
    print("=" * 62)
    print("  PASSIVE MODE - packets are classified, never dropped")
    print(f"  Block threshold : score >= {config.BLOCK_THRESHOLD}")
    print(f"  BPF filter      : {args.filter or 'none'}")
    print("  Try `ping 8.8.8.8` in another terminal to trigger a rule hit.")
    print("  Ctrl+C to stop")
    print("=" * 62 + "\n")

    engine = DetectionEngine()
    if not engine.ml_enabled:
        print("[!] ML layer disabled. Rules, DPI and heuristics remain active.\n")

    started = time.time()
    try:
        sniff(prn=build_callback(engine, args.quiet), store=0,
              filter=args.filter, count=args.count)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Permission denied. Run as Administrator (Windows, with "
              "Npcap installed) or with sudo (Linux).")
        return 1
    except Exception as exc:
        print(f"\n[!] Capture error: {exc}")
        print("[!] On Windows this usually means Npcap is missing or you are "
              "not running as Administrator.")
        return 1

    elapsed = max(time.time() - started, 1e-6)
    s = engine.stats
    print(f"\n[*] Stopped. Inspected {s['inspected']} packets in {elapsed:.1f}s, "
          f"{s['blocked']} would have been blocked, {s['errors']} errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
