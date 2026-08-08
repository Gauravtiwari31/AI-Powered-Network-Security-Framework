# dpi_firewall.py
# Author: Gaurav Tiwari
"""Linux front-end (NetfilterQueue).

Packets are redirected into userspace by iptables/ip6tables and each one is
handed to `detection_engine`, which is shared verbatim with the Windows
engine. This file only moves bytes and applies the accept/drop decision.

    sudo iptables  -I INPUT  -j NFQUEUE --queue-num 0
    sudo iptables  -I OUTPUT -j NFQUEUE --queue-num 0
    sudo ip6tables -I INPUT  -j NFQUEUE --queue-num 0
    sudo ip6tables -I OUTPUT -j NFQUEUE --queue-num 0
    sudo python3 dpi_firewall.py

Tear the rules down again with `iptables -D` / `ip6tables -D` (same arguments)
or `sudo iptables -F` once you are finished.
"""

import argparse
import logging
import sys
import time

import config
from detection_engine import DetectionEngine

log = logging.getLogger("firewall")


def setup_logging(verbose=False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("firewall.log", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(logging.WARNING if not verbose else logging.DEBUG)


def build_handler(engine, monitor_only):
    """Return the NetfilterQueue callback bound to this engine."""

    def packet_handler(pkt):
        try:
            verdict = engine.inspect(pkt.get_payload())
        except Exception as exc:
            # inspect() already swallows its own errors; this only catches a
            # failure to read the payload out of the queue itself.
            log.error("Queue read failed: %s", exc, exc_info=True)
            pkt.accept()
            return

        if verdict.block and not monitor_only:
            print(f"[DROPPED] {verdict.summary}")
            log.warning("DROPPED %s", verdict.summary)
            pkt.drop()
            return

        if verdict.block:
            print(f"[WOULD DROP] {verdict.summary}")
            log.warning("WOULD DROP %s", verdict.summary)

        pkt.accept()

    return packet_handler


def print_stats(engine, started):
    elapsed = max(time.time() - started, 1e-6)
    s = engine.stats
    print("\n" + "=" * 62)
    print("  Session summary")
    print("=" * 62)
    print(f"  Runtime            : {elapsed:.1f}s")
    print(f"  Packets inspected  : {s['inspected']} ({s['inspected'] / elapsed:.0f}/s)")
    print(f"  Allowed            : {s['allowed']}")
    print(f"  Blocked            : {s['blocked']}")
    print(f"  Engine errors      : {s['errors']}")
    print(f"  ML evaluations     : {s['ml_evaluated']} (flagged {s['ml_flagged']})")
    print(f"  Flows tracked      : {len(engine.flows)} (evicted {engine.flows.evictions})")
    print("=" * 62)


def run_firewall(queue_num=0, monitor_only=False, verbose=False):
    setup_logging(verbose)

    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        print("[-] NetfilterQueue is not installed (Linux only).")
        print("[-] Try: sudo apt install build-essential python3-dev "
              "libnetfilter-queue-dev && pip install NetfilterQueue")
        return 1

    mode = "MONITOR (nothing will be dropped)" if monitor_only else "ACTIVE PREVENTION"
    print("\n" + "=" * 62)
    print("      AI-Powered Network Security Framework - Linux Engine")
    print("=" * 62)
    print(f"  Mode          : {mode}")
    print(f"  NFQUEUE       : {queue_num}")
    print(f"  Block at      : threat score >= {config.BLOCK_THRESHOLD}")
    print(f"  ML layer      : {'enforcing' if config.ML_ENFORCE else 'monitor-only'}")
    print(f"  On error      : fail-{config.FAILURE_MODE}")
    print("  Ctrl+C to stop")
    print("=" * 62 + "\n")

    engine = DetectionEngine()
    if not engine.ml_enabled:
        print("[!] ML layer disabled (see firewall.log). Rules, DPI and "
              "heuristics remain active.\n")

    nfqueue = NetfilterQueue()
    started = time.time()
    bound = False
    try:
        nfqueue.bind(queue_num, build_handler(engine, monitor_only))
        bound = True
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Firewall stopped by user.")
    except Exception as exc:
        log.critical("Fatal error in capture loop: %s", exc, exc_info=True)
        print(f"\n[!] Error: {exc}")
        print("[!] Ensure you are running as root and the iptables NFQUEUE "
              "rules are loaded.")
        return 1
    finally:
        # unbind() on a queue that never bound raises and masks the real error.
        if bound:
            try:
                nfqueue.unbind()
            except Exception:
                pass
        print_stats(engine, started)
        print("[*] Remember to remove your iptables NFQUEUE rules.")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Network Security Framework (Linux/NetfilterQueue)")
    parser.add_argument("--queue-num", type=int, default=0,
                        help="NFQUEUE number, must match your iptables rule")
    parser.add_argument("--monitor", action="store_true",
                        help="inspect and log but never drop packets")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="debug-level console logging")
    args = parser.parse_args()
    return run_firewall(args.queue_num, args.monitor, args.verbose)


if __name__ == "__main__":
    sys.exit(main())
