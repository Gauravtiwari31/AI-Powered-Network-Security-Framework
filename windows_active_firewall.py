# windows_active_firewall.py
# Author: Gaurav Tiwari
"""Windows active-prevention front-end (WinDivert).

Intercepts packets from the Windows network stack via pydivert and drops
anything `detection_engine` flags. All detection logic lives in
`detection_engine.py` so this file stays a thin transport shim.

Run from an **Administrator** PowerShell / Command Prompt:

    python windows_active_firewall.py            # enforce
    python windows_active_firewall.py --monitor  # log only, drop nothing
"""

import argparse
import logging
import signal
import sys
import time

import config
from detection_engine import DetectionEngine

log = logging.getLogger("firewall")

_running = True


def _handle_sigint(signum, frame):
    global _running
    _running = False


def setup_logging(verbose=False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("firewall.log", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Keep the console readable; the file keeps everything.
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(logging.WARNING if not verbose else logging.DEBUG)


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


def start_active_firewall(monitor_only=False, divert_filter="ip or ipv6", verbose=False):
    setup_logging(verbose)

    try:
        import pydivert
    except ImportError:
        print("[-] pydivert is not installed. Run: pip install pydivert")
        print("[-] pydivert requires Windows and Administrator privileges.")
        return 1

    mode = "MONITOR (nothing will be dropped)" if monitor_only else "ACTIVE PREVENTION"
    print("\n" + "=" * 62)
    print("      AI-Powered Network Security Framework - Windows Engine")
    print("=" * 62)
    print(f"  Mode          : {mode}")
    print(f"  WinDivert     : {divert_filter}")
    print(f"  Block at      : threat score >= {config.BLOCK_THRESHOLD}")
    print(f"  ML layer      : {'enforcing' if config.ML_ENFORCE else 'monitor-only'}")
    print(f"  On error      : fail-{config.FAILURE_MODE}")
    print("  Ctrl+C to stop")
    print("=" * 62 + "\n")

    engine = DetectionEngine()
    if not engine.ml_enabled:
        print("[!] ML layer disabled (see firewall.log). Rules, DPI and "
              "heuristics remain active.\n")

    signal.signal(signal.SIGINT, _handle_sigint)
    started = time.time()
    last_prune = started

    try:
        with pydivert.WinDivert(divert_filter) as w:
            for packet in w:
                if not _running:
                    break

                verdict = engine.inspect(packet.raw)

                if verdict.block and not monitor_only:
                    # Not re-injecting the packet is what drops it.
                    print(f"[DROPPED] {verdict.summary}")
                    log.warning("DROPPED %s", verdict.summary)
                    continue

                if verdict.block:
                    print(f"[WOULD DROP] {verdict.summary}")
                    log.warning("WOULD DROP %s", verdict.summary)

                w.send(packet)

                now = time.time()
                if now - last_prune > 30:
                    engine.behaviour.prune(now)
                    last_prune = now

    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log.critical("Fatal error in capture loop: %s", exc, exc_info=True)
        print(f"\n[!] Error: {exc}")
        print("[!] Ensure this PowerShell / Command Prompt is running as Administrator.")
        return 1
    finally:
        print("\n[*] Firewall stopped. Traffic is flowing normally again.")
        print_stats(engine, started)

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Network Security Framework (Windows/WinDivert)")
    parser.add_argument("--monitor", action="store_true",
                        help="inspect and log but never drop packets")
    parser.add_argument("--filter", default="ip or ipv6",
                        help="WinDivert filter expression (default: 'ip or ipv6')")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="debug-level console logging")
    args = parser.parse_args()
    return start_active_firewall(args.monitor, args.filter, args.verbose)


if __name__ == "__main__":
    sys.exit(main())
