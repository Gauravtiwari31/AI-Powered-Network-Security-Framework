from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw, IPv6  # IPv6 is imported for future use

# --- Configuration: Define your blocking rules here ---

BLOCKED_IPS = [
    "8.8.8.8",         # Example: Google Public DNS
    "192.168.1.100"    # Example: A specific internal IP
]

# Ports to block (source OR destination for TCP/UDP)
BLOCKED_PORTS = [
    22,    # SSH
    23,    # Telnet
    8080   # Common proxy/web server port
]

# --- Packet Handling Function ---


def packet_handler(pkt):
    """
    This function is called for every packet redirected to our NetfilterQueue.
    It inspects the packet and decides whether to accept or drop it.
    """

    # Get the raw payload from NetfilterQueue and convert to a Scapy packet
    # We assume IPv4 for now; more robust handling for IPv6 can be added later.
    try:
        scapy_packet = IP(pkt.get_payload())
    except Exception as e:
        print(f"[-] Could not parse packet payload with Scapy: {e}")
        pkt.accept()  # Accept if cannot parse, to avoid blocking legitimate traffic
        return

    print(f"\n--- New Packet ({pkt.id}) ---")
    scapy_packet.show()  # Show a detailed view of the packet

    # 1. Basic IP Filtering
    if IP in scapy_packet:
        src_ip = scapy_packet[IP].src
        dst_ip = scapy_packet[IP].dst

        if src_ip in BLOCKED_IPS:
            print(f"BLOCKING: Source IP {src_ip} is on the blacklist.")
            pkt.drop()  # Drop the packet
            return
        if dst_ip in BLOCKED_IPS:
            print(f"BLOCKING: Destination IP {dst_ip} is on the blacklist.")
            pkt.drop()  # Drop the packet
            return

    # 2. Basic Port Filtering (for TCP and UDP)
    if TCP in scapy_packet:
        src_port = scapy_packet[TCP].sport
        dst_port = scapy_packet[TCP].dport
        if src_port in BLOCKED_PORTS:
            print(f"BLOCKING: Source TCP Port {src_port} is on the blacklist.")
            pkt.drop()
            return
        if dst_port in BLOCKED_PORTS:
            print(
                f"BLOCKING: Destination TCP Port {dst_port} is on the blacklist.")
            pkt.drop()
            return
    elif UDP in scapy_packet:
        src_port = scapy_packet[UDP].sport
        dst_port = scapy_packet[UDP].dport
        if src_port in BLOCKED_PORTS:
            print(f"BLOCKING: Source UDP Port {src_port} is on the blacklist.")
            pkt.drop()
            return
        if dst_port in BLOCKED_PORTS:
            print(
                f"BLOCKING: Destination UDP Port {dst_port} is on the blacklist.")
            pkt.drop()
            return

    # If no blocking rules are matched, accept the packet
    print("ACCEPTING packet.")
    pkt.accept()

# --- Main Firewall Execution Logic ---


def run_firewall():
    """
    Initializes NetfilterQueue and binds the packet_handler function to a queue.
    """
    nfqueue = NetfilterQueue()
    try:
        # Bind to queue 0. This number must match the --queue-num in your iptables rule.
        nfqueue.bind(0, packet_handler)
        print("[*] Firewall started, listening on NetfilterQueue 0...")
        print("[*] Press Ctrl+C to stop.")
        nfqueue.run()  # Start processing packets redirected by iptables
    except KeyboardInterrupt:
        print("\n[*] Firewall stopped by user.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    finally:
        # Clean up the queue binding when the script exits
        nfqueue.unbind()
        print("[*] NetfilterQueue unbound.")


if __name__ == "__main__":
    run_firewall()
