# Author: Gaurav Tiwari

import logging
import os
import re
import hashlib
import time
import joblib
import numpy as np
import pandas as pd
import math

# --- Configuration ---
from config import (
    BLOCKED_IPS,
    BLOCKED_PORTS,
    MALICIOUS_REGEX_PATTERNS,
    KNOWN_MALICIOUS_JA3_HASHES,
    FRAGMENT_TIMEOUT
)

# --- NetfilterQueue and Scapy Imports ---
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw, IPv6
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS


# --- ML Model Global Variables ---
RF_MODEL = None
LR_MODEL = None
SCALER = None

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


# --- Helper Functions ---

def calculate_ja3_hash(tls_client_hello_layer):
    try:
        tls_version = int(tls_client_hello_layer.version) if hasattr(
            tls_client_hello_layer, 'version') else 0
        ciphers = sorted([int(c) for c in tls_client_hello_layer.ciphers]) if hasattr(
            tls_client_hello_layer, 'ciphers') and tls_client_hello_layer.ciphers else []
        extensions_types = []
        elliptic_curves = []
        elliptic_curve_point_formats = []

        if hasattr(tls_client_hello_layer, 'ext') and tls_client_hello_layer.ext:
            for ext in tls_client_hello_layer.ext:
                if hasattr(ext, 'type'):
                    extensions_types.append(int(ext.type))
                if ext.type == 10 and hasattr(ext, 'groups'):
                    elliptic_curves = sorted([int(g) for g in ext.groups])
                elif ext.type == 11 and hasattr(ext, 'ecpl'):
                    elliptic_curve_point_formats = sorted(
                        [int(p) for p in ext.ecpl])

        extensions_types = sorted(list(set(extensions_types)))

        ja3_str = []
        ja3_str.append(str(tls_version))
        ja3_str.append("-".join(str(c) for c in ciphers))
        ja3_str.append("-".join(str(t) for t in extensions_types))
        ja3_str.append("-".join(str(ec) for ec in elliptic_curves))
        ja3_str.append("-".join(str(ecpf)
                       for ecpf in elliptic_curve_point_formats))

        final_ja3_string = ",".join(ja3_str)
        ja3_hash = hashlib.md5(final_ja3_string.encode('ascii')).hexdigest()
        return ja3_hash
    except Exception as e:
        return None


def calculate_entropy(data):
    if not data:
        return 0.0
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    entropy = 0
    data_len = len(data)
    for freq in frequencies.values():
        p = float(freq) / data_len
        entropy -= p * math.log2(p)
    return entropy


def load_ml_models():
    """Loads the trained ML models and scaler from disk."""
    global RF_MODEL, LR_MODEL, SCALER
    MODEL_DIR = './trained_models'
    try:
        RF_MODEL = joblib.load(os.path.join(
            MODEL_DIR, 'random_forest_model.pkl'))
        LR_MODEL = joblib.load(os.path.join(
            MODEL_DIR, 'logistic_regression_model.pkl'))
        SCALER = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
        logging.info("ML models and scaler loaded successfully.")
    except Exception as e:
        logging.error(
            f"Error loading ML models: {e}. ML detection will be disabled.")
        RF_MODEL = None
        LR_MODEL = None
        SCALER = None


def extract_ml_features(scapy_packet):
    """
    Extracts numerical features from a Scapy packet, matching the format
    expected by the trained ML models.
    """
    features_dict = {col: 0.0 for col in ML_FEATURE_COLUMNS}

    if IP in scapy_packet:
        features_dict['Protocol'] = scapy_packet[IP].proto
        features_dict['Fwd Header Len'] = scapy_packet[IP].ihl * 4
        features_dict['Pkt Len Min'] = scapy_packet[IP].len
        features_dict['Pkt Len Max'] = scapy_packet[IP].len
        features_dict['Pkt Len Mean'] = scapy_packet[IP].len
        features_dict['Fwd Pkt Len Max'] = scapy_packet[IP].len
        features_dict['Fwd Pkt Len Min'] = scapy_packet[IP].len
        features_dict['Fwd Pkt Len Mean'] = scapy_packet[IP].len

        features_dict['Tot Fwd Pkts'] = 1.0
        features_dict['TotLen Fwd Pkts'] = scapy_packet[IP].len
        features_dict['Pkt Size Avg'] = scapy_packet[IP].len

        features_dict['Flow Duration'] = 0.0
        features_dict['Flow IAT Mean'] = 0.0
        features_dict['Flow IAT Std'] = 0.0
        features_dict['Flow IAT Max'] = 0.0
        features_dict['Flow IAT Min'] = 0.0
        features_dict['Fwd IAT Tot'] = 0.0
        features_dict['Fwd IAT Mean'] = 0.0
        features_dict['Fwd IAT Std'] = 0.0
        features_dict['Fwd IAT Max'] = 0.0
        features_dict['Fwd IAT Min'] = 0.0
        features_dict['Bwd IAT Tot'] = 0.0
        features_dict['Bwd IAT Mean'] = 0.0
        features_dict['Bwd IAT Std'] = 0.0
        features_dict['Bwd IAT Max'] = 0.0
        features_dict['Bwd IAT Min'] = 0.0
        features_dict['Bwd Header Len'] = 0.0
        features_dict['Tot Bwd Pkts'] = 0.0
        features_dict['TotLen Bwd Pkts'] = 0.0
        features_dict['Bwd Pkt Len Max'] = 0.0
        features_dict['Bwd Pkt Len Min'] = 0.0
        features_dict['Bwd Pkt Len Mean'] = 0.0
        features_dict['Bwd Pkt Len Std'] = 0.0
        features_dict['Down/Up Ratio'] = 0.0
        features_dict['Fwd Byts/b Avg'] = 0.0
        features_dict['Fwd Pkts/b Avg'] = 0.0
        features_dict['Fwd Blk Rate Avg'] = 0.0
        features_dict['Bwd Byts/b Avg'] = 0.0
        features_dict['Bwd Pkts/b Avg'] = 0.0
        features_dict['Bwd Blk Rate Avg'] = 0.0
        features_dict['Init Bwd Win Byts'] = 0.0
        features_dict['Active Mean'] = 0.0
        features_dict['Active Std'] = 0.0
        features_dict['Active Max'] = 0.0
        features_dict['Active Min'] = 0.0
        features_dict['Idle Mean'] = 0.0
        features_dict['Idle Std'] = 0.0
        features_dict['Idle Max'] = 0.0
        features_dict['Idle Min'] = 0.0
        features_dict['Fwd Pkt Len Std'] = 0.0
        features_dict['Pkt Len Std'] = 0.0
        features_dict['Pkt Len Var'] = 0.0
        features_dict['Fwd Seg Size Avg'] = 0.0
        features_dict['Bwd Seg Size Avg'] = 0.0
        features_dict['Fwd Act Data Pkts'] = 0.0
        features_dict['Fwd Seg Size Min'] = 0.0

    if TCP in scapy_packet:
        features_dict['Dst Port'] = scapy_packet[TCP].dport
        features_dict['FIN Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.F else 0.0
        features_dict['SYN Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.S else 0.0
        features_dict['RST Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.R else 0.0
        features_dict['PSH Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.P else 0.0
        features_dict['ACK Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.A else 0.0
        features_dict['URG Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.U else 0.0
        features_dict['CWE Flag Count'] = 1.0 if scapy_packet[TCP].flags.C else 0.0
        features_dict['ECE Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.E else 0.0
        features_dict['Init Fwd Win Byts'] = scapy_packet[TCP].window
        if scapy_packet[TCP].payload:
            features_dict['Fwd Act Data Pkts'] = 1.0
            features_dict['Fwd Seg Size Min'] = len(scapy_packet[TCP].payload)
            features_dict['Pkt Size Avg'] = len(scapy_packet[IP])

    elif UDP in scapy_packet:
        features_dict['Dst Port'] = scapy_packet[UDP].dport
        if scapy_packet[UDP].payload:
            features_dict['Fwd Act Data Pkts'] = 1.0
            features_dict['Fwd Seg Size Min'] = len(scapy_packet[UDP].payload)
            features_dict['Pkt Size Avg'] = len(scapy_packet[IP])

    for key in features_dict:
        features_dict[key] = float(features_dict[key])

    features_series = pd.Series(
        features_dict, index=ML_FEATURE_COLUMNS, dtype=float)

    features_series.replace([np.inf, -np.inf], np.nan, inplace=True)
    features_series.fillna(0.0, inplace=True)

    return features_series.values.reshape(1, -1)


# --- Packet Handling Function ---
def packet_handler(pkt):
    current_time = time.time()
    try:
        scapy_packet = IP(pkt.get_payload())
    except Exception as e:
        logging.error(
            f"Error parsing packet payload with Scapy: {e}. Accepting packet.")
        pkt.accept()
        return

    # --- Fragmentation Handling ---
    if scapy_packet.flags & 0x1 or scapy_packet.frag != 0:
        keys_to_remove = [k for k, v in FRAGMENT_BUFFER.items(
        ) if current_time - v['timestamp'] > FRAGMENT_TIMEOUT]
        for k in keys_to_remove:
            del FRAGMENT_BUFFER[k]

        frag_key = (scapy_packet[IP].src,
                    scapy_packet[IP].dst, scapy_packet.id)
        if frag_key not in FRAGMENT_BUFFER:
            FRAGMENT_BUFFER[frag_key] = {
                'fragments': [], 'timestamp': current_time}

        FRAGMENT_BUFFER[frag_key]['fragments'].append(scapy_packet)
        FRAGMENT_BUFFER[frag_key]['timestamp'] = current_time

        if scapy_packet.frag == 0:
            if scapy_packet.len < 28:
                logging.info(
                    f"BLOCKING (Fragmentation): Detected tiny first fragment (len={scapy_packet.len}) for ID {scapy_packet.id}.")
                print(f"--- Packet Blocked by Fragmentation ({pkt.id}) ---")
                scapy_packet.show()
                pkt.drop()
                del FRAGMENT_BUFFER[frag_key]
                return

        pkt.accept()
        return

    src_ip = scapy_packet[IP].src if IP in scapy_packet else "N/A"
    dst_ip = scapy_packet[IP].dst if IP in scapy_packet else "N/A"
    proto_num = scapy_packet[IP].proto if IP in scapy_packet else "N/A"

    src_port = None
    dst_port = None
    proto_name = "N/A"

    if TCP in scapy_packet:
        src_port = scapy_packet[TCP].sport
        dst_port = scapy_packet[TCP].dport
        proto_name = "TCP"
    elif UDP in scapy_packet:
        src_port = scapy_packet[UDP].sport
        dst_port = scapy_packet[UDP].dport
        proto_name = "UDP"

    payload_bytes = b""
    if scapy_packet.haslayer(Raw):
        payload_bytes = scapy_packet[Raw].load

    # --- Phase 1: Basic IP and Port Filtering ---
    is_blocked_by_rule = False
    block_reason = ""

    if src_ip in BLOCKED_IPS:
        block_reason = f"IP: Source IP {src_ip} -> {dst_ip} is on the blacklist."
        is_blocked_by_rule = True
    elif dst_ip in BLOCKED_IPS:
        block_reason = f"IP: Destination IP {src_ip} -> {dst_ip} is on the blacklist."
        is_blocked_by_rule = True
    elif src_port in BLOCKED_PORTS and (proto_name == "TCP" or proto_name == "UDP"):
        block_reason = f"Port: Source {proto_name} Port {src_port} -> {dst_port} is on the blacklist."
        is_blocked_by_rule = True
    elif dst_port in BLOCKED_PORTS and (proto_name == "TCP" or proto_name == "UDP"):
        block_reason = f"Port: Destination {proto_name} Port {src_port} -> {dst_port} is on the blacklist."
        is_blocked_by_rule = True

    if is_blocked_by_rule:
        logging.info(f"BLOCKING ({block_reason})")
        print(f"--- Packet Blocked by Rule ({pkt.id}) ---")
        scapy_packet.show()
        pkt.drop()
        return

    # --- Phase 2: DPI - Aggressive Pattern Matching (Regex) ---
    if payload_bytes:
        try:
            decoded_payload = payload_bytes.decode('utf-8', errors='ignore')
            for pattern in MALICIOUS_REGEX_PATTERNS:
                if pattern.search(decoded_payload):
                    logging.info(
                        f"BLOCKING (DPI-Regex): Malicious pattern '{pattern.pattern}' detected in payload.")
                    print(f"--- Packet Blocked by DPI-Regex ({pkt.id}) ---")
                    scapy_packet.show()
                    pkt.drop()
                    return
        except Exception as e:
            logging.error(
                f"Error decoding payload for regex search: {e}. Accepting packet.")

    # --- Phase 2: DPI - Basic HTTP Payload Parsing ---
    if proto_name == "TCP" and (dst_port == 80 or src_port == 80):
        try:
            http_data = payload_bytes.decode('utf-8', errors='ignore')
            if http_data.startswith("GET ") or http_data.startswith("POST ") or \
               http_data.startswith("HTTP/"):
                if "User-Agent: Nikto" in http_data:
                    logging.info(
                        "BLOCKING (DPI-HTTP): Detected Nikto User-Agent.")
                    print(f"--- Packet Blocked by DPI-HTTP ({pkt.id}) ---")
                    scapy_packet.show()
                    pkt.drop()
                    return
                if "/admin/login.php?user=" in http_data and "password=" in http_data:
                    logging.info(
                        "BLOCKING (DPI-HTTP): Suspicious login attempt pattern.")
                    print(f"--- Packet Blocked by DPI-HTTP ({pkt.id}) ---")
                    scapy_packet.show()
                    pkt.drop()
                    return
        except Exception as e:
            logging.error(
                f"Error parsing HTTP payload: {e}. Accepting packet.")

    # --- Phase 2: DPI - JA3 TLS Fingerprinting ---
    if TLSClientHello in scapy_packet:
        try:
            ja3_hash = calculate_ja3_hash(scapy_packet[TLSClientHello])
            if ja3_hash:
                if ja3_hash in KNOWN_MALICIOUS_JA3_HASHES:
                    logging.info(
                        f"BLOCKING (JA3): Detected known malicious JA3 hash: {ja3_hash}")
                    print(f"--- Packet Blocked by JA3 ({pkt.id}) ---")
                    scapy_packet.show()
                    pkt.drop()
                    return
        except Exception as e:
            logging.error(f"Error in JA3 processing: {e}. Accepting packet.")

    # --- Phase 3: AI/ML Model Prediction ---
    ml_prediction_decision = False
    if RF_MODEL and LR_MODEL and SCALER:
        try:
            features_array = extract_ml_features(scapy_packet)

            rf_pred = RF_MODEL.predict(features_array)[0]
            lr_pred = LR_MODEL.predict(SCALER.transform(features_array))[0]

            rf_pred_label = "MALICIOUS" if rf_pred == 1 else "BENIGN"
            lr_pred_label = "MALICIOUS" if lr_pred == 1 else "BENIGN"

            logging.info(
                f"ML Prediction: RF={rf_pred_label}, LR={lr_pred_label} for packet {pkt.id} from {src_ip}:{src_port} to {dst_ip}:{dst_port}.")

            if rf_pred == 1 or lr_pred == 1:
                ml_prediction_decision = True
                logging.info(
                    f"BLOCKING (ML): RF={rf_pred_label}, LR={lr_pred_label}")
                print(f"--- Packet Blocked by ML ({pkt.id}) ---")
                scapy_packet.show()
                pkt.drop()
                return

        except Exception as e:
            logging.error(
                f"Error during ML prediction: {e}. Accepting packet.")

    pkt.accept()


# --- Main Firewall Execution Logic ---
def run_firewall():
    logging.basicConfig(filename='firewall.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info(
        "Firewall logging initialized. Logging all events to firewall.log")
    print("[*] Console will show only critical BLOCKING events. See firewall.log for all details.")

    from scapy.all import load_layer
    try:
        load_layer("tls")
        logging.info("Scapy TLS layer loaded successfully for JA3.")
    except Exception as e:
        logging.error(
            f"Warning: Could not load Scapy TLS layer: {e}. TLS/JA3 features might not work correctly.")

    load_ml_models()

    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(0, packet_handler)
        print("[*] AI-Enhanced DPI Firewall started, listening on NetfilterQueue 0...")
        print(
            "[*] Ensure iptables rules are set: sudo iptables -A INPUT -j NFQUEUE --queue-num 0")
        print(
            "[*]                                sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0")
        print("[*] Press Ctrl+C to stop.")
        logging.info("AI-Enhanced DPI Firewall is now active.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] AI-Enhanced DPI Firewall stopped by user.")
        logging.info("AI-Enhanced DPI Firewall stopped by user.")
    except Exception as e:
        print(f"An error occurred in main firewall loop: {e}")
        logging.critical(
            f"Critical error in main firewall loop: {e}", exc_info=True)
    finally:
        nfqueue.unbind()
        print("[*] NetfilterQueue unbound.")
        logging.info("NetfilterQueue unbound. Firewall shut down cleanly.")


if __name__ == "__main__":
    run_firewall()
