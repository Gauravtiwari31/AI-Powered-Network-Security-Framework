# test_windows.py
import time
import os
import sys
import hashlib
import math
import joblib
import numpy as np
import pandas as pd

# Windows compatibility check for Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
except ImportError:
    print("[-] Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)

# Import firewall configurations
try:
    import config
except ImportError as e:
    print(f"[-] Failed to import config.py: {e}")
    sys.exit(1)

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

def load_ml_models():
    """Loads the trained ML models and scaler from disk."""
    global RF_MODEL, LR_MODEL, SCALER
    MODEL_DIR = './trained_models'
    try:
        RF_MODEL = joblib.load(os.path.join(MODEL_DIR, 'random_forest_model.pkl'))
        LR_MODEL = joblib.load(os.path.join(MODEL_DIR, 'logistic_regression_model.pkl'))
        SCALER = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
        print("[*] ML models and scaler loaded successfully.")
    except Exception as e:
        print(f"[-] Error loading ML models: {e}. ML detection will be disabled.")
        RF_MODEL = None
        LR_MODEL = None
        SCALER = None

def extract_ml_features(scapy_packet):
    """Extracts features from Scapy packet for model prediction."""
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

    features_series = pd.Series(features_dict, index=ML_FEATURE_COLUMNS, dtype=float)
    features_series.replace([np.inf, -np.inf], np.nan, inplace=True)
    features_series.fillna(0.0, inplace=True)
    return features_series.values.reshape(1, -1)

def analyze_packet(scapy_packet):
    if not scapy_packet.haslayer(IP):
        return

    src_ip = scapy_packet[IP].src
    dst_ip = scapy_packet[IP].dst
    proto_name = "TCP" if scapy_packet.haslayer(TCP) else "UDP" if scapy_packet.haslayer(UDP) else "Other"

    src_port = None
    dst_port = None
    if scapy_packet.haslayer(TCP):
        src_port = scapy_packet[TCP].sport
        dst_port = scapy_packet[TCP].dport
    elif scapy_packet.haslayer(UDP):
        src_port = scapy_packet[UDP].sport
        dst_port = scapy_packet[UDP].dport

    # --- Phase 1: Rule-Based IP and Port Filtering ---
    if src_ip in config.BLOCKED_IPS:
        print(f"🚨 [RULE BLOCK] Source IP is blacklisted: {src_ip} -> {dst_ip}")
        return
    if dst_ip in config.BLOCKED_IPS:
        print(f"🚨 [RULE BLOCK] Destination IP is blacklisted: {src_ip} -> {dst_ip}")
        return

    if (src_port in config.BLOCKED_PORTS) or (dst_port in config.BLOCKED_PORTS):
        print(f"🚨 [RULE BLOCK] Port on blacklist: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto_name})")
        return

    # --- Phase 2: DPI (Deep Packet Inspection) - Regex Matching ---
    if scapy_packet.haslayer(Raw):
        payload_bytes = scapy_packet[Raw].load
        try:
            decoded_payload = payload_bytes.decode('utf-8', errors='ignore')
            for pattern in config.MALICIOUS_REGEX_PATTERNS:
                if pattern.search(decoded_payload):
                    print(f"🚨 [DPI BLOCK] Malicious pattern '{pattern.pattern}' detected in payload from {src_ip}")
                    return
        except Exception:
            pass

    # --- Phase 3: Machine Learning Model Prediction ---
    if RF_MODEL and LR_MODEL and SCALER:
        try:
            features_array = extract_ml_features(scapy_packet)
            rf_pred = RF_MODEL.predict(features_array)[0]
            lr_pred = LR_MODEL.predict(SCALER.transform(features_array))[0]
            
            if rf_pred == 1 or lr_pred == 1:
                print(f"🚨 [ML BLOCK] AI classified packet as MALICIOUS (RF={rf_pred}, LR={lr_pred})! {src_ip}:{src_port or ''} -> {dst_ip}:{dst_port or ''}")
                return
        except Exception as e:
            pass

    # Print clean allowed packets
    print(f"✅ [ALLOW] Packet allowed: {src_ip}:{src_port or ''} -> {dst_ip}:{dst_port or ''} ({proto_name})")

def start_sniffer():
    print("\n" + "="*60)
    print("      AI-Enhanced Firewall Demonstration (Windows Sniffer)")
    print("="*60)
    print("[*] Sniffing live network packets... (Press Ctrl+C to stop)")
    print("[*] Try pinging 8.8.8.8 in another command prompt to trigger a Rule Block.")
    print("="*60 + "\n")
    
    # Load ML models before starting
    load_ml_models()
    
    try:
        sniff(prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
    except Exception as e:
        print(f"\n[!] An error occurred during sniffing: {e}")
        print("[!] Ensure you are running this Command Prompt/PowerShell as Administrator.")

if __name__ == "__main__":
    start_sniffer()
