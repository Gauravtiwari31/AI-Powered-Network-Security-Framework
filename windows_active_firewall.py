# Author: Gaurav Tiwari
import sys
import os
import time

try:
    import pydivert
except ImportError:
    print("[-] pydivert is not installed. Please run: pip install pydivert")
    sys.exit(1)

# We still use scapy to parse the raw IP packets for our DPI and ML logic
try:
    from scapy.all import IP, TCP, UDP, Raw
except ImportError:
    print("[-] Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)

import config
import joblib
import numpy as np
import pandas as pd

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

def should_block_packet(raw_bytes):
    try:
        scapy_packet = IP(raw_bytes)
    except Exception:
        return False, "" # If we can't parse it, let it through

    if not scapy_packet.haslayer(IP):
        return False, ""

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

    # Phase 1: Rule-Based filtering
    if src_ip in config.BLOCKED_IPS:
        return True, f"[RULE] Source IP blacklisted: {src_ip} -> {dst_ip}"
    if dst_ip in config.BLOCKED_IPS:
        return True, f"[RULE] Destination IP blacklisted: {src_ip} -> {dst_ip}"
    if (src_port in config.BLOCKED_PORTS) or (dst_port in config.BLOCKED_PORTS):
        return True, f"[RULE] Port blacklisted: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto_name})"

    # Phase 2: DPI Regex Matching
    if scapy_packet.haslayer(Raw):
        payload_bytes = scapy_packet[Raw].load
        try:
            decoded_payload = payload_bytes.decode('utf-8', errors='ignore')
            for pattern in config.MALICIOUS_REGEX_PATTERNS:
                if pattern.search(decoded_payload):
                    return True, f"[DPI] Malicious regex pattern '{pattern.pattern}' detected"
        except Exception:
            pass

    # Phase 3: Machine Learning Model Prediction
    if RF_MODEL and LR_MODEL and SCALER:
        try:
            features_array = extract_ml_features(scapy_packet)
            rf_pred = RF_MODEL.predict(features_array)[0]
            lr_pred = LR_MODEL.predict(SCALER.transform(features_array))[0]
            
            if rf_pred == 1 or lr_pred == 1:
                return True, f"[ML] AI classified MALICIOUS (RF={rf_pred}, LR={lr_pred})"
        except Exception:
            pass

    return False, ""

def start_active_firewall():
    print("\n" + "="*60)
    print("      AI-Enhanced Firewall (Windows Active Prevention Mode)")
    print("="*60)
    
    load_ml_models()
    
    # WinDivert filter: intercept outbound and inbound IP traffic
    # Filter 'ip' grabs IPv4 traffic.
    divert_filter = "ip" 
    
    print(f"[*] Starting WinDivert engine on Windows... (Press Ctrl+C to stop)")
    print(f"[*] Intercepting all IP traffic for real-time blocking.")
    print("="*60 + "\n")
    
    try:
        with pydivert.WinDivert(divert_filter) as w:
            for packet in w:
                # Get the raw bytes of the packet
                raw_bytes = packet.raw
                
                # Check if we should block it
                block, reason = should_block_packet(raw_bytes)
                
                if block:
                    # By NOT sending the packet back to WinDivert, we effectively DROP it.
                    print(f"🚨 [DROPPED] {reason}")
                else:
                    # Allow packet through
                    w.send(packet)
                    
    except KeyboardInterrupt:
        print("\n[*] Firewall stopped by user. Traffic is flowing normally again.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        print("[!] Ensure you are running this Command Prompt/PowerShell as Administrator.")

if __name__ == "__main__":
    start_active_firewall()
