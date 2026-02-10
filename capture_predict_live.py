import os, sqlite3, time, json
from datetime import datetime
from collections import deque

import numpy as np
import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP, Raw, conf, get_if_list, get_if_addr
from colorama import Fore, Style, init
init(autoreset=True)

MODEL_LOCAL = "model_10f_v2.pkl"
MODEL_FALLBACK = "/mnt/data/malware_model.pkl"
MODEL_PATH = MODEL_LOCAL if os.path.exists(MODEL_LOCAL) else MODEL_FALLBACK

DB_PATH = "detections.db"        # SQLite DB (created if missing)
TABLE_NAME = "detections"

FEATURE_NAMES = [
    "feature1_packet_length",
    "feature2_src_port",
    "feature3_dst_port",
    "feature4_protocol_id",
    "feature5_flow_duration",
    "feature6_bytes_in",
    "feature7_bytes_out",
    "feature8_ttl",
    "feature9_entropy",
    "feature10_packet_rate",
]

FLOW_STATE = {}
PACKET_COUNT = {"total": 0, "processed": 0, "skipped": 0, "errors": 0}

# -------- Helpers ----------
def get_network_interfaces():
    """Get list of available network interfaces"""
    try:
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        print(f"[WARN] Could not list interfaces: {e}")
        return []

def get_interface_info(iface):
    """Get IP address for an interface"""
    try:
        addr = get_if_addr(iface)
        return addr if addr else "No IP"
    except:
        return "Unknown"

def select_best_interface():
    """Select the best network interface for capture"""
    interfaces = get_network_interfaces()
    if not interfaces:
        return None
    
    # Prefer interfaces with IP addresses (active interfaces)
    for iface in interfaces:
        addr = get_interface_info(iface)
        if addr and addr != "No IP" and not addr.startswith("127."):
            return iface
    
    # Fallback to default or first available
    if conf.iface:
        return conf.iface
    return interfaces[0] if interfaces else None
def load_model(path=MODEL_PATH):
    print("[INFO] Loading model from:", path)
    model = joblib.load(path)
    print("[INFO] Model loaded.")
    return model

def estimate_entropy(payload_bytes):
    if not payload_bytes:
        return 1.0
    arr = np.frombuffer(payload_bytes, dtype=np.uint8)
    probs = np.bincount(arr, minlength=256) / arr.size
    probs = probs[probs > 0]
    h = -(probs * np.log2(probs)).sum()
    return float(np.clip(h, 1.0, 8.0))

def update_flow(key, t, payload_len):
    dq = FLOW_STATE.get(key)
    if dq is None:
        dq = deque(maxlen=300)
        FLOW_STATE[key] = dq
    dq.append((t, payload_len))

def flow_metrics(key):
    dq = FLOW_STATE.get(key, deque())
    if not dq:
        return 0.0, 0.0
    times = [t for t, b in dq]
    duration = max(times) - min(times) if len(times) > 1 else 0.0
    pkt_rate = len(times) / (duration + 1e-6)
    return float(pkt_rate), float(duration)

def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    # WAL mode for concurrent reader/writer
    conn.execute("PRAGMA journal_mode=WAL;")
    # create table if not exists
    cols = ",\n".join([f"{c} REAL" for c in FEATURE_NAMES])
    sql = f"""
    CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        {cols},
        prediction TEXT,
        confidence REAL
    );
    """
    conn.execute(sql)
    conn.commit()
    return conn

def insert_detection(conn, timestamp, src, dst, features, pred, conf):
    placeholders = ",".join(["?"] * (3 + len(FEATURE_NAMES) + 2))
    sql = f"INSERT INTO {TABLE_NAME} (timestamp, src_ip, dst_ip, {', '.join(FEATURE_NAMES)}, prediction, confidence) VALUES ({placeholders})"
    vals = [timestamp, src, dst] + [features[name] for name in FEATURE_NAMES] + [pred, conf]
    conn.execute(sql, vals)
    conn.commit()

def extract_features(pkt):
    """Extract features from a real network packet"""
    # Only process IP packets (real network traffic)
    if IP not in pkt:
        PACKET_COUNT["skipped"] += 1
        return None, None, None
    
    ts = time.time()
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    ttl = float(pkt[IP].ttl) if hasattr(pkt[IP], "ttl") else 64.0

    sport, dport = 0, 0
    proto = 1.0
    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        proto = 2.0
    elif UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        proto = 3.0

    payload_bytes = b""
    if Raw in pkt:
        try:
            payload_bytes = bytes(pkt[Raw].load)
        except Exception:
            payload_bytes = b""

    pkt_len = len(pkt)
    payload_len = len(payload_bytes)

    key = (src_ip, dst_ip, sport, dport, int(proto))
    update_flow(key, ts, payload_len)
    pkt_rate, flow_dur = flow_metrics(key)

    features = {
        "feature1_packet_length": float(pkt_len),
        "feature2_src_port": float(sport),
        "feature3_dst_port": float(dport),
        "feature4_protocol_id": float(proto),
        "feature5_flow_duration": float(flow_dur),
        "feature6_bytes_in": float(payload_len),
        "feature7_bytes_out": float(payload_len),
        "feature8_ttl": float(ttl),
        "feature9_entropy": float(estimate_entropy(payload_bytes)),
        "feature10_packet_rate": float(pkt_rate),
    }
    PACKET_COUNT["processed"] += 1
    return features, src_ip, dst_ip

def make_handler(model, db_conn):
    def handle(pkt):
        PACKET_COUNT["total"] += 1
        try:
            features, src, dst = extract_features(pkt)
            
            # Skip if not an IP packet
            if features is None:
                return
            
            df = pd.DataFrame([features])
            pred = model.predict(df)[0]
            conf = float(model.predict_proba(df).max())

            ts = datetime.now().isoformat()
            insert_detection(db_conn, ts, src, dst, features, pred, conf)

            # console output - only show every 10th packet or malware detections
            if pred == "malware" or PACKET_COUNT["processed"] % 10 == 0:
                color = Fore.RED + Style.BRIGHT if pred == "malware" else Fore.GREEN + Style.BRIGHT
                stats = f"[Stats: {PACKET_COUNT['processed']} processed, {PACKET_COUNT['skipped']} skipped]"
                print(color + f"[{pred.upper()}] {ts} {src} -> {dst} conf={conf:.3f} len={features['feature1_packet_length']:.0f} {stats if pred == 'malware' else ''}")
        except Exception as e:
            PACKET_COUNT["errors"] += 1
            if PACKET_COUNT["errors"] % 100 == 0:  # Don't spam errors
                print(Fore.RED + f"[ERROR] handler (errors: {PACKET_COUNT['errors']}): {e}")
    return handle

if __name__ == "__main__":
    print("=" * 60)
    print("NETSHIELD AI - REAL NETWORK TRAFFIC CAPTURE")
    print("=" * 60)
    print("[INFO] This system captures ACTUAL network traffic from your network interface")
    print("[INFO] All packets are analyzed in real-time for malware detection")
    print("=" * 60)
    
    # Select network interface
    iface = select_best_interface()
    if not iface:
        print(Fore.RED + "[ERROR] No network interface available for capture!")
        print("[INFO] Make sure you have network interfaces available and proper permissions")
        exit(1)
    
    iface_addr = get_interface_info(iface)
    print(f"[INFO] Selected network interface: {iface}")
    print(f"[INFO] Interface IP address: {iface_addr}")
    print(f"[INFO] Capturing REAL network packets from: {iface}")
    print("-" * 60)
    
    # List available interfaces
    all_interfaces = get_network_interfaces()
    if len(all_interfaces) > 1:
        print(f"[INFO] Available interfaces: {', '.join(all_interfaces)}")
        print(f"[INFO] Using: {iface}")
        print("-" * 60)
    
    model = load_model()
    conn = init_db()
    handler = make_handler(model, conn)

    print(f"[INFO] Starting REAL network traffic capture on interface: {iface}")
    print("[INFO] Press Ctrl+C to stop capture")
    print("=" * 60)
    
    try:
        # Filter to only capture IP packets (real network traffic)
        # This ensures we're only processing actual network packets, not other protocols
        sniff(prn=handler, store=False, iface=iface, filter="ip")
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("[INFO] Capture stopped by user")
        print("=" * 60)
        print(f"[STATS] Total packets captured: {PACKET_COUNT['total']}")
        print(f"[STATS] Packets processed: {PACKET_COUNT['processed']}")
        print(f"[STATS] Packets skipped (non-IP): {PACKET_COUNT['skipped']}")
        print(f"[STATS] Errors: {PACKET_COUNT['errors']}")
        print("=" * 60)
    except PermissionError:
        print(Fore.RED + "[ERROR] Permission denied! Packet capture requires administrator/root privileges.")
        print("[INFO] Please run this script as administrator (Windows) or with sudo (Linux/Mac)")
        exit(1)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Capture failed: {e}")
        print("[INFO] Make sure:")
        print("  - You have administrator/root privileges")
        print("  - The network interface is available")
        print("  - Scapy is properly installed")
        exit(1)
