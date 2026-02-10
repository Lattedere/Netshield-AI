import streamlit as st
import pandas as pd
import numpy as np
import joblib
import sqlite3
import time
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta
import altair as alt

st.set_page_config(page_title="Netshield AI (SQLite)", layout="wide")

MODEL_PATH = "model_10f_v2.pkl"
DB_PATH = "detections.db"
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

@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)

model = load_model()

if "logs" not in st.session_state:
    st.session_state["logs"] = pd.DataFrame(columns=["timestamp"] + FEATURE_NAMES + ["prediction", "confidence"])

def get_db_conn(path=DB_PATH):
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path, check_same_thread=False)
    return conn

def read_recent(conn, limit=200):
    if conn is None:
        return pd.DataFrame()
    q = f"SELECT id, timestamp, src_ip, dst_ip, prediction, confidence, {', '.join(FEATURE_NAMES)} FROM {TABLE_NAME} ORDER BY id DESC LIMIT {limit}"
    try:
        df = pd.read_sql_query(q, conn)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df
    except Exception as e:
        st.error("DB read error: " + str(e))
        return pd.DataFrame()

st.title("NetShield AI Dashboard (SQLite)")
tab_manual, tab_csv, tab_sim, tab_capture, tab_live, tab_logs, tab_docs = st.tabs(
    ["Manual Input", "CSV Upload", "Simulation", "Live Capture", "Live (DB)", "Logs", "Docs"]
)

with tab_manual:
    st.header("Manual Input Detection")
    inputs = {}
    for feat in FEATURE_NAMES:
        inputs[feat] = st.number_input(feat, value=0.0, step=1.0)
    if st.button("Run Manual Detection"):
        feat_list = [inputs[f] for f in FEATURE_NAMES]
        dfX = pd.DataFrame([feat_list], columns=FEATURE_NAMES)
        pred = model.predict(dfX)[0]
        conf = float(model.predict_proba(dfX).max())
        st.metric("Prediction", pred.upper())
        st.write(f"Confidence: {conf:.4f}")
        if pred == "malware":
            st.error("⚠ MALWARE DETECTED!")
        else:
            st.success("BENIGN")
        # log
        entry = {"timestamp": datetime.now().isoformat()}
        for f in FEATURE_NAMES:
            entry[f] = inputs[f]
        entry["prediction"] = pred
        entry["confidence"] = conf
        st.session_state["logs"] = pd.concat([st.session_state["logs"], pd.DataFrame([entry])], ignore_index=True)

with tab_csv:
    st.header("Batch Detection via CSV")
    file = st.file_uploader("Upload CSV", type=["csv"])
    if file:
        df = pd.read_csv(file)
        st.write(df.head())
        missing = [c for c in FEATURE_NAMES if c not in df.columns]
        if missing:
            st.error(f"Missing columns: {missing}")
        else:
            preds = model.predict(df[FEATURE_NAMES])
            confs = model.predict_proba(df[FEATURE_NAMES]).max(axis=1)
            df["prediction"] = preds
            df["confidence"] = confs
            st.success("Analysis complete!")
            st.dataframe(df.head(50))
            csv_out = df.to_csv(index=False).encode()
            st.download_button("Download Results CSV", csv_out, "results.csv", "text/csv")

with tab_sim:
    st.header("Real-Time Simulation (Synthetic)")
    if "simulate" not in st.session_state:
        st.session_state["simulate"] = False
    start = st.button("Start Simulation")
    stop = st.button("Stop Simulation")
    if start:
        st.session_state["simulate"] = True
    if stop:
        st.session_state["simulate"] = False
    placeholder = st.empty()
    while st.session_state["simulate"]:
        sample = {
            "feature1_packet_length": float(np.random.normal(900, 200)),
            "feature2_src_port": float(np.random.randint(1, 65535)),
            "feature3_dst_port": float(np.random.randint(1, 65535)),
            "feature4_protocol_id": float(np.random.choice([1, 2, 3])),
            "feature5_flow_duration": float(np.random.normal(5000, 2000)),
            "feature6_bytes_in": float(np.random.normal(15000, 6000)),
            "feature7_bytes_out": float(np.random.normal(20000, 8000)),
            "feature8_ttl": float(np.random.randint(32, 255)),
            "feature9_entropy": float(np.random.normal(6, 1)),
            "feature10_packet_rate": float(np.random.normal(500, 200)),
        }
        df = pd.DataFrame([sample])
        pred = model.predict(df)[0]
        conf = float(model.predict_proba(df).max())
        df["prediction"] = pred
        df["confidence"] = conf
        placeholder.dataframe(df)
        # log
        entry = {"timestamp": datetime.now().isoformat()}
        for f in FEATURE_NAMES:
            entry[f] = sample[f]
        entry["prediction"] = pred
        entry["confidence"] = conf
        st.session_state["logs"] = pd.concat([st.session_state["logs"], pd.DataFrame([entry])], ignore_index=True)
        time.sleep(1)

with tab_capture:
    st.header("Live Network Capture & Prediction")
    st.write("Start capturing network packets and running real-time malware detection.")
    
    # Initialize session state for capture process
    if "capture_process" not in st.session_state:
        st.session_state["capture_process"] = None
    if "capture_running" not in st.session_state:
        st.session_state["capture_running"] = False
    if "capture_output" not in st.session_state:
        st.session_state["capture_output"] = []
    if "capture_start_time" not in st.session_state:
        st.session_state["capture_start_time"] = None
    
    # Check if capture script exists
    capture_script = "capture_predict_live.py"
    script_exists = os.path.exists(capture_script)
    
    if not script_exists:
        st.error(f"Capture script not found: `{capture_script}`")
        st.info("Make sure `capture_predict_live.py` is in the same directory as this dashboard.")
    else:
        # Status display
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.session_state["capture_running"]:
                st.metric("Status", "🟢 Running", delta="Active")
            else:
                st.metric("Status", "🔴 Stopped", delta="Inactive")
        
        with col2:
            if st.session_state["capture_start_time"]:
                elapsed = datetime.now() - st.session_state["capture_start_time"]
                st.metric("Uptime", f"{elapsed.seconds // 60}m {elapsed.seconds % 60}s")
            else:
                st.metric("Uptime", "0m 0s")
        
        with col3:
            conn = get_db_conn()
            if conn:
                df_count = read_recent(conn, limit=10000)
                total_detections = len(df_count) if not df_count.empty else 0
                st.metric("Total Detections", total_detections)
            else:
                st.metric("Total Detections", "N/A")
        
        st.markdown("---")
        
        # Control buttons
        button_col1, button_col2, button_col3 = st.columns([1, 1, 2])
        
        with button_col1:
            if st.button("▶ Start Capture", type="primary", disabled=st.session_state["capture_running"], width='stretch'):
                try:
                    # Start the capture script as a subprocess
                    process = subprocess.Popen(
                        [sys.executable, capture_script],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        universal_newlines=True
                    )
                    st.session_state["capture_process"] = process
                    st.session_state["capture_running"] = True
                    st.session_state["capture_start_time"] = datetime.now()
                    st.session_state["capture_output"] = []
                    st.success("Capture started!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to start capture: {str(e)}")
                    st.info("**Tip:** Packet capture may require administrator privileges. Try running Streamlit as administrator.")
        
        with button_col2:
            if st.button("⏹ Stop Capture", type="secondary", disabled=not st.session_state["capture_running"], width='stretch'):
                if st.session_state["capture_process"]:
                    try:
                        st.session_state["capture_process"].terminate()
                        # Wait a bit for graceful shutdown
                        try:
                            st.session_state["capture_process"].wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            st.session_state["capture_process"].kill()
                        st.session_state["capture_process"] = None
                        st.session_state["capture_running"] = False
                        st.session_state["capture_start_time"] = None
                        st.success("Capture stopped!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error stopping capture: {str(e)}")
        
        with button_col3:
            if st.button("Refresh Status", width='stretch'):
                st.rerun()
        
        st.markdown("---")
        
        # Check process status
        if st.session_state["capture_process"]:
            return_code = st.session_state["capture_process"].poll()
            if return_code is not None:
                # Process has ended
                st.session_state["capture_running"] = False
                st.session_state["capture_process"] = None
                if return_code != 0:
                    st.warning(f"Capture process ended with code {return_code}")
        
        # Recent detections preview
        st.subheader("Recent Detections")
        conn = get_db_conn()
        if conn:
            df_recent = read_recent(conn, limit=50)
            if not df_recent.empty:
                # Show summary
                total = len(df_recent)
                malware_count = int((df_recent["prediction"] == "malware").sum()) if "prediction" in df_recent.columns else 0
                benign_count = total - malware_count
                
                summary_col1, summary_col2, summary_col3 = st.columns(3)
                summary_col1.metric("Recent Total", total)
                summary_col2.metric("Malware", malware_count, delta=None if malware_count == 0 else f"{malware_count} detected", delta_color="inverse")
                summary_col3.metric("Benign", benign_count)
                
                # Show recent detections
                display_df = df_recent[["timestamp", "src_ip", "dst_ip", "prediction", "confidence"]].head(20)
                st.dataframe(display_df, width='stretch', hide_index=True)
            else:
                st.info("No detections yet. Start capture to begin monitoring.")
        else:
            st.warning("Database not initialized. Capture will create it automatically.")
        
        # Information section
        with st.expander("ℹ Capture Information"):
            st.write("""
            **How it works:**
            1. Click "Start Capture" to begin monitoring network traffic
            2. The system captures packets and extracts features in real-time
            3. Each packet is analyzed using the ML model for malware detection
            4. Results are saved to the SQLite database (`detections.db`)
            5. View live results in the "Live (DB)" tab
            
            **Requirements:**
            - Administrator/root privileges (for packet capture)
            - Network interface access
            - Model file (`model_10f_v2.pkl`) must be present
            
            **Note:** The capture runs in the background. You can navigate to other tabs while it's running.
            """)
            
            if st.session_state["capture_running"]:
                st.info("**Tip:** Keep this tab open or check the 'Live (DB)' tab to see real-time detections.")

with tab_live:
    st.header("Live Detections (SQLite)")

    conn = get_db_conn()
    if conn is None:
        st.warning("Database not found. Run capture_to_sqlite.py first.")
    else:
        refresh = st.slider("Refresh interval (s)", 1, 5, 2)
        show_count = st.number_input("Show last N rows", min_value=10, max_value=1000, value=200, step=10)

        if "live_db_run" not in st.session_state:
            st.session_state["live_db_run"] = False
        if "last_malware_ids" not in st.session_state:
            st.session_state["last_malware_ids"] = set()

        if st.button("Start Live View"):
            st.session_state["live_db_run"] = True
            st.session_state["last_malware_ids"] = set()  # Reset when starting
        if st.button("Stop Live View"):
            st.session_state["live_db_run"] = False

        # Alert placeholder untuk pop-up warning
        alert_placeholder = st.empty()
        placeholder = st.empty()
        while st.session_state["live_db_run"]:
            df = read_recent(conn, limit=show_count)
            if df.empty:
                placeholder.info("No detections yet.")
                alert_placeholder.empty()
            else:
                # Cek malware baru
                if "prediction" in df.columns and "id" in df.columns:
                    malware_df = df[df["prediction"] == "malware"]
                    if not malware_df.empty:
                        current_malware_ids = set(malware_df["id"].astype(int))
                        new_malware_ids = current_malware_ids - st.session_state["last_malware_ids"]
                        
                        # Tampilkan pop-up warning jika ada malware baru
                        if new_malware_ids:
                            new_malware = malware_df[malware_df["id"].astype(int).isin(new_malware_ids)]
                            # Ambil malware terbaru untuk ditampilkan
                            latest_malware = new_malware.iloc[0] if len(new_malware) > 0 else None
                            
                            if latest_malware is not None:
                                # Format timestamp
                                ts_str = str(latest_malware.get('timestamp', 'N/A'))
                                if hasattr(latest_malware.get('timestamp'), 'strftime'):
                                    ts_str = latest_malware['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                                
                                # Pop-up warning dengan HTML/CSS
                                alert_html = f"""
                                <div style="
                                    position: fixed;
                                    top: 20px;
                                    right: 20px;
                                    background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
                                    color: white;
                                    padding: 20px 30px;
                                    border-radius: 10px;
                                    box-shadow: 0 4px 20px rgba(255, 68, 68, 0.5);
                                    z-index: 9999;
                                    animation: slideIn 0.5s ease-out;
                                    max-width: 400px;
                                    border: 3px solid #ff6666;
                                    font-family: Arial, sans-serif;
                                ">
                                    <h2 style="margin: 0 0 15px 0; font-size: 24px; text-align: center; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                                        MALWARE DETECTED!
                                    </h2>
                                    <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 5px; margin: 10px 0;">
                                        <p style="margin: 8px 0; font-size: 14px;"><strong>Source IP:</strong> {latest_malware.get('src_ip', 'N/A')}</p>
                                        <p style="margin: 8px 0; font-size: 14px;"><strong>Destination IP:</strong> {latest_malware.get('dst_ip', 'N/A')}</p>
                                        <p style="margin: 8px 0; font-size: 14px;"><strong>Confidence:</strong> {latest_malware.get('confidence', 0):.1%}</p>
                                        <p style="margin: 8px 0; font-size: 14px;"><strong>Time:</strong> {ts_str}</p>
                                    </div>
                                    <p style="margin: 15px 0 0 0; text-align: center; font-weight: bold; font-size: 16px;">
                                        🚨 Immediate action required! 🚨
                                    </p>
                                </div>
                                <style>
                                    @keyframes slideIn {{
                                        from {{
                                            transform: translateX(400px);
                                            opacity: 0;
                                        }}
                                        to {{
                                            transform: translateX(0);
                                            opacity: 1;
                                        }}
                                    }}
                                </style>
                                """
                                alert_placeholder.markdown(alert_html, unsafe_allow_html=True)
                                
                                # Tampilkan juga error box di Streamlit (lebih persistent)
                                st.error(f"🚨 **MALWARE DETECTED!**\n\n"
                                       f"**Source IP:** `{latest_malware.get('src_ip', 'N/A')}` → **Destination IP:** `{latest_malware.get('dst_ip', 'N/A')}`\n\n"
                                       f"**Confidence:** `{latest_malware.get('confidence', 0):.2%}`\n\n"
                                       f"**Timestamp:** `{ts_str}`\n\n"
                                       f"**Total new malware detections:** {len(new_malware_ids)}")
                            
                            # Update last_malware_ids
                            st.session_state["last_malware_ids"] = current_malware_ids
                        else:
                            # Kosongkan alert jika tidak ada malware baru
                            alert_placeholder.empty()
                else:
                    alert_placeholder.empty()
            
                def color_row(r):
                    return ["background-color: #ffdddd" if r.prediction=="malware" else ""] * len(r)
                total = len(df)
                mal = int((df["prediction"]=="malware").sum()) if "prediction" in df.columns else 0
                benign = total - mal
                col1, col2, col3 = st.columns(3)
                col1.metric("Total", total)
                col2.metric("Malware", mal, delta=None if mal == 0 else f"{mal} detected", delta_color="inverse")
                col3.metric("Benign", benign)

                placeholder.dataframe(df.head(200))
            time.sleep(refresh)

with tab_logs:
    st.header("Internal Logs")
    st.dataframe(st.session_state["logs"].tail(100))
    csv_download = st.session_state["logs"].to_csv(index=False)
    st.download_button("Download Logs", csv_download, "netshield_logs.csv")
    if st.button("Clear Logs"):
        st.session_state["logs"] = st.session_state["logs"].iloc[0:0]
        st.success("Logs cleared.")

with tab_docs:
    st.header("Documentation & Info")
    st.write("Model path:", MODEL_PATH)
    st.write("Database:", DB_PATH)

st.markdown("---")
st.write("NetShield AI Dashboard — SQLite live viewer")
