import streamlit as st
import pandas as pd
import time

st.set_page_config(page_title="Live Malware Detection Dashboard", layout="wide")

st.title("Netshield AI Dashboard")
st.write("Monitoring live network traffic and AI predictions from capture script.")

CSV_PATH = "live_detections.csv"

REFRESH_RATE = 1  # seconds

placeholder = st.empty()

while True:
    try:
        df = pd.read_csv(CSV_PATH)

        df["color"] = df["prediction"].apply(
            lambda x: "MALWARE" if x == "malware" else "BENIGN"
        )

        show_df = df[[
            "timestamp",
            "color",
            "prediction",
            "confidence",
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
        ]]

        with placeholder.container():
            st.subheader("Live Packet Detection Feed")
            st.dataframe(show_df.tail(30), height=600)

            # Summary stats
            benign_count = (df["prediction"] == "benign").sum()
            malware_count = (df["prediction"] == "malware").sum()

            st.markdown("---")
            st.subheader("Detection Summary")
            col1, col2 = st.columns(2)

            col1.metric("Total Benign Packets", benign_count)
            col2.metric("Total Malware Packets", malware_count)

    except Exception:
        st.warning("Waiting for data... Start the capture script first.")

    time.sleep(REFRESH_RATE)