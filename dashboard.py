import streamlit as st
import pandas as pd
import numpy as np
import joblib
import io
from datetime import datetime
import time
import base64

st.set_page_config(page_title="Netshield AI Dashboard", layout="wide")

MODEL_PATH = "model_10f_v2.pkl"
model = joblib.load(MODEL_PATH)

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

if "logs" not in st.session_state:
    st.session_state["logs"] = pd.DataFrame(columns=["timestamp"] + FEATURE_NAMES + ["prediction", "confidence"])

def predict_single(features_list):
    X = np.array(features_list).reshape(1, -1)
    pred = model.predict(X)[0]

    if hasattr(model, "predict_proba"):
        prob = model.predict_proba(X)[0]
        conf = float(prob[list(model.classes_).index(pred)])
    else:
        conf = 1.0

    return pred, conf

def log_prediction(features_dict, pred, conf):
    entry = {"timestamp": datetime.now().isoformat()}
    for f in FEATURE_NAMES:
        entry[f] = features_dict.get(f, np.nan)
    entry["prediction"] = pred
    entry["confidence"] = conf

    st.session_state["logs"] = pd.concat(
        [st.session_state["logs"], pd.DataFrame([entry])], ignore_index=True
    )

def download_df_as_csv(df, filename="export.csv"):
    buff = io.StringIO()
    df.to_csv(buff, index=False)
    b64 = base64.b64encode(buff.getvalue().encode()).decode()
    return f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download {filename}</a>'

def make_pie_counts(df):
    benign = int(df["prediction"].value_counts().get("benign", 0))
    malware = int(df["prediction"].value_counts().get("malware", 0))
    return benign, malware

st.title("Netshield AI Dashboard")
st.write("Fully interactive AI-powered malware detection system")

tab_manual, tab_csv, tab_live, tab_logs, tab_docs = st.tabs(
    ["Manual Input", "CSV Upload", "Live Simulation", "Logs", "Docs / Export"]
)

with tab_manual:
    st.header("Manual Input - Single Sample Detection")

    inputs = {}
    for feat in FEATURE_NAMES:
        val = st.number_input(feat, value=100.0, step=1.0, format="%.2f")
        inputs[feat] = float(val)

    if st.button("Run Detection (Manual)"):
        feature_list = [inputs[f] for f in FEATURE_NAMES]
        pred, conf = predict_single(feature_list)

        st.subheader("Result")
        st.metric("Prediction", pred.upper())
        st.write(f"Confidence Score: {conf:.4f}")

        if pred == "malware":
            st.error("MALWARE DETECTED!")
        else:
            st.success("BENIGN")

        log_prediction(inputs, pred, conf)

with tab_csv:
    st.header("CSV Upload - Batch Detection")
    uploaded = st.file_uploader("Upload CSV file", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)
        st.write("Preview:")
        st.dataframe(df.head())

        missing = [c for c in FEATURE_NAMES if c not in df.columns]
        if missing:
            st.error(f"Missing required columns: {missing}")
        else:
            X = df[FEATURE_NAMES].values
            preds = model.predict(X)
            probs = model.predict_proba(X).max(axis=1)

            df["prediction"] = preds
            df["confidence"] = probs

            st.success("Detection complete!")
            st.dataframe(df.head(50))

            st.markdown("### Highlighted Results (Malware in Red)")
            def highlight(row):
                color = "background-color: #ffcccc" if row["prediction"] == "malware" else ""
                return [color]*len(row)
            st.dataframe(df.style.apply(highlight, axis=1))

            if st.button("Add results to logs"):
                for _, r in df.iterrows():
                    log_prediction(
                        {f: r[f] for f in FEATURE_NAMES},
                        r["prediction"],
                        float(r["confidence"]),
                    )
                st.success("Results added to logs!")

            csv_out = df.to_csv(index=False).encode()
            st.download_button("Download Results CSV", csv_out, "predictions.csv", "text/csv")

with tab_live:
    st.header("Live Simulation - Real-time Synthetic Traffic")

    start = st.button("Start Simulation")
    stop = st.button("Stop Simulation")

    n_samples = st.slider("Samples per cycle", 1, 10, 3)
    delay = st.slider("Delay (seconds)", 0.2, 3.0, 1.0)
    iterations = st.number_input("Number of cycles (0 = infinite)", 0, value=5)

    placeholder = st.empty()

    if "live" not in st.session_state:
        st.session_state["live"] = False

    if start:
        st.session_state["live"] = True
    if stop:
        st.session_state["live"] = False

    run_count = 0

    while st.session_state["live"]:
        if iterations > 0 and run_count >= iterations:
            st.session_state["live"] = False
            break

        samples = []
        for _ in range(n_samples):
            sample = {
                "feature1_packet_length": float(np.random.normal(900, 200)),
                "feature2_src_port": float(np.random.randint(1, 65535)),
                "feature3_dst_port": float(np.random.randint(1, 65535)),
                "feature4_protocol_id": float(np.random.choice([1,2,3])),
                "feature5_flow_duration": float(np.random.normal(5000, 2000)),
                "feature6_bytes_in": float(np.random.normal(15000, 6000)),
                "feature7_bytes_out": float(np.random.normal(20000, 8000)),
                "feature8_ttl": float(np.random.randint(32, 255)),
                "feature9_entropy": float(np.random.normal(6, 1)),
                "feature10_packet_rate": float(np.random.normal(500, 200)),
            }
            samples.append(sample)

        df_live = pd.DataFrame(samples)
        preds = model.predict(df_live[FEATURE_NAMES])
        probs = model.predict_proba(df_live[FEATURE_NAMES]).max(axis=1)

        df_live["prediction"] = preds
        df_live["confidence"] = probs

        placeholder.dataframe(df_live)

        for _, r in df_live.iterrows():
            log_prediction(
                {f: r[f] for f in FEATURE_NAMES},
                r["prediction"],
                float(r["confidence"])
            )

        run_count += 1
        time.sleep(delay)

with tab_logs:
    st.header("Prediction Logs")
    df_logs = st.session_state["logs"]

    st.dataframe(df_logs.tail(100).sort_values("timestamp", ascending=False))

    st.markdown(download_df_as_csv(df_logs, "detection_logs.csv"), unsafe_allow_html=True)

    if st.button("Clear Logs"):
        st.session_state["logs"] = st.session_state["logs"].iloc[0:0]
        st.success("Logs cleared.")

with tab_docs:
    st.header("Documentation & Export")
    st.write("")

    st.subheader("Feature Names")
    st.write(FEATURE_NAMES)

    template = pd.DataFrame(columns=FEATURE_NAMES).to_csv(index=False).encode()
    st.download_button("Download CSV Template", template, "template.csv", "text/csv")

    readme = f"""
Netshield AI Dashboard
Generated: {datetime.now().isoformat()}

Features:
- Manual detection
- Batch CSV detection
- Real-time simulation
- Logs & export
- Good UI

Model: {MODEL_PATH}
"""
    st.download_button("Download README.txt", readme.encode(), "README.txt", "text/plain")

st.markdown("---")
st.write("AI Malware Detection System")
