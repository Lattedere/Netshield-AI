import joblib
from live_features import extract_features
from scapy.all import sniff

model = joblib.load("model_baseline.pkl")

def analyze(packet):
    features = extract_features(packet)
    prediction = model.predict([features])[0]

    print(f"\nPacket detected:")
    print(f"Features: {features}")
    print(f"Prediction: {prediction}\n")

def start_detection():
    print("Starting real-time malware detection...")
    sniff(prn=analyze, store=False)

if __name__ == "__main__":
    start_detection()
