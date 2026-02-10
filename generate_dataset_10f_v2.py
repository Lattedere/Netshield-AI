import pandas as pd
import numpy as np

N = 10000  # dataset size
np.random.seed(42)

benign = pd.DataFrame({
    "feature1_packet_length": np.random.normal(300, 80, N//2).clip(60, 1500),
    "feature2_src_port": np.random.randint(1024, 50000, N//2),
    "feature3_dst_port": np.random.randint(1024, 50000, N//2),
    "feature4_protocol_id": np.random.choice([1,2,3], N//2, p=[0.1, 0.7, 0.2]),
    "feature5_flow_duration": np.random.normal(20000, 5000, N//2).clip(1000, 80000),
    "feature6_bytes_in": np.random.normal(8000, 2000, N//2).clip(100, 30000),
    "feature7_bytes_out": np.random.normal(7000, 2500, N//2).clip(100, 30000),
    "feature8_ttl": np.random.normal(100, 20, N//2).clip(32, 255),
    "feature9_entropy": np.random.normal(3.5, 0.7, N//2).clip(1.0, 8.0),
    "feature10_packet_rate": np.random.normal(200, 50, N//2).clip(1, 2000),
})

benign["label"] = "benign"

malware = pd.DataFrame({
    "feature1_packet_length": np.random.normal(900, 200, N//2).clip(60, 1500),
    "feature2_src_port": np.random.randint(1, 65535, N//2),
    "feature3_dst_port": np.random.randint(1, 65535, N//2),
    "feature4_protocol_id": np.random.choice([1,2,3], N//2, p=[0.05, 0.5, 0.45]),
    "feature5_flow_duration": np.random.normal(5000, 3000, N//2).clip(100, 50000),
    "feature6_bytes_in": np.random.normal(15000, 6000, N//2).clip(1000, 50000),
    "feature7_bytes_out": np.random.normal(20000, 8000, N//2).clip(1000, 50000),
    "feature8_ttl": np.random.normal(70, 30, N//2).clip(32, 255),
    "feature9_entropy": np.random.normal(6.0, 0.9, N//2).clip(1.0, 8.0),
    "feature10_packet_rate": np.random.normal(600, 200, N//2).clip(1, 2000),
})

malware["label"] = "malware"

df = pd.concat([benign, malware], axis=0).sample(frac=1, random_state=42)

df.to_csv("dataset_10f_v2.csv", index=False)

print("Dataset v2 created successfully: dataset_10f_v2.csv")
print(df.head())
