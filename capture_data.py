import pandas as pd
from sklearn.datasets import make_classification

X, y = make_classification(
    n_samples=1000, 
    n_features=10, 
    n_informative=6, 
    n_classes=2, 
    random_state=42
)

df = pd.DataFrame(X, columns=[f'feature_{i}' for i in range(10)])
df['label'] = y  # 0 = benign, 1 = malware
df.to_csv("network_traffic.csv", index=False)

print(" Sample network traffic data created and saved as network_traffic.csv")
