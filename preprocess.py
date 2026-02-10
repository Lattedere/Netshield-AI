import pandas as pd
from sklearn.preprocessing import StandardScaler

df = pd.read_csv("network_traffic.csv")
print("Loaded dataset with shape:", df.shape)

X = df.drop('label', axis=1)
y = df['label']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

preprocessed_df = pd.DataFrame(X_scaled, columns=X.columns)
preprocessed_df['label'] = y
preprocessed_df.to_csv("network_traffic_preprocessed.csv", index=False)

print(" Preprocessed data saved as network_traffic_preprocessed.csv")
