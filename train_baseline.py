import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
import joblib

df = pd.read_csv("network_traffic_preprocessed.csv")
x = df.drop('label', axis=1)
y = df['label']

x_train, x_test, y_train, y_test = train_test_split(
    x, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(x_train, y_train)

y_pred = model.predict(x_test)

print("Model Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report: \n")
print(classification_report(y_test, y_pred))

joblib.dump(model, "model_baseline.pkl")
print("Model saved as model_baseline.pkl")