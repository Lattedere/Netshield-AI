import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

print("Loading dataset...")
data = pd.read_csv("dataset_10f_v2.csv")

# Pisahkan ciri & label
X = data.drop("label", axis=1)
y = data["label"]

print("Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training model V2, please wait...")

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=12,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {acc:.3f}\n")
print("Classification Report:")
print(classification_report(y_test, y_pred))

model_path = "model_10f_v2.pkl"
joblib.dump(model, model_path)

print(f"\nModel V2 saved as: {model_path}")
