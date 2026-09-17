import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

os.chdir(r"C:\Users\CHATRADHARA\.gemini\antigravity\scratch\traffic_classifier")

print("Loading parquet dataset...")
df = pd.read_parquet("data/processed_data.parquet")
print(f"Loaded {len(df)} flows across {df['label'].nunique()} classes.")

for n in (10, 15):
    print(f"\nTraining model for N={n} with class_weight='balanced'...")
    cols = []
    for i in range(n):
        cols.extend([f"pkt_size_{i}", f"pkt_dir_{i}", f"pkt_iat_{i}"])
    X = df[cols].values
    y = df['label'].values
    
    clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X, y)
    
    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, f"models/rf_model_n{n}.joblib")
    print(f"[+] Saved models/rf_model_n{n}.joblib!")

print("\nDone! All models retrained with balanced weights.")
