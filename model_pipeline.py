import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import json
import os

def load_data(filepath="data/processed_data.parquet"):
    print(f"Loading data from {filepath}...")
    return pd.read_parquet(filepath)

def train_and_evaluate_for_n(df, n_packets):
    """
    Extracts features for the first N packets, trains an RF, and returns accuracy.
    """
    # 1. Filter columns to only include up to N packets
    feature_cols = []
    for i in range(n_packets):
        feature_cols.extend([f'pkt_size_{i}', f'pkt_dir_{i}', f'pkt_iat_{i}'])
        
    X = df[feature_cols]
    y = df['label']
    
    # 2. Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 3. Train Model
    print(f"Training Random Forest with N={n_packets} packets ({len(feature_cols)} features)...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # 4. Evaluate
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy for N={n_packets}: {acc * 100:.2f}%")
    
    # Save the model if it's our chosen production model (N=15)
    if n_packets == 15:
        os.makedirs("models", exist_ok=True)
        joblib.dump(clf, f"models/rf_model_n{n_packets}.joblib")
        print(f"Saved model to models/rf_model_n{n_packets}.joblib")
    
    return acc

def run_experiment(filepath="data/processed_data.parquet", n_values=[5, 10, 15, 20, 30]):
    df = load_data(filepath)
    
    results = {}
    for n in n_values:
        accuracy = train_and_evaluate_for_n(df, n)
        results[n] = accuracy
        
    # Save results
    os.makedirs("results", exist_ok=True)
    with open("results/accuracy_vs_n.json", "w") as f:
        json.dump(results, f, indent=4)
        
    print("Experiment completed. Results saved to results/accuracy_vs_n.json")
    return results

if __name__ == "__main__":
    data_path = "C:/Users/CHATRADHARA/.gemini/antigravity/scratch/traffic_classifier/data/processed_data.parquet"
    # Ensure working dir is set properly
    os.chdir("C:/Users/CHATRADHARA/.gemini/antigravity/scratch/traffic_classifier")
    run_experiment(data_path)
