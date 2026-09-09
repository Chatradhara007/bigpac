import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os
import sys

# Windows console colors
import ctypes
kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

class Colors:
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

DATA_FILE = 'data/live_training_data.csv'
MODEL_PATH = 'models/my_custom_model.joblib'

def train():
    if not os.path.exists(DATA_FILE):
        print(f"{Colors.RED}[!] No training data found at {DATA_FILE}. Run live_collector.py first!{Colors.ENDC}")
        sys.exit(1)
        
    print(f"{Colors.CYAN}[*] Loading your custom live dataset...{Colors.ENDC}")
    df = pd.read_csv(DATA_FILE)
    
    if len(df) < 10:
        print(f"{Colors.RED}[!] Only {len(df)} samples found. You need to collect more data before training!{Colors.ENDC}")
        sys.exit(1)
        
    print(f"{Colors.YELLOW}[*] Found {len(df)} total connections across {df['label'].nunique()} apps.{Colors.ENDC}")
    print(df['label'].value_counts())
    
    import numpy as np
    X = np.array(df.drop(columns=['label']), dtype=float)
    y = np.array(df['label'], dtype=str)
    
    # Check if we have at least 2 classes
    if len(set(y)) < 2:
        print(f"{Colors.RED}[!] You only have data for ONE app. Collect data for at least 2 apps to train a classifier.{Colors.ENDC}")
        sys.exit(1)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"\n{Colors.CYAN}[*] Training custom Random Forest Model...{Colors.ENDC}")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"{Colors.GREEN}[+] Model trained successfully!{Colors.ENDC}")
    print(f"{Colors.GREEN}[+] Custom Model Accuracy on test split: {acc * 100:.2f}%{Colors.ENDC}")
    
    os.makedirs('models', exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"{Colors.CYAN}[*] Saved model to {MODEL_PATH}{Colors.ENDC}")
    print(f"{Colors.YELLOW}[*] You can now update live_capture.py to use this model!{Colors.ENDC}")

if __name__ == "__main__":
    train()
