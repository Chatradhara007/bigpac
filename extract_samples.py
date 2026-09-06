import pandas as pd
import json
import random
import os

def extract_samples():
    print("Loading parquet data...")
    df = pd.read_parquet('data/processed_data.parquet')
    
    apps_needed = ['youtube', 'discord', 'spotify', 'whatsapp', 'facebook-web']
    
    samples_db = {}
    
    for app in apps_needed:
        app_data = df[df['label'] == app]
        if len(app_data) == 0:
            print(f"Warning: No data for {app}")
            continue
            
        # Take up to 100 random samples
        sample_size = min(100, len(app_data))
        sampled_df = app_data.sample(n=sample_size, random_state=42)
        
        # Convert rows to feature arrays
        features_list = []
        for _, row in sampled_df.iterrows():
            features = []
            # We need 45 features for N=15
            for i in range(15):
                features.extend([
                    int(row[f'pkt_size_{i}']),
                    int(row[f'pkt_dir_{i}']),
                    float(row[f'pkt_iat_{i}'])
                ])
            features_list.append(features)
            
        samples_db[app] = features_list
        print(f"Extracted {len(features_list)} real samples for {app}")
        
    os.makedirs('data', exist_ok=True)
    with open('data/real_samples.json', 'w') as f:
        json.dump(samples_db, f)
    print("Saved real samples to data/real_samples.json")

if __name__ == "__main__":
    os.chdir(r"C:\Users\CHATRADHARA\.gemini\antigravity\scratch\traffic_classifier")
    extract_samples()
