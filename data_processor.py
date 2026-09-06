import pandas as pd
import numpy as np
import ast
import os
import glob

MAX_PACKETS = 30 
CATEGORIES = [
    'youtube', 'facebook-web', 'discord', 'instagram', 'google-play', 
    'spotify', 'whatsapp', 'snapchat', 'tiktok', 'microsoft-outlook'
]

def process_directory(base_dir, output_parquet="data/processed_data.parquet", max_rows_per_file=20000):
    print(f"Scanning directory: {base_dir}")
    
    # Find all flow CSV files recursively
    search_pattern = os.path.join(base_dir, '**', 'flows-*.csv*')
    all_files = glob.glob(search_pattern, recursive=True)
    
    if not all_files:
        print("No flow files found!")
        return
        
    print(f"Found {len(all_files)} flow files. We will sample {max_rows_per_file} rows from each to ensure diversity across weeks/days.")
    
    processed_data = []
    
    for file_path in all_files:
        print(f"Processing: {os.path.basename(file_path)}")
        try:
            # Read a chunk from the file
            df = pd.read_csv(file_path, nrows=max_rows_per_file)
            
            # Filter by categories
            df = df[df['APP'].isin(CATEGORIES)]
            
            for index, row in df.iterrows():
                app = row['APP']
                ppi_str = row['PPI']
                
                try:
                    ppi_data = ast.literal_eval(ppi_str)
                    iats = ppi_data[0]
                    dirs = ppi_data[1]
                    sizes = ppi_data[2]
                    
                    flat_features = {'label': app}
                    for i in range(MAX_PACKETS):
                        if i < len(sizes):
                            flat_features[f'pkt_size_{i}'] = sizes[i]
                            flat_features[f'pkt_dir_{i}'] = dirs[i]
                            flat_features[f'pkt_iat_{i}'] = iats[i]
                        else:
                            flat_features[f'pkt_size_{i}'] = 0
                            flat_features[f'pkt_dir_{i}'] = 0
                            flat_features[f'pkt_iat_{i}'] = 0
                            
                    processed_data.append(flat_features)
                except Exception:
                    continue
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            continue
            
    processed_df = pd.DataFrame(processed_data)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_parquet)), exist_ok=True)
    processed_df.to_parquet(output_parquet, index=False)
    print(f"\nSaved massive processed dataset ({len(processed_df)} samples from {len(all_files)} files) to {output_parquet}")

if __name__ == "__main__":
    BASE_DATA_DIR = r"C:\Users\CHATRADHARA\Downloads\cesnet-quic22\cesnet-quic22"
    os.chdir(r"C:\Users\CHATRADHARA\.gemini\antigravity\scratch\traffic_classifier")
    
    process_directory(BASE_DATA_DIR, max_rows_per_file=20000)
