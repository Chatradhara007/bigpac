import urllib.request
import json
import os

def download_sample():
    print("Fetching file list from Zenodo API...")
    url = 'https://zenodo.org/api/records/7409923'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        
    files = data.get('files', [])
    if not files:
        print("No files found!")
        return
        
    # Filter for parquet files
    parquet_files = [f for f in files if f['key'].endswith('.parquet')]
    parquet_files.sort(key=lambda x: x['size'])
    
    if not parquet_files:
        print("No parquet files found!")
        return
        
    # Pick the smallest file
    target_file = parquet_files[0]
    filename = target_file['key']
    download_url = target_file['links']['self']
    size_mb = target_file['size'] / 1024 / 1024
    
    print(f"Selected: {filename} ({size_mb:.2f} MB)")
    print(f"Downloading from {download_url}...")
    
    os.makedirs('data/cesnet_raw', exist_ok=True)
    out_path = f"data/cesnet_raw/{filename}"
    
    urllib.request.urlretrieve(download_url, out_path)
    print(f"Downloaded to {out_path}")

if __name__ == "__main__":
    download_sample()
