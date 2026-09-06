import sys
from cesnet_datazoo.datasets import CESNET_QUIC22
from cesnet_datazoo.config import DatasetConfig, AppSelection

def test_datazoo():
    print("Initializing CESNET-QUIC22 Dataset (XS size)...")
    # This will download the XS dataset to the specified folder
    dataset = CESNET_QUIC22("data/cesnet_raw", size="XS")
    
    dataset_config = DatasetConfig(
        dataset=dataset,
        apps_selection=AppSelection.ALL_KNOWN,
        train_period_name="W-2022-44",
        test_period_name="W-2022-45",
    )
    dataset.set_dataset_config_and_initialize(dataset_config)

    print("Loading Train DataFrame...")
    train_df = dataset.get_train_df()
    
    print(f"Loaded DataFrame with shape: {train_df.shape}")
    print("Columns available:")
    for col in train_df.columns:
        print(f" - {col}")
        
    # Save a small sample to inspect
    sample = train_df.head(5)
    sample.to_csv("data/sample_cesnet.csv", index=False)
    print("Saved sample to data/sample_cesnet.csv")

if __name__ == "__main__":
    test_datazoo()
