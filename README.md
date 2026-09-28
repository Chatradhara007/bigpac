# BigPAC — Encrypted QUIC App Classifier

BigPAC identifies which app (YouTube, Instagram, Spotify, …) produced an encrypted QUIC connection using only the sizes, directions and timing of its first packets.

**How to run everything:** [`docs/RUN_AND_DEMO_GUIDE.md`](docs/RUN_AND_DEMO_GUIDE.md)
**Full project history, every experiment and result:** [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)

## Results (all measured; see `results/`)

| Model | Test data | Known apps | All traffic |
|---|---|---|---|
| Original RF (`rf_model_n15`) | CESNET-QUIC22, random split (reported) | 97.1% | — |
| Original RF | all our live captures | 30.8% | 13.1% |
| Original RF | held-out live session | 25.4% | 11.4% |
| **BigPAC v2** | **held-out live session** (never seen in training) | **51.4%** | **76.5%** |
| BigPAC v2 | CESNET-QUIC22 test split | 95.6% | — |

"Known apps" = connections of the 10 target apps; "all traffic" also includes connections to other services, which v2 should label `other`. Live labels come from the TLS server name (SNI) in the QUIC Initial packets; the model never sees the SNI.

## Main files

| File | Purpose |
|---|---|
| `features.py` | Feature extraction shared by training, live sniffer and web demo |
| `train_v2.py` | Trains and evaluates BigPAC v2 (one command) |
| `live_capture_v2.py` | Live classifier (sniffs Wi-Fi, or replays a capture with `--pcap`) |
| `app.py`, `static/` | Web demo on held-out real flows |
| `pcap_to_dataset.py` | Converts Wireshark captures into the SNI-labelled live dataset |
| `eval_live.py` | Evaluates any old-format model on the live dataset |
| `tests/` | Unit and consistency tests |

Original pipeline (unchanged, reproduces the 97% CESNET result): `data_processor.py`, `model_pipeline.py`, `retrain_balanced.py`, `visualizer.py`, `extract_samples.py`, `live_capture.py`.
Superseded, kept for reference: `live_collector.py`, `train_live_model.py` (replaced by `pcap_to_dataset.py` + `train_v2.py`), `fetch_zenodo.py`, `test_datazoo.py` (abandoned). `PROJECT_DOCUMENTATION.md` describes the project before this work and is partly outdated.

## Data (not in git)

`data/processed_data.parquet` (CESNET-QUIC22, 192,713 flows, 10 apps), `data/live_labelled.csv` (1,948 of our own labelled flows), captures in `data/captures/`, models in `models/`.
