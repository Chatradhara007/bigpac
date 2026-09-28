# BigPAC — Run and Demo Guide (for teammates)

Follow the steps in order. Every command runs from inside the `bigpac` folder.
Tested in a Linux sandbox; not yet run on Windows. If any step fails, copy the full error and send it.

## 0. What you need

From the repository (via `git clone` / `git pull`):
all code, `docs/`, `tests/`, `results/`.

Sent separately (Google Drive / USB, **not** in git), put them exactly here:

| File | Put it at | Needed for |
|---|---|---|
| `live_labelled.csv` | `data\live_labelled.csv` | training, demo |
| `processed_data.parquet` | `data\processed_data.parquet` | training |
| `rf_model_n15.joblib` (old model, 285 MB) | `models\rf_model_n15.joblib` | optional: old-vs-new comparison |
| `home-laptop-session3_00001_20260926221146.pcapng` | `data\captures\` | optional: replay demo |

Software: Python 3.10 or newer. For the live demo only: Wireshark with **Npcap** (installed together).

## 1. Install (once)

```
pip install -r requirements.txt
python -c "import sklearn; print(sklearn.__version__)"
```

Write down the scikit-learn version. The person who trains and the laptop that runs the demo **must have the same version**; otherwise the model may not load.

## 2. Quick checks (1 minute)

```
python tests\test_pcap_to_dataset.py
python tests\test_features.py
```

Expected: `9 passed` and `4 passed`.

## 3. Train the model (about 2–5 minutes)

**Final run (decided protocol, see IMPLEMENTATION_STATUS.md §11.1):** laptop data only, gradient boosting, tested on the new laptop session recorded last:

```
python train_v2.py --exclude-network home-phone --candidates hgb_iat --test-source <final session file name>
```

`<final session file name>` is the capture's file name exactly as in the `source` column (run `python diagnose_capture.py` to list them). First copy the previous results so they are not lost: `mkdir results\run1` then `copy results\stage5_train_v2.* results\run1\`.

Reference run (reproduces §9.4):

```
python train_v2.py
```

It prints everything and saves:

- `models\bigpac_v2.joblib` — the new model (about 30 MB)
- `results\stage5_train_v2.txt` and `.json` — the results (commit these)
- `data\demo_samples.json` — held-out flows for the web demo

Check the block **FINAL EVALUATION ON THE HELD-OUT LIVE CAPTURE**. The reference run (scikit-learn 1.8.0) printed:

```
new model, threshold 0.30 : known acc 0.514 | ... | open acc 0.765 | ...
OLD model (rf_model_n15)   : known acc 0.254 | ... | open acc 0.114 | ...
```

A different scikit-learn version can change these slightly. **Report the numbers your run prints**, not the reference ones, and send them so they can be recorded in `IMPLEMENTATION_STATUS.md`.

## 4. Demo A — web page (no admin needed)

```
python app.py
```

Open http://127.0.0.1:5000 . Click an app, then **Replay & Classify**. Each flow is a real connection from a capture session the model never trained on. The page shows the prediction, whether it is right (true app from the server name), and the measured results table. Stop with Ctrl+C.

## 5. Demo B — live traffic

1. Open a terminal **as Administrator**.
2. Run:
   ```
   python live_capture_v2.py
   ```
   If it picks the wrong network adapter: `python live_capture_v2.py --list-ifaces`, then `python live_capture_v2.py --iface "Wi-Fi"` (use the name shown).
3. Open YouTube, Instagram, Spotify, Facebook or WhatsApp Web in Chrome/Brave. Each new QUIC connection prints one line: prediction (app / `other` / `UNKNOWN`), confidence, top-3. Every 30 s it also shows which apps were seen.
4. Tip: a **new** connection is needed for a prediction. Close and reopen the tab, or use `chrome://net-internals/#sockets` → *Flush socket pools*.
5. Stop with Ctrl+C. All predictions are saved in `results\live_predictions.csv`.

Backup if the network blocks QUIC (the summary then says "Only TCP traffic seen"), or no admin rights: replay a saved capture instead:

```
python live_capture_v2.py --pcap data\captures\home-laptop-session3_00001_20260926221146.pcapng
```

The old sniffer `live_capture.py` is unchanged and can be shown as the "before" version (it needs the old `rf_model_n10/n15` files).

After converting captures you can see exactly what goes wrong for one capture:
`python diagnose_capture.py <capture file name>`.

## 6. What to say (honest numbers)

- The original model scored ~97% on the CESNET dataset but only **30.8%** on our real traffic (apps only) and **13.1%** on all traffic, because of three measured causes: Chrome now splits the handshake across two packets (98% of our flows vs 42% in CESNET), timing is measured differently, and most real traffic is none of the 10 apps.
- The new model, tested on a whole capture session it never saw, reaches **51.4%** on the apps and **76.5%** on all traffic (the old model scores 25.4% / 11.4% on that same session), and still **95.6%** on CESNET.
- Limits: Discord, Snapchat and Google Play are still not recognised live (little or no live training data); TikTok (banned in India) and Outlook have no live test data; the test session is from the same evening and network as the training sessions, so this is an optimistic live estimate.

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: features` / `pcap_to_dataset` | You are not in the `bigpac` folder, or the file is missing from it |
| `Model trained with scikit-learn X, you have Y` | Retrain on this machine (`python train_v2.py`) or install the same version |
| `Model not found: models/bigpac_v2.joblib` | Run step 3 first |
| Live mode: `Capture failed` | Administrator terminal; Npcap installed |
| Live mode prints nothing | Open a *new* tab/site; check the adapter with `--list-ifaces` |
| Web page table says "results not found" | Run step 3 first (it writes `results\stage5_train_v2.json`) |
