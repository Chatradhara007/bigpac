# BigPAC — Implementation Status

Reference plan: *BigPAC Project Analysis & Model Improvement Plan* (2026-09-24)
Repository base: commit `7ab1750` (HEAD of `main`, 2026-09-18); files added since then are listed per stage and are not yet committed.
Last updated: 2026-09-24 (Stage 1 session)

| Session | Date | Work |
|---|---|---|
| 1 | 2026-09-24 | Stage 0 audit (read-only) |
| 2 | 2026-09-24 | Stage 1 tooling: converter, tests, capture guide |

---

## 1. Stage tracker

| Stage | Plan step (from PDF) | Status |
|---|---|---|
| 0 | Repository audit and baseline | **Done (audit) / Blocked (baseline numbers)** — see §5 |
| 1 | SNI auto-labelled live test set (`pcap_to_dataset.py`) | **In progress — tooling done and validated; waiting for real captures** (see §7) |
| 2 | Measure the gap (`eval_live.py`, per-class report, shift AUC) | Not started |
| 3 | `other` class + unknown threshold; `week` column; chunked reading | Not started |
| 4 | Shared drift-robust `features.py` | Not started |
| 5 | Time-based split + retrain with live data (`train_v2.py`) | Not started |
| 6 | Sniffer fixes: IPv6, idle reset, expiry, shared features | Not started |
| 7 | Gradient boosting, then 1D-CNN | Not started |

At the Stage 0 audit none of the files the PDF proposes existed. `pcap_to_dataset.py` now exists (Stage 1); `eval_live.py`, `features.py` and `train_v2.py` do not.

---

## 2. Current architecture (as found at Stage 0)

§2–§6 are the Stage 0 audit record and describe commit `7ab1750`. Stage 1 additions are in §7.

### 2.1 Inventory

12 Python files, 3 static web files, `PROJECT_DOCUMENTATION.md`, `requirements.txt`, `.gitignore` — 1,688 lines total. (The PDF says 13 Python files; the actual count is 12.) There are no tests, no README, no CLI arguments and no config file.

| File | Lines | Role |
|---|---|---|
| `data_processor.py` | 76 | CESNET `flows-*.csv*` → `data/processed_data.parquet` (10 apps, 90 columns + `label`) |
| `model_pipeline.py` | 67 | RF per N ∈ {5,10,15,20,30}, random 80/20 split, saves `models/rf_model_n{N}.joblib`, `results/accuracy_vs_n.json` |
| `retrain_balanced.py` | 27 | Retrains N=10, N=15 on 100% of data, overwrites those two model files |
| `visualizer.py` | 43 | Plots `accuracy_vs_n.json` |
| `extract_samples.py` | 47 | 100 flows × 5 apps from the parquet → `data/real_samples.json` |
| `app.py` + `static/` | 70 + 502 | Flask demo: `/get_sample/<app>`, `/predict` (N=15 model, top-3) |
| `live_capture.py` | 283 | Scapy sniffer; classifies UDP:443 flows at 10 and 15 packets |
| `live_collector.py` | 169 | Records first 15 packets of every port-443 flow under a typed label |
| `train_live_model.py` | 66 | Trains `models/my_custom_model.joblib` on collector CSV |
| `debug_network.py` | 23 | Interface listing / capture smoke test |
| `fetch_zenodo.py`, `test_datazoo.py` | 42 + 32 | Abandoned dataset-download attempts |

### 2.2 Data flow

```
CESNET flows-*.csv*  ──data_processor──►  processed_data.parquet (label + 30×{size,dir,iat})
                                              │
               ┌──────────────────────────────┼─────────────────────────────┐
        model_pipeline                 retrain_balanced                extract_samples
   rf_model_n{5,10,15,20,30}      overwrites rf_model_n{10,15}       real_samples.json (5 apps)
   + accuracy_vs_n.json           (trained on 100% of data)                 │
               │                              │                             ▼
          visualizer                          ├──────────────► app.py (/predict uses n15)
                                              ▼
                                       live_capture.py (n10 early, n15 final)

live_collector ──► data/live_training_data.csv ──train_live_model──► my_custom_model.joblib
                                                                        └─► live_capture.py --custom
```

Feature vector everywhere is interleaved `[size_0, dir_0, iat_0, size_1, …]`; ordering is consistent between training, the web demo and the live sniffer. `dir` is +1 client→server, −1 server→client, 0 for padding; IAT in ms; size is UDP payload bytes live.

### 2.3 Which model is actually deployed

After running scripts in their documented order, the `models/` directory contains a mix:

| File | Produced by | Held-out score |
|---|---|---|
| `rf_model_n5`, `n20`, `n30` | `model_pipeline.py` (80% train) | Yes, in `accuracy_vs_n.json` |
| `rf_model_n10`, `n15` | `retrain_balanced.py` (100% train) | **None** |
| `my_custom_model` | `train_live_model.py` | Random split on noisy labels |

The two models used by both the web demo and the live sniffer are the ones with no evaluation.

---

## 3. Findings compared against the PDF

### 3.1 PDF claims — verified

| PDF claim | Verdict | Evidence |
|---|---|---|
| Only first 20,000 rows per file; hardcoded Windows paths | Confirmed | `data_processor.py:32,73–74`; `C:\Users\CHATRADHARA\…` also in 5 other files |
| Only the PPI column is used | Confirmed | `data_processor.py:38–56` |
| 100-tree RF, random 80/20 split | Confirmed, and the split is also **not stratified** | `model_pipeline.py:26,30` |
| Accuracy only; no per-class report or confusion matrix | Confirmed | `model_pipeline.py:35` |
| Closed world, 10 classes, no `other` | Confirmed | `CATEGORIES` in `data_processor.py:8`; no rejection in `live_capture.py` beyond colouring |
| `retrain_balanced.py` has no held-out evaluation and overwrites deployed models | Confirmed | `retrain_balanced.py:21,24` |
| Web demo is circular | Confirmed, and **worse than stated**: the demo uses `rf_model_n15`, which after `retrain_balanced.py` was trained on 100% of the parquet, so every demo sample is a training sample | `app.py:10`, `extract_samples.py:8` |
| `generateSimulatedFeatures` / `profiles` are dead code | Confirmed | `script.js:15–51`, never called |
| IPv4 only | Confirmed in both live scripts | `live_capture.py:88`, `live_collector.py:41` |
| Flows never reset or expire; `flows` grows forever | Confirmed; `last_seen_ip` and `dns_cache` also grow forever | `live_capture.py:59–61,141` |
| 3.5 s idle reset in docs but not in code | Confirmed. **Context the PDF lacks:** it existed (commit `0298755`) and was deliberately removed in `7ab1750` together with the ≥1150-byte Initial gate | `git show 7ab1750` |
| Only connection starts are classified | Confirmed (`processed = True`, no reset) | `live_capture.py:164–165` |
| Reverse-DNS labels are hardcoded guesses | Confirmed | `live_capture.py:75–80` |
| Collector mixes TCP + QUIC, background traffic, mid-stream slices | Confirmed; no Initial check, BPF filter is `port 443` | `live_collector.py:47–52,71,162` |
| `train_live_model.py` random split, no comparison to CESNET model | Confirmed | `train_live_model.py:48` |
| `requirements.txt` missing flask/scapy/numpy/joblib; UTF-16 last line | Confirmed, and **worse than stated**: pip rejects the file outright (`Invalid requirement` on line 7), so nothing installs from it. `cesnet-datazoo` is also the abandoned dependency and should not be there. numpy/joblib do arrive transitively via scikit-learn | Tested with `pip install --dry-run -r` |
| `ctypes.windll` crashes on Linux/macOS | Confirmed (`AttributeError` at import) in `live_capture.py`, `live_collector.py`, `train_live_model.py` | Tested on Linux |
| Class imbalance: youtube ≈40.3k, google-play ≈34.3k, whatsapp ≈1.47k | Matches `PROJECT_DOCUMENTATION.md`; not re-verifiable without the parquet | — |

### 3.2 PDF claims — corrections and nuance

1. **File count.** 12 Python files, not 13.
2. **Where `class_weight='balanced'` comes from.** `model_pipeline.py` itself has used `class_weight='balanced'` since commit `842be90`. `retrain_balanced.py`'s only real difference is training on 100% of the data. The PDF's table reads as if balancing were unique to `retrain_balanced.py`.
3. **Provenance of the 97% figures is uncertain.** `accuracy_vs_n.json` is gitignored. The numbers first appear in `PROJECT_DOCUMENTATION.md` (`19dc178`), after `842be90` changed `model_pipeline.py` to balanced weights, but the documentation's Problem 7 describes the pre-balancing model as the one in use at that time, and the balanced retrain was done with `retrain_balanced.py`, not by rerunning `model_pipeline.py`. The table therefore most likely reflects the **unweighted** RF. This should be confirmed when the baseline is rerun (§5).
4. **"Genuine Client Initial" filter is a size heuristic only.** `live_capture.py:129` starts a flow on any client datagram ≥1150 bytes on an unseen 5-tuple. It does not check the QUIC long-header bit or packet type, so large client datagrams in an already-open connection (e.g. uploads after the sniffer starts) are also treated as handshakes.
5. **Idle reset interacts with the Initial gate.** Restoring the 3.5 s reset (PDF Stage 6) will make a reset flow start with a mid-stream packet, which is exactly the "slicing mismatch" `7ab1750` was written to remove. Also, `last_time` is not updated once a flow is `processed` (`live_capture.py:141` returns before line 148), so idle time would be measured from packet 15, not the last packet seen. Stage 6 needs to resolve both.

### 3.3 Additional problems not in the PDF

| # | Problem | Location | Impact |
|---|---|---|---|
| A1 | Debounce keyed on `(server_ip, n)` returns **before** the result is added to `recent_predictions`. Parallel connections to the same Google edge IP within 2 s are dropped from the session vote, which is exactly the case the vote is meant to handle | `live_capture.py:188–191,216–217` | Session view is starved; displayed predictions are a biased subset |
| A2 | Blocking `socket.gethostbyaddr` inside the Scapy callback | `live_capture.py:74,169` | Can stall capture and drop packets on slow reverse DNS |
| A3 | `quic_flow_count` counts packets (incl. dropped mid-stream ones), not flows; the TCP-fallback diagnostic relies on it | `live_capture.py:112,279` | Misleading diagnostic |
| A4 | Custom-model train/serve mismatch: trained on TCP+QUIC mid-stream slices, scored only on UDP flows starting at a ≥1150-byte client packet | `live_collector.py` vs `live_capture.py:129` | `--custom` accuracy is not meaningful |
| A5 | Collector labels are free text (prompt suggests `facebook`), CESNET uses `facebook-web`; no vocabulary check | `live_collector.py:147–149` | Live and CESNET labels cannot be merged without cleanup |
| A6 | Training includes zero-padded short flows; live only ever scores flows with exactly 10/15 real packets | `data_processor.py:53–56` vs `live_capture.py:159–162` | Minor train/serve mismatch |
| A7 | Parse errors are silently swallowed (`except Exception: continue`), no count logged | `data_processor.py:59–60` | Unknown data loss |
| A8 | No `week`/date/file column is kept, so a time-based split is impossible from the current parquet | `data_processor.py:47` | Blocks PDF Stage 5 until Stage 3 changes the processor |
| A9 | Demo covers only 5 of the 10 classes | `extract_samples.py:10`, `index.html:28–32` | Cosmetic |
| A10 | Every script `os.chdir`s into a hardcoded Windows directory; relative `data/`/`models/` paths otherwise | 6 files | Not runnable on any other machine without edits |
| A11 | `app.run(debug=True)` | `app.py:70` | Werkzeug debugger exposed if bound beyond localhost |
| A12 | Lint: 5 unused imports, 2 f-strings without placeholders | pyflakes | Cosmetic |

### 3.4 `PROJECT_DOCUMENTATION.md` vs code

The docs say the dataset is "balanced" (it is not; balancing is by class weight only), that `data_processor.py` uses custom `gzip`/`pyarrow` streaming parsers (it uses `pd.read_csv(nrows=…)`), and that a 3.5 s idle reset is active (removed in `7ab1750`). The documentation should be corrected when the related stages land, not now.

---

## 4. Environment and reproducibility

| Check | Result |
|---|---|
| `python -m py_compile *.py` | All 12 files compile |
| `pip install -r requirements.txt` | **Fails** (UTF-16 line 7) |
| Import of live scripts on Linux | **Fails** (`ctypes.windll`) |
| Data in repo | None (`data/`, `*.parquet` gitignored) |
| Models in repo | None (`models/`, `*.joblib` gitignored) |
| Results in repo | None (`results/` gitignored) |
| CESNET-QUIC22 reachable from the audit sandbox | No (Zenodo blocked by sandbox egress policy) |

Required to reproduce anything: the CESNET-QUIC22 CSV partition for weeks W-2022-44…47 (≈21 GB per the docs), placed where `data_processor.py` expects it.

---

## 5. Baseline

### 5.1 Documented baseline (unverified)

From `PROJECT_DOCUMENTATION.md`; 192,713 flows, 10 classes, random 80/20 split, overall accuracy only.

| N | Features | Reported accuracy |
|---|---|---|
| 5 | 15 | 94.03% |
| 10 | 30 | 96.78% |
| 15 | 45 | 97.07% |
| 20 | 60 | 97.13% |
| 30 | 90 | 96.87% |

Live accuracy baseline: **does not exist.** There is no labelled live test set (that is Stage 1).

### 5.2 Status: blocked in this audit

The baseline could not be re-established here because neither the dataset, the parquet nor the models are in the repository, and the dataset source is unreachable from the audit environment. No retraining was attempted on substitute data, since that would not be the existing baseline.

### 5.3 To confirm the baseline on the project machine (no code changes)

1. Record the parquet's identity: row count, per-class counts, and file hash (`certutil -hashfile data\processed_data.parquet SHA256`).
2. Back up the current `models/` directory (the n10/n15 files will be overwritten).
3. Run `python model_pipeline.py` exactly as-is. Compare `results/accuracy_vs_n.json` to §5.1. Because `model_pipeline.py` now uses balanced weights, a difference from §5.1 would confirm point 3.2(3).
4. Note that step 3 replaces the 100%-data n10/n15 models with 80%-data ones; restore the backup if the current live behaviour must be preserved.
5. Record the scikit-learn, pandas and Python versions used.

Record the results in this file under §5.1 before starting Stage 1.

---

## 6. Recommended housekeeping (still not done; not required by Stage 1)

These are housekeeping items that make every later stage runnable; they were identified here but intentionally not applied:

- Rewrite `requirements.txt` as UTF-8 with flask, scapy, numpy, joblib; drop `cesnet-datazoo`.
- Guard `ctypes.windll` behind `if os.name == "nt"`.
- Replace hardcoded `os.chdir`/paths with CLI arguments or a single config.
- Decide the fate of `fetch_zenodo.py`, `test_datazoo.py` and the dead JS.

---

## 7. Stage 1 — SNI auto-labelled live test set

**Status: In progress — tooling done and validated; waiting for real captures.**
Stage 1 is not complete. It completes only when real captures from your machine reach the targets in §7.8. No BigPAC live data exists yet.

Date: 2026-09-24 · Plan reference: PDF "Improvement plan", step 1

### 7.1 Files added (uncommitted)

| File | Purpose |
|---|---|
| `pcap_to_dataset.py` | `convert` captures to labelled rows; `report` progress per app |
| `tests/test_pcap_to_dataset.py` | 9 portable unit tests (no tshark needed) |
| `tests/make_quic_fixture.py` | Generates a synthetic loopback QUIC capture for end-to-end testing (Linux, root, aioquic) |
| `tests/fixtures/quic_loopback_fixture.pcapng` (+ `.truth.json`) | The synthetic capture used for validation (289 KB). **Test fixture only, not BigPAC data** |
| `docs/STAGE1_CAPTURE_GUIDE.md` | Capture, convert, spot-check and progress procedure for your Windows machine |

No existing file was modified. `live_collector.py` still exists; the PDF says the new converter replaces it, and removing it is left for your decision.

### 7.2 Output format: `data/live_labelled.csv`

Meta columns: `label, sni, network, capture_day, flow_start_utc, source, source_sha256, ip_version, server_ip, quic_version, n_client_initials, n_pkts, converter_version`, then the 90 columns `pkt_size_i, pkt_dir_i, pkt_iat_i` for i = 0…29.

Feature conventions match `processed_data.parquet` and `live_capture.py`: size = UDP payload bytes, dir = +1 client→server / −1 server→client / 0 padding, IAT in ms since the previous packet in the flow (first = 0), padded to 30. IATs are kept to 3 decimals (µs); CESNET's IAT resolution has not been checked yet (a Stage 2 question). The client IP is not stored.

### 7.3 Deviations from the PDF's script (and why)

1. **A flow start must be a real QUIC Initial**, read from the long header by tshark, plus ≥1150 bytes client→server. The PDF (and `live_capture.py`) check size only, which accepts any large client packet on an unseen 4-tuple (Stage 0 finding 3.2-4). Such rejections are counted as `rejected_large_non_initial`. QUIC v2 numbers its packet types differently and is handled.
2. **ICMP/ICMPv6 errors quoting UDP:443 are excluded**; otherwise their embedded headers would be read as packets.
3. **ECH outer names (`cloudflare-ech.com`) are skipped and counted**, not labelled `other`, because the real destination is unknown.
4. **Extra columns for later stages**: `capture_day` and `network` (the PDF wants a split by capture day and home/campus coverage), `n_client_initials` (direct evidence for drift cause 2, the split post-quantum ClientHello), `ip_version` (cause 6), and `source_sha256` + `converter_version` for provenance.
5. **Duplicate protection**: a capture already in the CSV (same SHA-256 prefix) is skipped unless `--force`.
6. **CLI** with `--network`, `--min-pkts` (default 15, as in the PDF), `--idle` (default 30 s, as in the PDF), `--tshark`, `--out`; Windows tshark path auto-detected.
7. `APP_RULES` gained `youtube-nocookie.com` and `play.google.com`; otherwise identical to the PDF.

### 7.4 Commands executed (sandbox, Ubuntu 24.04, Python 3.12, TShark 4.2.2, aioquic 1.3.0)

```
python3 -m pytest -q tests
python3 tests/make_quic_fixture.py tests/fixtures/quic_loopback_fixture.pcapng
python3 pcap_to_dataset.py convert tests/fixtures/quic_loopback_fixture.pcapng --network sandbox-loopback --out /tmp/val.csv
python3 pcap_to_dataset.py convert tests/fixtures/quic_loopback_fixture.pcapng --network sandbox-loopback --out /tmp/val.csv   # duplicate check
python3 pcap_to_dataset.py report --csv /tmp/val.csv
python3 -m pyflakes pcap_to_dataset.py tests/*.py
```
plus an ad-hoc Scapy script that re-read the fixture independently and compared every feature value with the CSV rows (not committed).

### 7.5 Datasets used

Only the synthetic fixture `tests/fixtures/quic_loopback_fixture.pcapng`, SHA-256 `493d534fc49e2c5986bb7dca494fa90667d49171cfd138ca5ef9a51255ae8e78`: aioquic client and server on 127.0.0.1:443, 5 connections, 264 datagrams. The validation output went to `/tmp/val.csv` and was discarded. No CESNET data and no real traffic were used.

### 7.6 Validation results (tooling only — these are not model or dataset results)

| Check | Result |
|---|---|
| Unit tests (flow start rules, mid-stream drop, idle split, 30-packet cap, split ClientHello count, IPv6 keys, SNI mapping incl. suffix traps, row shape) | 9/9 pass |
| End-to-end labels vs fixture truth | 5/5 correct: `googlevideo.com` → youtube; `scontent.cdninstagram.com` → instagram; `www.example.org` → other; `cloudflare-ech.com` → skipped (ECH); 50-byte transfer → skipped (short) |
| ClientHello split across two Initials (padded ALPN, mimicking Chrome's post-quantum case) | SNI recovered; `n_client_initials = 2` |
| Feature values vs independent Scapy parse | 270/270 values match (3 flows × 30 packets × size/dir/IAT) |
| Re-converting the same capture | Refused ("nothing new to convert") |
| pyflakes on new files | Clean |

### 7.7 Not validated yet (known gaps)

- **Real Chrome traffic.** The fixture is aioquic, not Chrome. Real post-quantum ClientHellos, 0-RTT, connection migration and ECH have not been seen by the converter. The first real capture must be spot-checked (guide §4).
- **IPv6 end-to-end.** The sandbox has no IPv6; IPv6 is covered by the unit test only (the IPv6 fixture case is skipped automatically where IPv6 is unavailable).
- **Windows.** Code avoids Windows-specific pitfalls (no `ctypes.windll`, UTF-8 I/O, default tshark path) but has not been run on Windows.
- **Idle timeout.** 30 s is the PDF's value; its effect on real traffic has not been measured.

### 7.8 Completion criteria (from the PDF)

At least **200 flows per app**, collected over **several days** on **home and campus** networks, with the first capture spot-checked. At least one capture day should be available to hold out for Stage 5. Record the `report` output here when met.

### 7.9 Open decisions for you

1. Apps that cannot reach 200 QUIC flows from your devices (likely whatsapp and spotify from a desktop browser; possibly discord because of ECH): collect from a phone via hotspot, accept a smaller count and flag it, or exclude the app from Stage 2. Record the choice here.
2. Whether to delete `live_collector.py` and `train_live_model.py` now that the converter replaces them, or keep them until Stage 2 has compared against the old custom model.

### 7.10 Blockers

Stage 1 cannot finish in this environment: it needs days of real captures from your laptop (and optionally phone). Stage 2 stays gated until then. The Stage 0 CESNET baseline (§5) is also still unconfirmed; it should be recorded before Stage 2 compares CESNET against live accuracy.

### 7.11 Exact next action

1. Commit the files in §7.1 and this file.
2. On your laptop: `python -m pytest tests` (or `python tests/test_pcap_to_dataset.py`), then `python pcap_to_dataset.py convert tests\fixtures\quic_loopback_fixture.pcapng --network fixture --out %TEMP%\fixture.csv` to confirm the converter and tshark work on Windows (expect `written=3`).
3. Capture ~30 minutes of normal use (guide §2), convert it, and spot-check 3–5 flows in Wireshark (guide §4). Report the `convert` counters and any mismatch.
4. If the spot-check passes, collect over several days and networks until §7.8 is met, then share the `report` output.
