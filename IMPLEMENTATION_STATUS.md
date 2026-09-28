# BigPAC — Implementation Status

Reference plan: *BigPAC Project Analysis & Model Improvement Plan* (2026-09-24)
Repository base: commit `7ab1750` (HEAD of `main`, 2026-09-18); files added since then are listed per stage and are not yet committed.
Last updated: 2026-09-27 (§13, live SNI and hybrid mode)

| Session | Date | Work |
|---|---|---|
| 1 | 2026-09-24 | Stage 0 audit (read-only) |
| 2 | 2026-09-24 | Stage 1 tooling: converter, tests, capture guide |
| 3 | 2026-09-24 | Stage 1: first real capture converted (§7.12) |
| 4 | 2026-09-27 | Stage 1: cumulative report after 2 days / 3 networks (§7.13) |
| 5 | 2026-09-27 | Stage 1 frozen (deadline); Stage 2 baseline measured (§8) |
| 6 | 2026-09-27 | Deadline build: Stages 3–6 compressed into one session (§9) |
| 7 | 2026-09-27 | Live demo feedback: YouTube → `other` diagnosed (§10) |
| 8 | 2026-09-27 | Phone-data / model-type ablation; final-run protocol fixed (§11) |
| 9 | 2026-09-27 | Labelling bug fixed (Instagram CDN → facebook-web); `relabel` and `merge` added (§12) |
| 10 | 2026-09-27 | Live SNI reading: model vs truth on screen, optional hybrid mode (§13) |

---

## 1. Stage tracker

| Stage | Plan step (from PDF) | Status |
|---|---|---|
| 0 | Repository audit and baseline | **Done (audit) / Blocked (baseline numbers)** — see §5 |
| 1 | SNI auto-labelled live test set (`pcap_to_dataset.py`) | **Frozen early by user decision (submission deadline); targets not met** — see §7.14 |
| 2 | Measure the gap (`eval_live.py`, per-class report, shift AUC) | **Done (baseline measured)** — see §8 |
| 3 | `other` class + unknown threshold; `week` column; chunked reading | **Partial** — `other` (live only) + UNKNOWN threshold done; CESNET-side items not done (§9.2) |
| 4 | Shared drift-robust `features.py` | **Done** (§9.3) |
| 5 | Time-based split + retrain with live data (`train_v2.py`) | **Partial** — live held-out-by-capture done; CESNET time split impossible (§9.4) |
| 6 | Sniffer fixes: IPv6, idle reset, expiry, shared features | **Done in new file `live_capture_v2.py`**; not yet run live on a real network (§9.6) |
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
2. On your laptop: `python -m pytest tests` (or `python tests/test_pcap_to_dataset.py`), then `python pcap_to_dataset.py convert tests\fixtures\quic_loopback_fixture.pcapng --network fixture --out $env:TEMP\fixture.csv` (PowerShell; `%TEMP%` only works in cmd, and in PowerShell it creates a literal `%TEMP%` folder) to confirm the converter and tshark work on Windows (expect `written=3`).
3. Capture ~30 minutes of normal use (guide §2), convert it, and spot-check 3–5 flows in Wireshark (guide §4). Report the `convert` counters and any mismatch.
4. If the spot-check passes, collect over several days and networks until §7.8 is met, then share the `report` output.

### 7.12 Real capture log

Status after this entry: Stage 1 still **in progress** (first capture converted; spot-check and most apps still pending).

**Capture 1** — 2026-09-24, network `home-laptop`, Wi-Fi, `data/captures/home-laptop.pcapng` (~260k UDP:443 packets per tshark's counter). Browser appears to be Brave (Chromium-based), inferred from a `brave-core-ext.s3.brave.com` SNI; to be confirmed by the user.

Commands (user's Windows machine):
```
"C:\Program Files\Wireshark\tshark.exe" -i 5 -f "udp port 443" -w "data\captures\home-laptop.pcapng"
python pcap_to_dataset.py convert data\captures\home-laptop.pcapng --network home-laptop
python pcap_to_dataset.py report
```

`report` output (as reported by the user):

| app | flows | IPv6 | 2+ client Initials |
|---|---|---|---|
| youtube | 77 | 77 | 77 |
| google-play | 3 | 3 | 3 |
| discord | 3 | 0 | 3 |
| snapchat | 31 | 6 | 31 |
| instagram, facebook-web, whatsapp, spotify, tiktok, microsoft-outlook | 0 | — | — |
| other | 290 | 237 | 290 |
| **total** | **404** | | |

Not yet recorded: the `convert` counters (`skip_no_sni`, `skip_ech_hidden`, `skip_short`, `dropped_midstream`, `rejected_large_non_initial`), the capture file's SHA-256, the tshark version on the user's machine, and the result of the unit tests on Windows.

Observations (one capture, one day, one network — early evidence, not the Stage 2 measurement):
- **IPv6:** 77/77 youtube flows were IPv6. `live_capture.py` is IPv4-only (Stage 0, §3.1), so it cannot have seen any of them. Supports PDF cause 6.
- **Split ClientHello:** all 404 flows had ≥2 client Initial packets before the first server packet. Supports PDF cause 2. (The count could in principle include Initial retransmissions; the Wireshark spot-check should confirm on a few flows.)
- **Open world:** 290/404 (72%) of flows are `other`. Supports PDF cause 1.

Labelling decision pending: whether `yt3.ggpht.com` (YouTube channel images) counts as youtube. `APP_RULES` unchanged until decided. The other top `other` SNIs (Google accounts, ads, analytics, fonts, gstatic, NEL beacons) stay `other`.

Next action: send the `convert` output, do the Wireshark spot-check (guide §4) on at least one youtube and one snapchat flow, confirm `9 passed` on Windows, then continue capturing with deliberate use of the apps that have 0 flows.

### 7.13 Cumulative report (2026-09-27)

Status: Stage 1 still **in progress**. Target (§7.8) met for youtube only.

`report` output as shown by the user (screenshot); capture file list, hashes and `convert` counters not yet provided:

| app | flows | days | nets | IPv6 | 2+ client Initials |
|---|---|---|---|---|---|
| youtube | 224 | 2 | 3 | 0 | 224 |
| google-play | 45 | 2 | 2 | 0 | 44 |
| instagram | 93 | 2 | 3 | 0 | 89 |
| facebook-web | 109 | 2 | 3 | 0 | 102 |
| whatsapp | 98 | 2 | 2 | 0 | 80 |
| discord | 18 | 1 | 1 | 0 | 18 |
| spotify | 191 | 1 | 1 | 0 | 191 |
| snapchat | 52 | 2 | 2 | 0 | 40 |
| tiktok | 0 | 0 | 0 | 0 | 0 |
| microsoft-outlook | 0 | 0 | 0 | 0 | 0 |
| other | 1118 | 2 | 3 | 0 | 1117 |

**Inconsistency to resolve before Stage 1 can close:** IPv6 = 0 for every app, but capture 1 (§7.12) had 77 IPv6 youtube flows. Either capture 1's rows are no longer in `data/live_labelled.csv`, or the new captures are all IPv4. The user has been asked which. If capture 1 was removed, it should be re-converted (the pcap is the raw evidence).

Observations (not yet the Stage 2 measurement):
- Not every flow now has 2+ client Initials (whatsapp 80/98, snapchat 40/52, instagram 89/93, facebook-web 102/109), unlike capture 1 (404/404). Plausibly a different client (e.g. phone apps), unconfirmed; networks per capture are not yet recorded here.
- `other` is 1118 of 1948 flows (57%).

App-specific blockers:
- **tiktok**: 0 flows. TikTok has been banned in India since 2020, and a VPN would hide the QUIC traffic. Proposed: exclude from the live test set and state this in the write-up. Awaiting the user's decision.
- **microsoft-outlook**: 0 flows. Suspected `APP_RULES` gap (Outlook on the web is served from `outlook.cloud.microsoft`, which is not in the rules) and/or the client using TCP. Awaiting `report --top 80` to check. `APP_RULES` unchanged.
- **discord**: 18 flows; suspected ECH. Awaiting the `convert` counter `skip_ech_hidden`.

Still outstanding from §7.12: Wireshark spot-check, unit tests on Windows (`9 passed`), `yt3.ggpht.com` labelling decision, browser (Brave vs Chrome).

Decision requested from the user: **Option A** — 2–3 more capture days targeting google-play, discord, snapchat, instagram, whatsapp and facebook-web, including at least one new day for a Stage 5 hold-out, then freeze; or **Option B** — freeze now, flag apps under ~50 flows as low-confidence, exclude tiktok and microsoft-outlook.

Exact next action: resolve the IPv6 inconsistency, send `report --top 80` and one `convert` output, complete the spot-check, and choose A or B.

### 7.14 Freeze (2026-09-27)

Stage 1 was **frozen by the user's decision** because the model must be submitted on 2026-09-28. This is Option B from §7.13. The §7.8 targets were **not** met; only youtube reached 200 flows. Consequences, to be stated in any write-up:

- tiktok (0 flows; banned in India) and microsoft-outlook (0 flows) have **no live test data**.
- discord (18) and google-play (45) are low-confidence classes.
- The Wireshark spot-check (guide §4) was not reported as done.
- The IPv6 capture from 2026-09-24 (§7.12) is **not** in the frozen dataset; all frozen flows are IPv4.

Frozen dataset: `data/live_labelled.csv`, SHA-256 prefix `ecddb8802868b345`, 1,948 flows, converter `stage1-v1`:

| source capture | flows | capture_day | network |
|---|---|---|---|
| `home-laptop_00001_20260926203149.pcapng` | 415 | 2026-09-26 | home-laptop |
| `home-laptop-session2_00001_20260926210939.pcapng` | 504 | 2026-09-26 | home-laptop |
| `home-laptop-session3_00001_20260926221146.pcapng` | 779 | 2026-09-26 | home-laptop |
| `test-1min.pcapng` | 70 | 2026-09-26 | test-laptop |
| `home-phone-session1_00001_20260927132855.pcapng` | 180 | 2026-09-27 | home-phone |

Labels: other 1118, youtube 224, spotify 191, facebook-web 109, whatsapp 98, instagram 93, snapchat 52, google-play 45, discord 18. Note: the two capture days are also two different devices (laptop vs phone), so a split "by day" is really a split by device.

---

## 8. Stage 2 — Measure the real gap

**Status: Done (baseline measured).** Date: 2026-09-27. Plan reference: PDF step 2.

### 8.1 Files added (uncommitted)

`eval_live.py` (PDF's evaluation plus confusion matrix, open-world accuracy, per-network accuracy and confidence summary), `results/stage2_baseline.txt` (full printed report), `results/stage2_baseline.json`.

### 8.2 Experiment record

| Item | Value |
|---|---|
| Command | `python eval_live.py data/live_labelled.csv data/processed_data.parquet models/rf_model_n15.joblib` |
| Model | `rf_model_n15.joblib` as deployed (SHA-256 prefix `96975ff7c785b0ac`): RandomForest, 100 trees, `class_weight='balanced'`, 45 raw features, 10 classes. Per Stage 0 §2.3 this is the `retrain_balanced.py` model trained on 100% of CESNET |
| Live data | frozen set, §7.14 (`ecddb8802868b345`) |
| CESNET data | `processed_data.parquet`, SHA-256 prefix `61af198d10b00b55`, 192,713 flows × 91 columns (no week column) |
| Features | raw `pkt_{size,dir,iat}_{0..14}` (feature version "raw-v0") |
| Shift check | RF 200 trees, seed 0; CESNET sample = 5 × live size, seed 0; 5-fold ROC AUC |
| Environment | sandbox, Python 3.12, scikit-learn 1.8.0 (model loaded without version warnings) |

### 8.3 Results (measured)

| Measurement | Value |
|---|---|
| Accuracy, live flows of the 8 apps present (closed world, n = 830) | **30.8%** |
| Macro F1, same flows | **0.241** |
| Accuracy, all live flows (open world, n = 1,948; model has no `other`) | **13.1%** |
| Shift AUC, CESNET vs live | **0.9999** |
| Reported CESNET accuracy for comparison (Stage 0, unverified) | 97.07% |

Per class (precision / recall / F1, support): discord 1.000 / 0.667 / 0.800 (18); facebook-web 0.033 / 0.009 / 0.014 (109); google-play 0.053 / 0.222 / 0.086 (45); instagram 0.165 / 0.151 / 0.157 (93); snapchat 0.333 / 0.135 / 0.192 (52); spotify 0.278 / 0.052 / 0.088 (191); whatsapp 0.000 / 0.000 / 0.000 (98); youtube 0.441 / 0.902 / 0.592 (224).

- `other` flows (1,118) were predicted as youtube 806, google-play 154, spotify 90, discord 58, instagram 6, snapchat 4.
- Spotify flows were mostly predicted as google-play (116/191); facebook-web, instagram and whatsapp flows were mostly predicted as youtube or each other.
- Per network: home-laptop 31.2% (n = 724), home-phone 26.4% (n = 91), test-laptop 40.0% (n = 15).
- Mean top-class probability: 0.337 when correct, 0.301 when wrong, 0.288 on `other` flows. **Confidence barely separates right from wrong**, so a confidence threshold alone cannot rescue this model.

### 8.4 What drifted (evidence for PDF causes 2 and 3)

The top shift features are `pkt_iat_1`, `pkt_size_1`, `pkt_iat_3`, `pkt_size_2`, `pkt_dir_1`, i.e. the second and third packets, which is where the split ClientHello lands. Direct check:

| | CESNET | Live |
|---|---|---|
| Packet 1 is client→server (`pkt_dir_1 = +1`) | 42.1% | 98.0% |
| Median `pkt_iat_1` | 3 ms | 0.041 ms |
| Median first-packet size | 1250 | 1250 |

CESNET IATs are **integer milliseconds** (e.g. 0, 100, 3), while the live converter keeps microseconds. Live IATs below 1 ms therefore have no CESNET equivalent; rounding live IATs to integer ms is a required alignment step before any combined training.

### 8.5 Conclusion

The 97% CESNET figure does not transfer: the deployed model reaches 30.8% on known apps and 13.1% on all live traffic, and CESNET and live flows are almost perfectly separable (AUC 0.9999). This is the baseline every later model must beat, measured on the same frozen live set.

### 8.6 Next action

Superseded by §9 (deadline build).

---

## 9. Deadline build — Stages 3–6 compressed (2026-09-27)

**Why:** the trained model and a demo must be submitted on 2026-09-28. At the user's request, Stages 3–6 were done in one session instead of one at a time. The stage gates were relaxed deliberately. Everything below was run; nothing is estimated. Training and the demo will be re-run by teammates on their own machines (§9.8).

### 9.1 Files (uncommitted)

| File | Status | Purpose |
|---|---|---|
| `features.py` | new | Stage 4 features, shared by training, sniffer and web app |
| `train_v2.py` | new | Stages 3–5: training, model selection, threshold, evaluation, saving |
| `live_capture_v2.py` | new | Stage 6 sniffer (old `live_capture.py` left unchanged as the "before" version) |
| `app.py`, `static/index.html`, `static/script.js` | rewritten | Web demo on held-out live flows (old version in git history) |
| `static/style.css` | appended | Styles for the new elements |
| `tests/test_features.py`, `tests/test_live_consistency.py` | new | Feature correctness; training/sniffer consistency |
| `requirements.txt` | rewritten | UTF-8, all dependencies (fixes Stage 0 finding) |
| `.gitignore` | edited | `results/` is now committed |
| `README.md`, `docs/RUN_AND_DEMO_GUIDE.md` | new | Overview; teammates' setup/train/demo guide |
| `results/stage5_train_v2.{txt,json}` | new | Reference run output |

Not changed: the original CESNET pipeline, `live_capture.py`, `live_collector.py`, `train_live_model.py`, `PROJECT_DOCUMENTATION.md`.

### 9.2 Stage 3 — `other` class and UNKNOWN

- **Done:** an 11th class `other`, trained from the live non-target flows; an UNKNOWN output when the top probability is below a threshold chosen on training captures only.
- **Not done:** CESNET `other` flows, the `week` column and chunked reading in `data_processor.py`. All three need the raw CESNET CSV files, which are not available (only the processed parquet). Consequence: `other` is learned from 689 live flows only.
- Threshold selection maximises out-of-fold open-world macro-F1. The PDF's example rule (≥90% precision on known apps) was not used, because out-of-fold precision never reached it. Chosen: **0.30**. The curve is nearly flat below 0.40, so the threshold changes little (UNKNOWN on 0.6% of test flows).

### 9.3 Stage 4 — `features.py` (feature version `aligned-v1`, 45 features)

- The window starts at the first server reply: 12 packets × (size, dir, log1p(IAT)).
- IATs are rounded to whole ms (the CESNET resolution, §8.4).
- 9 aggregates, including `n_client_before_server`.
- A no-IAT variant (44 features) is also available.

Verified:
- Vectorised output equals a plain per-flow reference implementation on 1,948 live and 3,000 CESNET flows (0 mismatches).
- `tests/test_features.py`: 4/4 pass.
- A split ClientHello changes only `n_client_before_server`.

### 9.4 Stage 5 — training and evaluation (`python train_v2.py`)

| Item | Value |
|---|---|
| Environment (reference run) | sandbox, Python 3.12.3, scikit-learn 1.8.0, numpy 2.4.4, pandas 3.0.2, 1 CPU |
| Live data | frozen set §7.14 (`ecddb8802868b345`) |
| Held-out live test | whole capture `home-laptop-session3_00001_20260926221146.pcapng`, 779 flows. Chosen because it is the only session containing all 8 live apps. Chosen before training, from label counts only |
| Live training | the other 4 captures, 1,169 flows (other 689, youtube 144, spotify 92, facebook-web 78, instagram 61, whatsapp 61, google-play 31, snapchat 13; **discord 0**) |
| CESNET | parquet `61af198d10b00b55`; stratified random 80/20, seed 0 (no week column, so no time split); training capped at 5,000 flows/app → 42,578; test 38,543 |
| Weights | `balanced` class weights; live flows × 5 (PDF value) |
| Model selection | 3-fold GroupKFold by capture on training captures only (folds: session2 / session1 / phone + test-1min) |
| Candidates | RF 200 trees, min_samples_leaf 2, with IAT; HistGradientBoosting (300 iter, early stopping) with and without IAT; seed 0 |

Out-of-fold selection results (training captures only):

| Candidate | known acc | known macro-F1 | open acc | open macro-F1 |
|---|---|---|---|---|
| **rf_iat (selected)** | 0.346 | 0.333 | 0.676 | 0.380 |
| hgb_iat | 0.327 | 0.293 | 0.671 | 0.343 |
| hgb_noiat | 0.273 | 0.279 | 0.636 | 0.328 |

Removing IAT lowered every metric for HGB, so timing still helps after alignment. The PDF's "try without IAT" question is answered for this data.

**Final evaluation — held-out capture, evaluated once:**

| Model | known acc | known macro-F1 | open acc | open macro-F1 |
|---|---|---|---|---|
| Old `rf_model_n15` | 0.254 | 0.184 | 0.114 | 0.121 |
| **v2 (rf_iat, threshold 0.30)** | **0.514** | **0.462** | **0.765** | **0.496** |

Per class for v2 (precision / recall, support):

| App | Precision | Recall | Support |
|---|---|---|---|
| whatsapp | 0.750 | 0.811 | 37 |
| instagram | 0.676 | 0.719 | 32 |
| facebook-web | 0.778 | 0.677 | 31 |
| spotify | 0.901 | 0.646 | 99 |
| youtube | 0.933 | 0.525 | 80 |
| other | 0.745 | 0.963 | 429 |
| discord | 0 | 0 | 18 |
| snapchat | 0 | 0 | 39 |
| google-play | 0 | 0 | 14 |

The main remaining error is **app flows predicted as `other`**: youtube 38/80, spotify 33/99, snapchat 38/39, all 18 discord, 13/14 google-play. Apps with little or no live training data are not recognised live.

CESNET test split for v2: accuracy **0.956**, macro-F1 0.849 (0.008% of flows predicted `other`).

Output: `models/bigpac_v2.joblib` (29 MB, SHA-256 prefix `b9f5bd98918b9be6`, reference run), `data/demo_samples.json` (the 779 held-out flows), `results/stage5_train_v2.{txt,json}`. Runtime 90 s.

**Honesty notes:**
- No hyperparameter or design change was made after the test result was seen.
- The held-out session is from the same evening, network and laptop as three training sessions, so this is an **optimistic** live estimate; a different day or network has not been tested.
- Discord has no live training data.
- TikTok and Outlook have no live test data.

**Reproducibility check:** `bigpac_code.zip` was unpacked into an empty folder and given only the two data files. `python train_v2.py --old-model none` then reproduced **identical** metrics (selected rf_iat, threshold 0.30, known 0.514, open 0.765) in 90 s. The model file hash differs from the reference run (`644f51be504a20b6` vs `b9f5bd98918b9be6`) only because the bundle stores its training timestamp.

### 9.5 Web demo (`app.py`)

- The page replays random held-out flows, shows the prediction, correct/wrong against the SNI label, and the measured results table (`/results` reads `results/*.json`).
- Tested with Flask's test client: all endpoints respond correctly, including error cases.
- **Running all 779 demo flows through `/predict` reproduces the held-out result exactly (known 0.514, open 0.765).**

### 9.6 Stage 6 — `live_capture_v2.py`

What it does:
- IPv4 **and IPv6**.
- A flow starts only on a real QUIC Initial (long-header check, v1 and v2) of ≥1150 bytes.
- One prediction per connection, once `features.ready()` or at 30 packets.
- Outputs app / `other` / UNKNOWN with top-3.
- A 30-second "apps seen" summary replaces the buggy debounced session vote (Stage 0 finding A1).
- Flows idle for 60 s are expired.
- No reverse-DNS lookups (Stage 0 finding A2).
- Guarded Windows console code.
- Warns if the scikit-learn version differs from the training version.
- Predictions are logged to `results/live_predictions.csv`.
- `--pcap` replay mode.

Not done:
- The 3.5 s idle reset. It is deliberately omitted: the design is one prediction per connection, and a reset would restart mid-stream (Stage 0 §3.2-5).
- Classifying later traffic on long-lived connections (PDF cause 5) remains open.

Verified:
- `tests/test_live_consistency.py`: flows sniffed by Scapy produce **identical** feature vectors to `pcap_to_dataset.py` + `features.py` on the fixture.
- `--pcap` replay runs end to end.

**Not verified:**
- Live sniffing on Windows / Npcap, or on any real network (the sandbox has neither).
- IPv6 live (the sandbox has no IPv6).

### 9.7 Tests at end of session

| Test | Result |
|---|---|
| `tests/test_pcap_to_dataset.py` | 9 passed |
| `tests/test_features.py` | 4 passed |
| `tests/test_live_consistency.py` | passed (3 flows identical) |
| pyflakes on new and changed Python files | clean |

### 9.8 Pending (teammates, before submission)

1. Commit everything in §9.1.
2. On the training machine: `python train_v2.py`. Record its printed FINAL EVALUATION numbers and scikit-learn version here. They may differ slightly from the reference run.
3. Run the web demo and the live demo on the demo laptop (same scikit-learn version as training). Record whether live sniffing works and whether IPv6 flows appear.

### 9.9 Open after the deadline

- More live data for discord, snapchat and google-play, plus captures on another day and network for a less optimistic test.
- CESNET-side Stage 3 items (needs raw CSVs).
- Stage 7 (1D-CNN) not started.
- Stage 0 baseline reproduction (§5) still unconfirmed.

---

## 10. Live demo feedback — YouTube predicted as `other` (2026-09-27)

**Observation:** the user ran `live_capture_v2.py` live on the home network, Windows, as Administrator (screenshots, 16:58–16:59).
- It works live.
- **Almost all connections were IPv6.**
- WhatsApp and Facebook connections (to Meta servers) were predicted correctly.
- While a YouTube video played, most new connections to Google servers were predicted `other`.

**Measured diagnosis** (held-out capture session3, reference model, `diagnose_capture.py` plus an ad-hoc breakdown):

| YouTube connection type (by SNI) | Flows | Predicted youtube |
|---|---|---|
| Video stream (`*.googlevideo.com`) | 33 | 90.9% |
| Thumbnails (`i.ytimg.com`) | 16 | 43.8% |
| Page / API (`www.youtube.com`, `accounts.youtube.com`, `suggestqueries-clients6.youtube.com`) | 31 | 16.1% |

- 74.7% of all `other` flows in the live set are Google-owned: google.com 234, googleapis.com 187, doubleclick 83, gstatic 76, and others.
- YouTube page/API connections terminate on the same Google front-end as those services, so their first packets are nearly identical.
- **Conclusion:** the YouTube video stream is recognised; YouTube page connections are largely indistinguishable from other Google services by early-packet features. This is a limitation of the approach, not a bug.

**IPv6 gap (hypothesis, untested):**
- The frozen training data has 0 IPv6 flows, but live demo traffic on the home network is now mostly IPv6.
- IPv6 lowers the QUIC payload size available per datagram, so packet sizes may shift.
- This will be tested with today's new captures, which include IPv6.

**Changes:**
- `train_v2.py`: the bundle stores `train_sources`, and the held-out evaluation prints a breakdown by `ip_version` and `network`. Metrics are unchanged.
- `diagnose_capture.py` (new): per-app accuracy, per-IP-version accuracy, and the server name of every misclassified app flow for a chosen capture. It warns if that capture was used in training.

**Decision not taken:** redefining `youtube` as video-stream connections only. That would be a label change made after seeing results. It is only acceptable if decided before evaluating on the new test session, and it must be reported as such.

**Demo guidance:** start the sniffer before opening a new video (the video connection is opened at playback start), and point to the `youtube` lines and the 30-second summary.

---

## 11. Ablation: phone data and model type (2026-09-27)

**Trigger:** in the live demo (laptop, Chrome, IPv6), YouTube search pages and the Snapchat web login page produced mostly `other`. The user suspected the phone captures in training, since the demo is laptop-only.

**Screenshot reading:**
- Nearly all classified connections went to Google address space (`2404:6800::/32`, `2001:4860::/32`).
- No video was playing (search results page), and Snapchat was at its login page, so neither page produced app-specific traffic.
- Consistent with §10.

**Experiment:** `train_v2.py` rerun with the phone capture removed (180 flows) and/or a fixed model type. Everything else as in §9.4 (seed 0, same splits, same held-out session3). Diagnostic only; not selected by out-of-fold score.

| Training live data | Model | Held-out known acc | known macro-F1 | open acc | open macro-F1 |
|---|---|---|---|---|---|
| all captures (reference, §9.4) | RF (selected OOF) | 0.514 | 0.462 | 0.765 | 0.496 |
| all captures | HGB | 0.571 | 0.521 | 0.783 | 0.548 |
| without phone | RF | 0.537 | 0.482 | 0.772 | 0.512 |
| **without phone** | **HGB (selected OOF)** | **0.609** | **0.537** | **0.802** | **0.563** |

Per-app recall, without phone + HGB vs reference:

| App | Reference | Without phone + HGB |
|---|---|---|
| youtube | 0.53 | 0.69 |
| spotify | 0.65 | 0.76 |
| instagram | 0.72 | 0.84 |
| facebook-web | 0.68 | 0.61 |
| whatsapp | 0.81 | 0.97 |
| snapchat | 0.00 | 0.03 |
| google-play | 0.00 | 0.07 |
| discord | 0.00 | 0.00 |
| other | 0.97 | 0.96 |

Commands (sandbox, scikit-learn 1.8.0):
```
python train_v2.py --old-model none --live data/no_phone.csv
python train_v2.py --old-model none --live data/no_phone.csv --candidates rf_iat
python train_v2.py --old-model none --candidates hgb_iat
python train_v2.py --old-model none --exclude-network home-phone --candidates hgb_iat   # reproduces row 4 exactly
```

**Interpretation:**
- Both changes help, and the effects roughly add up: removing phone data gives +2 to +4 points; HGB instead of RF gives +5 to +7 points (known-app accuracy).
- The test session has 350 app flows (binomial SE ≈ 2.7 points), so the phone effect alone is within noise.
- The earlier out-of-fold selection preferred RF by a small margin on small folds.

**Consequence for honesty:**
- These choices were made after seeing session3 results, so **session3 is now a validation set, not a test set**, and its numbers above are optimistic.
- The final reported result must come from a new, unseen laptop session.

### 11.1 Final-run protocol (fixed before the final test session is recorded)

1. Training live data: laptop captures only (`--exclude-network home-phone`); session3 joins training.
2. Model: HGB with IAT (`--candidates hgb_iat`). The threshold is still chosen out-of-fold on training captures.
3. Test: the new laptop-only session recorded last on 2026-09-27, passed as `--test-source <file>`. It is not to be changed after results are seen.
4. Command:
   ```
   python train_v2.py --exclude-network home-phone --candidates hgb_iat --test-source <final session file>
   ```
5. Report its FINAL EVALUATION block, the per-IP-version breakdown, and `diagnose_capture.py <final session file>`, alongside the §9.4 and §11 numbers (clearly labelled as validation).

**Changes:** `train_v2.py` gained `--exclude-network`. Defaults are unchanged, so earlier commands still reproduce §9.4.

---

## 12. Labelling bug: Instagram media labelled `facebook-web` (2026-09-27)

**Report:** in the live demo, Instagram usage appeared as Facebook.

**Cause (a bug in `pcap_to_dataset.py` stage1-v1):**
- Instagram serves photos and videos from `instagram.<site>.fna.fbcdn.net`.
- The rule `fbcdn.net → facebook-web` matched those names.
- In the frozen dataset, **71 of the 109 `facebook-web` flows were Instagram media.**
- Every model trained so far (§9, §11) learned from these wrong labels.

**Fix (converter `stage1-v2`):**
- New `PREFIX_RULES` step, checked before `APP_RULES`: `instagram.*.fbcdn.net → instagram`. Other `fbcdn.net` names stay `facebook-web`.
- New command `relabel`: recomputes every label from its stored SNI and writes a `.bak` backup. On the frozen set it changed exactly 71 labels, all facebook-web → instagram.
- New command `merge`: appends a teammate's CSV and skips captures already present (by `source_sha256`). Tested: merging the same file twice adds nothing the second time.
- Unit tests: 9/9 pass, including the new SNI cases.

**Corrected label counts (frozen set):**

| Label | Before | After |
|---|---|---|
| instagram | 93 | 164 |
| facebook-web | 109 | 38 |

**Validation run with corrected labels** (§11.1 settings: laptop captures only, HGB + IAT; session3 as validation — **not a test result**):
- known acc 0.574, open acc 0.789.
- Not directly comparable with §9–§11, because the labels changed.

Recall per app:

| App | Recall | Validation flows |
|---|---|---|
| instagram | 0.83 | 53 |
| whatsapp | 0.97 | 37 |
| spotify | 0.72 | 99 |
| youtube | 0.60 | 80 |
| facebook-web | 0.00 | 10 |
| snapchat | 0.03 | 39 |
| google-play | 0.07 | 14 |
| discord | 0.00 | 18 |
| other | 0.97 | 429 |

YouTube by connection type:

| Connection type | Correct |
|---|---|
| video stream | 0.97 of 33 |
| thumbnails | 0.88 of 16 |
| page / API | 0.06 of 31 |

**Remaining data gaps (laptop):** facebook-web (38 flows in total after the fix), discord 18, google-play 19, snapchat 40. These apps need dedicated collection time.

**Plan for the remaining collection** (user and teammate, one laptop each):
- Each person records about 1 hour of training captures with per-app time weighted towards the weak apps.
- Each person converts their own captures with a distinct `--network` tag (`laptop-<name>`).
- The teammate's CSV is combined with `merge`.
- The final test session is recorded last, on the demo laptop, and fixed before training (§11.1).

---

## 13. Live server-name reading and hybrid mode (PDF "honest shortcut") (2026-09-27)

**Trigger:** the user needs predictions to be as accurate as possible in tomorrow's demo. Live, the packet-only model still labels many connections `other`. Most of those really are other traffic (Google services, ads, trackers; §10, §12), but YouTube page connections, Facebook, Snapchat, Google Play and Discord are weak.

**Position recorded:**
- A packet-only model cannot be made near-perfect within hours; the limits are documented in §10–§12.
- The PDF's "honest shortcut" applies: for a working tool, use the SNI first and fall back to the model only when the SNI is hidden (ECH).
- For the research question, the SNI stays the label source only, never a model feature.

**Implemented:**
- `quic_sni.py` (new): derives QUIC v1/v2 client Initial keys from the DCID, removes header protection, decrypts the Initial with AES-GCM, reassembles CRYPTO frames across Initials (handles out-of-order frames and the split post-quantum ClientHello), and parses the SNI from the ClientHello. Requires `cryptography` (added to `requirements.txt`).
- `live_capture_v2.py`: collects the SNI from a flow's first client Initials.
  - Default mode (**model only**): each line shows the model's prediction, the true app from the SNI with ✓/✗, and every 10 labelled flows a running model accuracy. The final summary prints model accuracy against SNI labels, overall and on app connections only.
  - `--hybrid`: the final answer is the SNI app when visible, otherwise the model, and the source is shown as `[sni]` or `[model]`. The model's own prediction and ✓/✗ are still printed.
  - Log moved to `results/live_log.csv`, with extra columns `sni`, `sni_app`, `final`, `final_source`.
- `sni_to_app` is imported from `pcap_to_dataset.py`, so live labels use the same rules as the dataset.

**Verified (sandbox):**
- `tests/test_quic_sni.py`: the RFC 9001 Appendix A client key/IV/HP vector matches, and SNIs are recovered for all 5 fixture handshakes, including the ClientHello split over 2 Initials and the ECH outer name. 2/2 pass.
- `--pcap` replay of the fixture works in both modes; the consistency test still passes.
- Not yet run on real Chrome traffic or on Windows.

**Reporting rule:**
- Demo claims must state the mode.
- The model-only accuracy (held-out test, and the live running accuracy) is the research result.
- The hybrid mode is a system feature whose accuracy comes from the SNI, not from the model.
