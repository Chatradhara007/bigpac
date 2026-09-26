# Stage 1 — Collecting the SNI-labelled live dataset

Goal: a labelled set of **your own** QUIC flows, in the same 30-packet format as `data/processed_data.parquet`, with the app label taken from the server name (SNI) in each connection's Initial packets. Stage 2 uses it to measure how the existing models actually perform live.

The labels come from SNI, so you do not type labels and background traffic is separated automatically. SNI is the **label only**; it must never become a model feature.

## 1. One-time setup

1. Check tshark (installed with Wireshark), version 3.6 or newer:
   ```
   "C:\Program Files\Wireshark\tshark.exe" --version
   ```
   `pcap_to_dataset.py` finds tshark on `PATH` or at that default location; otherwise pass `--tshark PATH`.
2. Find your capture interface name:
   ```
   tshark -D
   ```
   Use the name shown for your Wi-Fi adapter (for example `Wi-Fi`).
3. Turn off any VPN while capturing. A VPN hides all QUIC traffic.
4. Create the capture folder: `mkdir data\captures`. `data/` is gitignored; captures contain metadata about all of your QUIC traffic and must not be committed.

## 2. Capturing

Run this in a terminal (Administrator if it fails with a permissions error):

```
tshark -i "Wi-Fi" -f "udp port 443" -b duration:3600 -w data\captures\home-laptop.pcapng
```

`-b duration:3600` starts a new file every hour (tshark appends a number and timestamp to each file name). Stop with Ctrl+C.

While it runs, use the apps normally. Things that increase the number of usable flows:

- **New connections matter.** Only flows that start with a client Initial packet are kept, so each new QUIC connection is one sample. Closing and reopening the site, opening it in a new window, or `chrome://net-internals/#sockets` → *Flush socket pools* all force new connections.
- **Use every app you can**, including the rarely used ones. SNI sorts everything out, so several apps in parallel are fine.
- **Spread captures over several days**, on home and campus networks. Stage 5 needs at least one whole capture day held back as a final test set, and one network or one day is not a fair test.
- **Phone apps (optional, recommended).** Much of CESNET's instagram / tiktok / snapchat / whatsapp traffic is mobile-app traffic. Connect your phone to the laptop's Windows Mobile Hotspot and capture on the hotspot interface (see `tshark -D`), using a network tag like `home-phone`.

Known limits you will probably hit, which are real results and not bugs:

- WhatsApp Web and Spotify Web mostly use TCP in desktop browsers, so they may yield few QUIC flows from a laptop.
- Campus networks that block UDP 443 yield no QUIC at all (`PROJECT_DOCUMENTATION.md`, Problem 4). Capture briefly there first to check.
- Sites behind Cloudflare with Encrypted Client Hello show the outer name `cloudflare-ech.com` instead of the real one. Those flows cannot be labelled and are skipped (reported as `skip_ech_hidden`). Discord is a likely victim. Do not disable ECH in Chrome without recording it, because that changes the handshake.

Storage: captures keep full packets (the Initial packets must be complete to read the SNI). An hour of video can be over 1 GB. Convert captures promptly; keep the pcaps if you have space, since they are the raw evidence.

## 3. Converting

Convert one network/device context at a time, with a tag in the form `<place>-<device>`:

```
python pcap_to_dataset.py convert data\captures\home-laptop*.pcapng --network home-laptop
python pcap_to_dataset.py convert data\captures\campus-laptop*.pcapng --network campus-laptop
```

Output: rows are appended to `data/live_labelled.csv`. Each capture is identified by a SHA-256 prefix, and a capture already in the CSV is skipped, so re-running the command is safe. The command prints per-capture counts:

| Counter | Meaning |
|---|---|
| `flows` | flows that started with a genuine client Initial |
| `written` | rows written |
| `skip_no_sni` | no SNI could be read (tshark could not decrypt the Initials) |
| `skip_ech_hidden` | SNI was an ECH outer name |
| `skip_short` | fewer than 15 packets (`--min-pkts`) |
| `dropped_midstream` | packets from connections that started before the capture |
| `rejected_large_non_initial` | large client packets that `live_capture.py` would wrongly treat as a new flow |

## 4. Spot-checking (do this on the first capture)

The converter was validated on synthetic loopback QUIC, not yet on real Chrome traffic. Before collecting for days, open the first capture in Wireshark and check 3–5 flows:

1. Display filter: `quic && tls.handshake.extensions_server_name`.
2. For a flow, note its SNI and client port, then filter `udp.port == <client port>`.
3. Compare the first few packet lengths (UDP payload = `udp.length − 8`) and directions with the matching row in `data/live_labelled.csv` (its `sni` column and `pkt_size_*`, `pkt_dir_*` columns).

If anything disagrees, stop and report it before collecting more.

## 5. Tracking progress

```
python pcap_to_dataset.py report
```

This shows flows per app, distinct days and networks per app, how many flows are IPv6, and how many used 2+ client Initial packets (the post-quantum split ClientHello). It also lists the most common SNIs labelled `other`.

Extend `APP_RULES` in `pcap_to_dataset.py` only with domains that clearly belong to the app. If you change the rules, write down the change: rows keep their raw `sni`, so Stage 2 can relabel them consistently.

## 6. When Stage 1 is done

Target from the improvement plan: **at least 200 flows per app, over several days, on both home and campus networks.** Run `report` and record its output in `IMPLEMENTATION_STATUS.md`. Some apps may not reach 200 over QUIC from your devices; record the actual counts rather than padding them. Deciding how Stage 2 treats those apps is an open question in the status file.
