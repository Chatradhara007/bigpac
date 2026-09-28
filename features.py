"""
Shared feature extraction for BigPAC (Stage 4). Imported by train_v2.py,
live_capture.py and app.py so training and prediction can never disagree.

Input for one flow: up to 30 packets as (size, dir, iat_ms), where size is UDP
payload bytes, dir is +1 client->server / -1 server->client, iat_ms is the gap
to the previous packet (0 for the first). Padding rows have dir == 0.

Drift fixes (see IMPLEMENTATION_STATUS.md, Stage 2 §8.4):
  * IATs are rounded to whole milliseconds, because CESNET-QUIC22 stores them
    that way, then log1p-scaled to shrink RTT differences between networks.
  * The packet window starts at the FIRST SERVER REPLY, so a ClientHello split
    over 1 or 2 client Initial packets no longer shifts every column. The
    number of client packets before that reply becomes one feature.
  * Per-direction aggregates of the window, which are stable across networks.
"""
import warnings

import numpy as np

FEATURE_VERSION = "aligned-v1"
MAX_PKTS = 30
N_BODY = 12

AGG_NAMES = ["n_client_before_server", "up_bytes", "down_bytes", "up_count",
             "down_count", "down_max", "down_mean", "down_large_count",
             "down_median_log_iat"]


def feature_names(use_iat=True):
    names = [f"body_size_{i}" for i in range(N_BODY)]
    names += [f"body_dir_{i}" for i in range(N_BODY)]
    if use_iat:
        names += [f"body_log_iat_{i}" for i in range(N_BODY)]
    aggs = AGG_NAMES if use_iat else AGG_NAMES[:-1]
    return names + aggs


def features_from_arrays(S, D, T, use_iat=True):
    """Vectorised features. S, D, T: arrays of shape (n_flows, 30)."""
    S = np.asarray(S, float)
    D = np.asarray(D, float)
    T = np.asarray(T, float)
    n, width = D.shape
    is_srv = D == -1
    n_real = (D != 0).sum(1)
    first_srv = np.where(is_srv.any(1), is_srv.argmax(1), n_real)

    idx = first_srv[:, None] + np.arange(N_BODY)[None, :]
    valid = idx < width
    idx_c = np.minimum(idx, width - 1)
    rows = np.arange(n)[:, None]
    bs = np.where(valid, S[rows, idx_c], 0.0)
    bd = np.where(valid, D[rows, idx_c], 0.0)
    bt = np.where(valid, T[rows, idx_c], 0.0)
    pad = bd == 0
    bs[pad] = 0.0
    bt[pad] = 0.0
    bt = np.log1p(np.rint(np.maximum(bt, 0.0)))

    up, down = bd == 1, bd == -1
    down_sizes = np.where(down, bs, np.nan)
    down_iats = np.where(down, bt, np.nan)
    has_down = down.any(1)
    with np.errstate(all="ignore"), warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        down_max = np.where(has_down, np.nanmax(np.where(down, bs, -np.inf), 1), 0)
        down_mean = np.where(has_down, np.nanmean(down_sizes, 1), 0)
        down_med = np.where(has_down, np.nanmedian(down_iats, 1), 0)
    agg = np.column_stack([
        first_srv, (bs * up).sum(1), (bs * down).sum(1), up.sum(1),
        down.sum(1), down_max, down_mean, (down & (bs >= 1200)).sum(1),
    ] + ([down_med] if use_iat else []))
    parts = [bs, bd] + ([bt] if use_iat else []) + [agg]
    return np.hstack(parts).astype(np.float32)


def features_from_frame(df, use_iat=True):
    """Features for a DataFrame with pkt_size_i / pkt_dir_i / pkt_iat_i columns."""
    S = df[[f"pkt_size_{i}" for i in range(MAX_PKTS)]].values
    D = df[[f"pkt_dir_{i}" for i in range(MAX_PKTS)]].values
    T = df[[f"pkt_iat_{i}" for i in range(MAX_PKTS)]].values
    return features_from_arrays(S, D, T, use_iat)


def features_from_packets(pkts, use_iat=True):
    """Features for one flow given a list of (size, dir, iat_ms) tuples (live)."""
    pk = list(pkts)[:MAX_PKTS]
    pk += [(0, 0, 0.0)] * (MAX_PKTS - len(pk))
    a = np.array(pk, float)
    return features_from_arrays(a[None, :, 0], a[None, :, 1], a[None, :, 2], use_iat)


def ready(pkts):
    """Live: True once the flow has a server reply plus N_BODY packets from it."""
    first_srv = next((i for i, p in enumerate(pkts) if p[1] == -1), None)
    return first_srv is not None and len(pkts) >= first_srv + N_BODY
