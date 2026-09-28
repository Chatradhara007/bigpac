"""
BigPAC v2 training (Stages 3-5, deadline version). One command does everything:

  python train_v2.py

What it does, in order:
  1. Loads CESNET (data/processed_data.parquet) and the SNI-labelled live set
     (data/live_labelled.csv) and computes features.py features.
  2. Holds out whole live capture(s) (--test-source) as the final test. The
     model never sees any packet of them. CESNET gets a stratified 80/20 split.
  3. Model selection using ONLY the training captures: each candidate model is
     cross-validated by capture (GroupKFold over capture files).
  4. Picks the UNKNOWN threshold from those out-of-fold predictions (never from
     the test capture).
  5. Retrains the winning candidate on all training data and evaluates it once
     on the held-out capture and on the CESNET test split. The old model is
     scored on the same held-out capture for comparison.
  6. Saves models/bigpac_v2.joblib, results/stage5_train_v2.{txt,json} and
     data/demo_samples.json (held-out flows for the web demo).

Labels: the 10 CESNET apps plus "other" (live non-target traffic). UNKNOWN is
what the model outputs when its top probability is below the threshold; when
scoring, UNKNOWN counts as correct only for "other" flows.
"""
import argparse
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.utils.class_weight import compute_sample_weight

import features as F

APPS = ["discord", "facebook-web", "google-play", "instagram",
        "microsoft-outlook", "snapchat", "spotify", "tiktok", "whatsapp",
        "youtube"]
OTHER, UNKNOWN = "other", "UNKNOWN"
DEFAULT_TEST = ["home-laptop-session3_00001_20260926221146.pcapng"]
CANDIDATES = {
    "rf_iat": ("rf", True),
    "hgb_iat": ("hgb", True),
    "hgb_noiat": ("hgb", False),
}
THRESHOLDS = np.round(np.arange(0.0, 0.951, 0.05), 2)


class Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")

    def write(self, s):
        sys.__stdout__.write(s)
        self.f.write(s)

    def flush(self):
        sys.__stdout__.flush()
        self.f.flush()


def sha16(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def make_model(kind, seed):
    if kind == "rf":
        return RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                      n_jobs=-1, random_state=seed)
    return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1,
                                          early_stopping=True,
                                          validation_fraction=0.1,
                                          random_state=seed)


def fit(kind, X, y, is_live, live_weight, seed):
    w = compute_sample_weight("balanced", y)
    w[is_live] *= live_weight
    m = make_model(kind, seed)
    m.fit(X, y, sample_weight=w)
    return m


def decide(proba, classes, threshold):
    """Top class, or UNKNOWN when its probability is below the threshold."""
    top = proba.argmax(1)
    pred = np.array(classes, dtype=object)[top]
    pred[proba.max(1) < threshold] = UNKNOWN
    return pred


def scores(y, pred):
    """Closed world = flows of the 10 apps; open world = all flows.
    UNKNOWN counts as correct for 'other' flows only."""
    y = np.asarray(y, dtype=object)
    pred = np.asarray(pred, dtype=object)
    p_open = np.where(pred == UNKNOWN, OTHER, pred)
    known = y != OTHER
    labels = sorted(set(y))
    return {
        "n": int(len(y)), "n_known": int(known.sum()),
        "known_accuracy": float((pred[known] == y[known]).mean()) if known.any() else None,
        "known_macro_f1": float(f1_score(y[known], pred[known], labels=sorted(set(y[known])),
                                         average="macro", zero_division=0)) if known.any() else None,
        "open_accuracy": float((p_open == y).mean()),
        "open_macro_f1": float(f1_score(y, p_open, labels=labels, average="macro", zero_division=0)),
        "unknown_rate": float((pred == UNKNOWN).mean()),
    }


def fmt(s):
    return (f"known acc {s['known_accuracy']:.3f} | known macro-F1 {s['known_macro_f1']:.3f} | "
            f"open acc {s['open_accuracy']:.3f} | open macro-F1 {s['open_macro_f1']:.3f} | "
            f"UNKNOWN {s['unknown_rate']:.3f}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--live", default="data/live_labelled.csv")
    ap.add_argument("--cesnet", default="data/processed_data.parquet")
    ap.add_argument("--old-model", default="models/rf_model_n15.joblib",
                    help="old model to score on the same test capture (skipped if missing)")
    ap.add_argument("--test-source", nargs="+", default=DEFAULT_TEST,
                    help="capture file name(s) (the 'source' column) held out as the final test")
    ap.add_argument("--exclude-network", nargs="+", default=[],
                    help="drop live captures with these network tags (e.g. home-phone)")
    ap.add_argument("--candidates", nargs="+", default=list(CANDIDATES))
    ap.add_argument("--cesnet-cap", type=int, default=5000,
                    help="max CESNET training flows per app (keeps training fast and balanced)")
    ap.add_argument("--live-weight", type=float, default=5.0)
    ap.add_argument("--folds", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="models/bigpac_v2.joblib")
    args = ap.parse_args()

    os.makedirs("results", exist_ok=True)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    sys.stdout = Tee("results/stage5_train_v2.txt")
    t0 = time.time()
    run = {"started": datetime.now().isoformat(timespec="seconds"),
           "python": platform.python_version(), "sklearn": sklearn.__version__,
           "numpy": np.__version__, "pandas": pd.__version__,
           "feature_version": F.FEATURE_VERSION, "args": vars(args)}
    print("BigPAC v2 training", run["started"])
    print(f"python {run['python']}, scikit-learn {run['sklearn']}, numpy {run['numpy']}, pandas {run['pandas']}")

    # ---------------------------------------------------------------- data
    live = pd.read_csv(args.live)
    if args.exclude_network:
        before = len(live)
        live = live[~live.network.isin(args.exclude_network)].reset_index(drop=True)
        print(f"excluded networks {args.exclude_network}: {before - len(live)} flows dropped")
    ces = pd.read_parquet(args.cesnet)
    run["live_sha16"], run["cesnet_sha16"] = sha16(args.live), sha16(args.cesnet)
    print(f"live: {args.live} [{run['live_sha16']}] {len(live)} flows; "
          f"cesnet: {args.cesnet} [{run['cesnet_sha16']}] {len(ces)} flows")
    bad = set(live.label) - set(APPS) - {OTHER}
    if bad:
        sys.exit(f"unexpected live labels: {bad}")
    missing = [s for s in args.test_source if s not in set(live.source)]
    if missing:
        sys.exit(f"--test-source not found in live data: {missing}\navailable: {sorted(set(live.source))}")

    ces_tr, ces_te = train_test_split(ces, test_size=0.2, stratify=ces.label, random_state=args.seed)
    # shuffle, then keep the first N per app (same result on every pandas version)
    ces_tr = ces_tr.sample(frac=1.0, random_state=args.seed).groupby("label").head(args.cesnet_cap)
    is_test = live.source.isin(args.test_source)
    live_tr, live_te = live[~is_test].reset_index(drop=True), live[is_test].reset_index(drop=True)
    print(f"CESNET train (capped {args.cesnet_cap}/app): {len(ces_tr)}, CESNET test: {len(ces_te)}")
    print(f"live train: {len(live_tr)} flows from {sorted(set(live_tr.source))}")
    print(f"live TEST (held out): {len(live_te)} flows from {args.test_source}")
    print("live train labels:", live_tr.label.value_counts().to_dict())
    print("live test labels: ", live_te.label.value_counts().to_dict())
    no_live_train = [a for a in APPS if a not in set(live_tr.label)]
    print("apps with NO live training data (learned from CESNET only):", no_live_train)

    feats = {}
    for use_iat in (True, False):
        feats[use_iat] = {k: F.features_from_frame(d, use_iat)
                          for k, d in [("ces_tr", ces_tr), ("ces_te", ces_te),
                                       ("live_tr", live_tr), ("live_te", live_te)]}
    y_ces_tr, y_live_tr = ces_tr.label.values, live_tr.label.values

    # --------------------------------------------- model selection (train only)
    groups = live_tr.source.values
    n_folds = min(args.folds, len(set(groups)))
    folds = list(GroupKFold(n_splits=n_folds).split(live_tr, groups=groups))
    print(f"\n=== Model selection: {n_folds}-fold CV grouped by capture (training captures only) ===")
    for i, (_, va) in enumerate(folds):
        print(f"fold {i}: validate on {sorted(set(groups[va]))} ({len(va)} flows)")
    sel = {}
    for name in args.candidates:
        kind, use_iat = CANDIDATES[name]
        fx = feats[use_iat]
        oof, classes = None, None
        tc = time.time()
        for tr, va in folds:
            X = np.vstack([fx["ces_tr"], fx["live_tr"][tr]])
            y = np.concatenate([y_ces_tr, y_live_tr[tr]])
            is_live = np.r_[np.zeros(len(y_ces_tr), bool), np.ones(len(tr), bool)]
            m = fit(kind, X, y, is_live, args.live_weight, args.seed)
            assert oof is None or list(m.classes_) == classes, "class set differs between folds"
            p = m.predict_proba(fx["live_tr"][va])
            if oof is None:
                classes = list(m.classes_)
                oof = np.zeros((len(live_tr), len(classes)))
            oof[va] = p
        s = scores(y_live_tr, decide(oof, classes, 0.0))
        sel[name] = {"oof": oof, "classes": classes, "scores": s}
        print(f"{name:<10} {fmt(s)}   ({time.time() - tc:.0f}s)")
    best = max(sel, key=lambda k: sel[k]["scores"]["open_macro_f1"])
    print(f"-> selected: {best} (highest out-of-fold open-world macro-F1)")

    # ------------------------------------------------ threshold (train only)
    oof, classes = sel[best]["oof"], sel[best]["classes"]
    grid = {float(t): scores(y_live_tr, decide(oof, classes, t)) for t in THRESHOLDS}
    threshold = max(grid, key=lambda t: (grid[t]["open_macro_f1"], -t))
    print("\n=== UNKNOWN threshold (out-of-fold, training captures) ===")
    for t in THRESHOLDS:
        mark = " <- chosen" if t == threshold else ""
        print(f"t={t:.2f}  {fmt(grid[float(t)])}{mark}")

    # ------------------------------------------------------ final model
    kind, use_iat = CANDIDATES[best]
    fx = feats[use_iat]
    X = np.vstack([fx["ces_tr"], fx["live_tr"]])
    y = np.concatenate([y_ces_tr, y_live_tr])
    is_live = np.r_[np.zeros(len(y_ces_tr), bool), np.ones(len(y_live_tr), bool)]
    tf = time.time()
    model = fit(kind, X, y, is_live, args.live_weight, args.seed)
    classes = list(model.classes_)
    print(f"\nfinal {best} trained on {len(y)} flows in {time.time() - tf:.0f}s; classes: {classes}")

    # ----------------------------------------- final evaluation (once)
    print("\n" + "=" * 70)
    print("FINAL EVALUATION ON THE HELD-OUT LIVE CAPTURE (never seen in training)")
    print("=" * 70)
    y_te = live_te.label.values
    p_te = model.predict_proba(fx["live_te"])
    res = {"argmax": scores(y_te, decide(p_te, classes, 0.0)),
           "with_threshold": scores(y_te, decide(p_te, classes, threshold))}
    print(f"new model, no threshold    : {fmt(res['argmax'])}")
    print(f"new model, threshold {threshold:.2f} : {fmt(res['with_threshold'])}")

    if os.path.exists(args.old_model):
        old = joblib.load(args.old_model)
        cols = [f"pkt_{k}_{i}" for i in range(15) for k in ("size", "dir", "iat")]
        old_pred = old.predict(live_te[cols].values)
        res["old_model"] = scores(y_te, old_pred)
        res["old_model"]["model_sha16"] = sha16(args.old_model)
        print(f"OLD model (rf_model_n15)   : {fmt(res['old_model'])}")
    else:
        print(f"old model not found at {args.old_model}; comparison skipped")

    pred_te = decide(p_te, classes, threshold)
    print("\nheld-out breakdown by IP version / network (with threshold):")
    for col in ("ip_version", "network"):
        for val, idx in live_te.groupby(col).groups.items():
            s_ = scores(y_te[idx], pred_te[idx])
            ka = "n/a" if s_["known_accuracy"] is None else f"{s_['known_accuracy']:.3f}"
            print(f"  {col}={val}: n={s_['n']} (apps {s_['n_known']}) known acc {ka} | open acc {s_['open_accuracy']:.3f}")
    labs = [c for c in classes if c in set(y_te) | set(pred_te)] + (
        [UNKNOWN] if UNKNOWN in set(pred_te) else [])
    print("\nper-class report (with threshold; UNKNOWN shown as its own column):")
    print(classification_report(y_te, pred_te, labels=sorted(set(y_te)), zero_division=0, digits=3))
    cm = pd.DataFrame(confusion_matrix(y_te, pred_te, labels=labs), index=labs, columns=labs)
    cm = cm.loc[[l for l in labs if l in set(y_te)]]
    print("confusion (rows = true, cols = predicted):")
    print(cm.to_string())
    res["per_class"] = classification_report(y_te, pred_te, labels=sorted(set(y_te)),
                                             zero_division=0, output_dict=True)

    print("\n" + "=" * 70)
    print("CESNET TEST SPLIT (random 80/20; no week column available)")
    print("=" * 70)
    y_ct = ces_te.label.values
    p_ct = model.predict(fx["ces_te"])
    res["cesnet_test"] = {"n": int(len(y_ct)), "accuracy": float(accuracy_score(y_ct, p_ct)),
                          "macro_f1": float(f1_score(y_ct, p_ct, average="macro", zero_division=0)),
                          "predicted_other_rate": float((p_ct == OTHER).mean())}
    print(f"accuracy {res['cesnet_test']['accuracy']:.3f} | macro-F1 {res['cesnet_test']['macro_f1']:.3f} "
          f"| flows predicted 'other': {res['cesnet_test']['predicted_other_rate']:.3f}")

    # ------------------------------------------------------------ save
    bundle = {"model": model, "classes": classes, "threshold": float(threshold),
              "use_iat": use_iat, "feature_version": F.FEATURE_VERSION,
              "n_body": F.N_BODY, "candidate": best, "sklearn_version": sklearn.__version__,
              "trained": run["started"], "test_source": args.test_source,
              "train_sources": sorted(set(live_tr.source)),
              "live_sha16": run["live_sha16"], "cesnet_sha16": run["cesnet_sha16"],
              "headline": res["with_threshold"]}
    joblib.dump(bundle, args.out, compress=3)
    run["model_file"], run["model_sha16"] = args.out, sha16(args.out)
    print(f"\nsaved {args.out} [{run['model_sha16']}]")

    demo = [{"label": r.label, "sni": r.sni, "network": r.network, "source": r.source,
             "packets": [[int(getattr(r, f"pkt_size_{i}")), int(getattr(r, f"pkt_dir_{i}")),
                          float(getattr(r, f"pkt_iat_{i}"))]
                         for i in range(F.MAX_PKTS) if getattr(r, f"pkt_dir_{i}") != 0]}
            for r in live_te.itertuples()]
    with open("data/demo_samples.json", "w", encoding="utf-8") as fh:
        json.dump({"test_source": args.test_source, "flows": demo}, fh)
    print(f"saved data/demo_samples.json ({len(demo)} held-out flows)")

    run.update({"selected": best, "threshold": float(threshold),
                "selection": {k: v["scores"] for k, v in sel.items()},
                "threshold_grid": {str(k): v for k, v in grid.items()},
                "results": res, "seconds": round(time.time() - t0)})
    with open("results/stage5_train_v2.json", "w", encoding="utf-8") as fh:
        json.dump(run, fh, indent=2)
    print(f"saved results/stage5_train_v2.json; total {run['seconds']}s")


if __name__ == "__main__":
    main()
