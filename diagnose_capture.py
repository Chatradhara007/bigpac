"""
Explain what the model predicts for the flows of one or more captures, using the
SNI labels in data/live_labelled.csv as the truth.

  python diagnose_capture.py                       # list captures in the CSV
  python diagnose_capture.py <capture file name>   # diagnose one capture (the 'source' column)

Shows: accuracy by true app, by IP version, and for every app flow predicted wrongly
its server name, so you can see whether a wrong 'other' is really a YouTube video
connection or, e.g., an ad/analytics server that is correctly 'other'.
If the capture was used for training, the results are optimistic and a warning is shown.
"""
import sys

import joblib
import numpy as np
import pandas as pd

import features as F

MODEL, CSV = "models/bigpac_v2.joblib", "data/live_labelled.csv"


def main():
    live = pd.read_csv(CSV)
    if len(sys.argv) < 2:
        print(live.groupby("source").agg(flows=("label", "size"), network=("network", "first"),
                                         day=("capture_day", "first"),
                                         ipv6=("ip_version", lambda s: int((s == 6).sum()))).to_string())
        return
    b = joblib.load(MODEL)
    df = live[live.source.isin(sys.argv[1:])].reset_index(drop=True)
    if df.empty:
        sys.exit("no flows for that capture; run without arguments to list captures")
    used = set(sys.argv[1:]) & set(b.get("train_sources", []))
    if used:
        print(f"WARNING: {sorted(used)} was used for TRAINING; these results are optimistic.\n")
    p = b["model"].predict_proba(F.features_from_frame(df, b["use_iat"]))
    top = np.array(b["classes"], dtype=object)[p.argmax(1)]
    df["pred"] = np.where(p.max(1) >= b["threshold"], top, "UNKNOWN")
    df["conf"] = p.max(1).round(2)
    df["ok"] = (df.pred == df.label) | ((df.pred == "UNKNOWN") & (df.label == "other"))
    print(f"{len(df)} flows; overall correct {df.ok.mean():.3f}")
    print("\nby true app:")
    t = df.groupby("label").agg(flows=("ok", "size"), correct=("ok", "mean"),
                                predicted_other=("pred", lambda s: int((s == "other").sum())))
    print(t.round(3).to_string())
    print("\nby IP version:")
    print(df.groupby("ip_version").agg(flows=("ok", "size"), correct=("ok", "mean")).round(3).to_string())
    wrong = df[(df.label != "other") & ~df.ok]
    if len(wrong):
        print("\napp flows predicted wrongly (true app, predicted, confidence, IP, server name):")
        for r in wrong.sort_values(["label", "sni"]).itertuples():
            print(f"  {r.label:<13} -> {r.pred:<13} {r.conf:.2f}  IPv{r.ip_version}  {r.sni}")
    fooled = df[(df.label == "other") & (df.pred != "other") & (df.pred != "UNKNOWN")]
    if len(fooled):
        print("\n'other' flows predicted as an app (server name -> predicted):")
        for r in fooled.itertuples():
            print(f"  {r.sni} -> {r.pred}")


if __name__ == "__main__":
    main()
