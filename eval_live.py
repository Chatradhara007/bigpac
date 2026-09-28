"""Stage 2: evaluate an existing model on the SNI-labelled live set (read-only).
Usage: python eval_live.py data/live_labelled.csv data/processed_data.parquet models/rf_model_n15.joblib
Writes results/stage2_baseline.json; print output is the full report."""
import os
import sys, json, warnings
import numpy as np, pandas as pd, joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.model_selection import cross_val_score
from sklearn.ensemble import RandomForestClassifier
warnings.simplefilter("always")

LIVE, PARQ, MODEL = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs("results", exist_ok=True)
N = 15
cols = [f"pkt_{k}_{i}" for i in range(N) for k in ("size", "dir", "iat")]
with warnings.catch_warnings(record=True) as w:
    model = joblib.load(MODEL)
    for x in w: print("LOAD WARNING:", str(x.message)[:200])
live = pd.read_csv(LIVE)
classes = list(model.classes_)
live["pred"] = model.predict(live[cols].values)
live["conf"] = model.predict_proba(live[cols].values).max(1)
known = live[live.label.isin(classes)]
other = live[~live.label.isin(classes)]
out = {}
print(f"live flows={len(live)} known={len(known)} other/non-target={len(other)}")
print("\n=== Closed-world: known-app live flows only ===")
print(classification_report(known.label, known.pred, labels=sorted(known.label.unique()), zero_division=0, digits=3))
out["known_accuracy"] = accuracy_score(known.label, known.pred)
out["known_macro_f1"] = f1_score(known.label, known.pred, labels=sorted(known.label.unique()), average="macro", zero_division=0)
labs = sorted(set(known.label) | set(known.pred))
cm = pd.DataFrame(confusion_matrix(known.label, known.pred, labels=labs), index=labs, columns=labs)
print("confusion (rows=true, cols=pred):\n", cm.to_string())
print("\n=== Open-world: all live flows (model has no 'other', so every 'other' flow is wrong) ===")
out["open_world_accuracy"] = float((live.label == live.pred).mean())
print("open-world accuracy:", round(out["open_world_accuracy"], 4))
print("'other' flows predicted as:", other.pred.value_counts().to_dict())
print("\n=== By network ===")
for net, g in known.groupby("network"):
    print(f"{net:<14} n={len(g):>4} acc={accuracy_score(g.label, g.pred):.3f}")
print("\n=== Confidence ===")
print("mean top-prob, correct:", round(known.conf[known.label == known.pred].mean(), 3),
      " wrong(known):", round(known.conf[known.label != known.pred].mean(), 3),
      " other:", round(other.conf.mean(), 3))
# Domain-shift check (PDF step 2)
cesnet = pd.read_parquet(PARQ).sample(len(live) * 5, random_state=0)
X = np.vstack([cesnet[cols].values, live[cols].values]); y = np.r_[np.zeros(len(cesnet)), np.ones(len(live))]
clf = RandomForestClassifier(200, n_jobs=-1, random_state=0)
out["shift_auc"] = cross_val_score(clf, X, y, cv=5, scoring="roc_auc").mean()
print("\nshift AUC (CESNET vs live, 5-fold):", round(out["shift_auc"], 4))
clf.fit(X, y)
top = sorted(zip(clf.feature_importances_, cols), reverse=True)[:10]
print("top shifted features:", [(c, round(v, 3)) for v, c in top])
out["n_live"] = len(live); out["n_known"] = len(known)
with open("results/stage2_baseline.json", "w") as fh:
    json.dump({k: (float(v) if isinstance(v, (float, np.floating)) else v) for k, v in out.items()}, fh, indent=2)
print("\n", out)
