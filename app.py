"""
BigPAC web demo (v2). Shows the v2 model on REAL held-out live flows: flows from
a capture session the model never saw in training (data/demo_samples.json,
written by train_v2.py). Each flow's true app comes from its server name (SNI),
which the model never sees.

  python app.py        then open http://127.0.0.1:5000
"""
import json
import os
import random

import joblib
import numpy as np
from flask import Flask, jsonify, request, send_from_directory

import features as F

MODEL_PATH = "models/bigpac_v2.joblib"
SAMPLES_PATH = "data/demo_samples.json"
RESULTS = {"stage5": "results/stage5_train_v2.json", "stage2": "results/stage2_baseline.json"}

app = Flask(__name__, static_folder="static")
bundle = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
samples = []
if os.path.exists(SAMPLES_PATH):
    with open(SAMPLES_PATH, encoding="utf-8") as fh:
        samples = json.load(fh)["flows"]
by_label = {}
for s in samples:
    by_label.setdefault(s["label"], []).append(s)
print(f"model: {MODEL_PATH if bundle else 'MISSING - run train_v2.py'}; "
      f"{len(samples)} held-out demo flows")


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/apps")
def apps():
    return jsonify({k: len(v) for k, v in sorted(by_label.items())})


@app.route("/get_sample/<label>")
def get_sample(label):
    pool = samples if label == "any" else by_label.get(label, [])
    if not pool:
        return jsonify({"error": f"no held-out flows for {label}"}), 404
    return jsonify(random.choice(pool))


@app.route("/predict", methods=["POST"])
def predict():
    if bundle is None:
        return jsonify({"error": "model not loaded; run train_v2.py"}), 500
    pkts = (request.json or {}).get("packets", [])
    if not pkts or any(len(p) != 3 for p in pkts):
        return jsonify({"error": "expected packets: [[size, dir, iat_ms], ...]"}), 400
    x = F.features_from_packets([tuple(map(float, p)) for p in pkts], bundle["use_iat"])
    p = bundle["model"].predict_proba(x)[0]
    order = np.argsort(p)[::-1]
    classes = bundle["classes"]
    top, conf = classes[order[0]], float(p[order[0]])
    pred = top if conf >= bundle["threshold"] else "UNKNOWN"
    return jsonify({"prediction": pred, "confidence": conf, "threshold": bundle["threshold"],
                    "top_3": [{"class": classes[i], "prob": float(p[i])} for i in order[:3]]})


@app.route("/results")
def results():
    s5, s2 = load_json(RESULTS["stage5"]), load_json(RESULTS["stage2"])
    out = {"cesnet_reported_old": 0.9707}
    if s2:
        out["old_live_all_captures"] = {"known_accuracy": s2["known_accuracy"],
                                        "open_accuracy": s2["open_world_accuracy"]}
    if s5:
        r = s5["results"]
        out["test_source"] = s5["args"]["test_source"]
        out["new_heldout"] = r["with_threshold"]
        out["old_heldout"] = r.get("old_model")
        out["new_cesnet_test"] = r["cesnet_test"]
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
