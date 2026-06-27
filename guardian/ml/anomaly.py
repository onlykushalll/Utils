#!/usr/bin/env python3
"""Layer 4: Anomaly detection (isolation forest).

Catches novel threats signatures/rules miss (zero-days). Trains an isolation
forest on "normal" process/network telemetry, then flags outliers.

Usage:
    python3 ml/anomaly.py --train --out ml/anomaly.pkl
    python3 ml/anomaly.py --check <features_json>     # returns verdict+score

The Guardian daemon calls this via subprocess (g_ml_check in C) on flagged
events that the deterministic layers couldn't resolve cleanly.
"""
import argparse
import json
import sys
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = Path(__file__).parent / "anomaly.pkl"

# Features per process/network-flow snapshot (keep small & cheap):
#   cpu_pct, mem_mb, net_conns, file_writes_min, fork_rate_min,
#   entropy_file_io, distinct_ips_5min, syscall_rate
FEATURE_NAMES = [
    "cpu_pct", "mem_mb", "net_conns", "file_writes_min",
    "fork_rate_min", "entropy_file_io", "distinct_ips_5min", "syscall_rate",
]


def _synthetic_normal(n=4000, seed=42):
    """Generate plausible 'normal' telemetry for training (replace with real
    baseline data captured on WLTIOS in production)."""
    rng = np.random.RandomState(seed)
    x = np.column_stack([
        rng.normal(3.0, 2.0, n),     # cpu_pct: low idle burst
        rng.normal(80, 30, n),       # mem_mb
        rng.poisson(4, n),           # net_conns
        rng.poisson(2, n),           # file_writes_min
        rng.poisson(0.2, n),         # fork_rate_min (rare)
        rng.uniform(0.2, 0.6, n),    # entropy_file_io
        rng.poisson(2, n),           # distinct_ips_5min
        rng.normal(500, 200, n),     # syscall_rate
    ])
    return np.clip(x, 0, None)


def train(out_path):
    X = _synthetic_normal()
    clf = IsolationForest(n_estimators=80, contamination=0.02,
                          random_state=42, n_jobs=-1)
    clf.fit(X)
    with open(out_path, "wb") as f:
        pickle.dump({"model": clf, "features": FEATURE_NAMES}, f)
    print(f"[ml] trained isolation forest on {len(X)} samples -> {out_path}")
    # quick self-check
    scores = clf.decision_function(X)
    print(f"[ml] baseline anomaly score: mean={scores.mean():.3f} min={scores.min():.3f}")
    return clf


def load():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"model not found: {MODEL_PATH} (run --train first)")
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def check(features):
    """features: dict of feature_name -> value. Returns verdict dict."""
    bundle = load()
    clf = bundle["model"]
    names = bundle["features"]
    vec = np.array([[features.get(n, 0.0) for n in names]])
    score = float(clf.decision_function(vec)[0])    # higher = more normal
    pred = int(clf.predict(vec)[0])                 # 1 normal, -1 anomaly
    return {
        "verdict": "clean" if pred == 1 else "anomaly",
        "anomaly_score": round(score, 4),
        "confidence": "high" if abs(score) > 0.15 else "low",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--out", default=str(MODEL_PATH))
    ap.add_argument("--check", metavar="JSON", help="features JSON to check")
    args = ap.parse_args()

    if args.train:
        train(args.out)
        return
    if args.check:
        feats = json.loads(args.check)
        print(json.dumps(check(feats), indent=2))
        return
    # stdin mode: Guardian daemon pipes features JSON on stdin
    raw = sys.stdin.read().strip()
    if raw:
        feats = json.loads(raw)
        print(json.dumps(check(feats)))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
