#!/usr/bin/env python3
"""machine learning anomaly detection for network flow analysis"""

import argparse
import csv
import json
import os
import pickle
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report
except ImportError:
    print("[error] sklearn required: pip install scikit-learn", file=sys.stderr)
    sys.exit(1)


FLOW_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "src_packets", "dst_packets",
    "byte_ratio", "packet_ratio", "bytes_per_packet_src", "bytes_per_packet_dst",
    "port_entropy", "unique_dst_ports", "avg_packet_size",
]


def extract_features(flow):
    """extract ml features from a network flow record"""
    duration = max(flow.get("duration", 0), 0.001)
    src_bytes = flow.get("src_bytes", 0)
    dst_bytes = flow.get("dst_bytes", 0)
    src_packets = max(flow.get("src_packets", 0), 1)
    dst_packets = max(flow.get("dst_packets", 0), 1)

    total_bytes = src_bytes + dst_bytes
    total_packets = src_packets + dst_packets

    byte_ratio = src_bytes / max(dst_bytes, 1)
    packet_ratio = src_packets / max(dst_packets, 1)

    return [
        duration,
        src_bytes,
        dst_bytes,
        src_packets,
        dst_packets,
        byte_ratio,
        packet_ratio,
        src_bytes / src_packets,
        dst_bytes / dst_packets,
        flow.get("port_entropy", 0),
        flow.get("unique_dst_ports", 1),
        total_bytes / total_packets,
    ]


def parse_flow_csv(filepath):
    """parse network flow data from csv"""
    flows = []
    try:
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                flow = {}
                for key, val in row.items():
                    key = key.strip().lower().replace(" ", "_")
                    try:
                        flow[key] = float(val)
                    except (ValueError, TypeError):
                        flow[key] = val
                flows.append(flow)
    except FileNotFoundError:
        print(f"[error] file not found: {filepath}", file=sys.stderr)
    return flows


def parse_flow_json(filepath):
    """parse network flow data from json"""
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "flows" in data:
            return data["flows"]
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[error] {filepath}: {e}", file=sys.stderr)
    return []


def generate_synthetic_flows(n_normal=500, n_anomaly=20):
    """generate synthetic flow data for training and testing"""
    rng = np.random.RandomState(42)
    flows = []

    # normal traffic patterns
    for _ in range(n_normal):
        flows.append({
            "duration": rng.exponential(30),
            "src_bytes": rng.lognormal(8, 1),
            "dst_bytes": rng.lognormal(9, 1.5),
            "src_packets": rng.poisson(20) + 1,
            "dst_packets": rng.poisson(30) + 1,
            "port_entropy": rng.normal(2.5, 0.5),
            "unique_dst_ports": rng.poisson(2) + 1,
            "label": 1,
        })

    # anomalous patterns (scans, exfil, c2)
    for _ in range(n_anomaly):
        anomaly_type = rng.choice(["scan", "exfil", "c2"])
        if anomaly_type == "scan":
            flows.append({
                "duration": rng.exponential(2),
                "src_bytes": rng.lognormal(4, 0.5),
                "dst_bytes": rng.lognormal(3, 0.5),
                "src_packets": rng.poisson(100) + 50,
                "dst_packets": rng.poisson(5) + 1,
                "port_entropy": rng.normal(5, 0.5),
                "unique_dst_ports": rng.poisson(50) + 20,
                "label": -1,
            })
        elif anomaly_type == "exfil":
            flows.append({
                "duration": rng.exponential(300),
                "src_bytes": rng.lognormal(14, 1),
                "dst_bytes": rng.lognormal(5, 0.5),
                "src_packets": rng.poisson(500) + 100,
                "dst_packets": rng.poisson(10) + 1,
                "port_entropy": rng.normal(0.5, 0.2),
                "unique_dst_ports": 1,
                "label": -1,
            })
        else:  # c2
            flows.append({
                "duration": rng.exponential(60),
                "src_bytes": rng.lognormal(6, 0.3),
                "dst_bytes": rng.lognormal(6, 0.3),
                "src_packets": rng.poisson(5) + 1,
                "dst_packets": rng.poisson(5) + 1,
                "port_entropy": rng.normal(0.1, 0.1),
                "unique_dst_ports": 1,
                "label": -1,
            })

    return flows


class AnomalyDetector:
    def __init__(self, model_type="isolation_forest", contamination=0.05):
        self.model_type = model_type
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.model = None
        self._init_model()

    def _init_model(self):
        if self.model_type == "isolation_forest":
            self.model = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,
                random_state=42,
            )
        elif self.model_type == "one_class_svm":
            self.model = OneClassSVM(
                kernel="rbf",
                gamma="scale",
                nu=self.contamination,
            )
        else:
            raise ValueError(f"unknown model type: {self.model_type}")

    def train(self, flows):
        """train the anomaly detection model"""
        feature_matrix = np.array([extract_features(f) for f in flows])
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=1e6, neginf=-1e6)

        self.scaler.fit(feature_matrix)
        scaled = self.scaler.transform(feature_matrix)

        self.model.fit(scaled)

        scores = self.model.decision_function(scaled)
        predictions = self.model.predict(scaled)

        n_anomalies = sum(1 for p in predictions if p == -1)
        print(f"[probaduce] trained on {len(flows)} flows, {n_anomalies} flagged as anomalous")

        return {
            "total_flows": len(flows),
            "anomalies_detected": n_anomalies,
            "mean_score": float(np.mean(scores)),
            "std_score": float(np.std(scores)),
        }

    def predict(self, flows):
        """predict anomalies in new flow data"""
        if self.model is None:
            raise RuntimeError("model not trained")

        feature_matrix = np.array([extract_features(f) for f in flows])
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=1e6, neginf=-1e6)
        scaled = self.scaler.transform(feature_matrix)

        predictions = self.model.predict(scaled)
        scores = self.model.decision_function(scaled)

        results = []
        for i, (flow, pred, score) in enumerate(zip(flows, predictions, scores)):
            results.append({
                "index": i,
                "prediction": "anomaly" if pred == -1 else "normal",
                "score": float(score),
                "flow": {k: v for k, v in flow.items() if k != "label"},
            })

        return results

    def evaluate(self, flows):
        """evaluate model against labeled data"""
        labeled = [f for f in flows if "label" in f]
        if not labeled:
            print("[warn] no labeled data for evaluation")
            return {}

        feature_matrix = np.array([extract_features(f) for f in labeled])
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=1e6, neginf=-1e6)
        scaled = self.scaler.transform(feature_matrix)

        predictions = self.model.predict(scaled)
        true_labels = [f["label"] for f in labeled]

        report = classification_report(
            true_labels, predictions,
            target_names=["anomaly", "normal"],
            output_dict=True,
        )
        return report

    def save(self, filepath):
        """save model and scaler to disk"""
        data = {"model": self.model, "scaler": self.scaler, "type": self.model_type}
        with open(filepath, "wb") as f:
            pickle.dump(data, f)
        print(f"[probaduce] model saved to {filepath}")

    def load(self, filepath):
        """load model and scaler from disk"""
        with open(filepath, "rb") as f:
            data = pickle.load(f)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.model_type = data["type"]
        print(f"[probaduce] model loaded from {filepath}")


def print_results(results, as_json=False, show_normal=False):
    anomalies = [r for r in results if r["prediction"] == "anomaly"]

    if as_json:
        output = {"total": len(results), "anomalies": len(anomalies), "results": results}
        print(json.dumps(output, indent=2))
        return

    print(f"\n[probaduce] analyzed {len(results)} flows, {len(anomalies)} anomalies")
    print()

    for r in results:
        if r["prediction"] == "normal" and not show_normal:
            continue
        status = "ANOMALY" if r["prediction"] == "anomaly" else "NORMAL"
        flow = r["flow"]
        print(f"  [{status}] score={r['score']:.3f} "
              f"src_bytes={flow.get('src_bytes', 0):.0f} "
              f"dst_bytes={flow.get('dst_bytes', 0):.0f} "
              f"duration={flow.get('duration', 0):.1f}s "
              f"ports={flow.get('unique_dst_ports', 0):.0f}")


def main():
    parser = argparse.ArgumentParser(description="ml anomaly detection engine")
    parser.add_argument("command", choices=["train", "predict", "evaluate", "demo"],
                        help="operation mode")
    parser.add_argument("-f", "--file", help="flow data file (csv or json)")
    parser.add_argument("-m", "--model-file", default="probaduce_model.pkl",
                        help="model file path")
    parser.add_argument("--model-type", default="isolation_forest",
                        choices=["isolation_forest", "one_class_svm"],
                        help="ml model type")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="expected anomaly ratio")
    parser.add_argument("--json", action="store_true", help="json output")
    parser.add_argument("--show-normal", action="store_true", help="show normal flows too")
    args = parser.parse_args()

    detector = AnomalyDetector(
        model_type=args.model_type,
        contamination=args.contamination,
    )

    if args.command == "demo":
        print("[probaduce] generating synthetic flow data")
        flows = generate_synthetic_flows()

        train_stats = detector.train(flows)
        print(f"[probaduce] training stats: {json.dumps(train_stats, indent=2)}")

        results = detector.predict(flows)
        print_results(results, args.json, args.show_normal)

        eval_report = detector.evaluate(flows)
        if eval_report:
            print(f"\n[probaduce] evaluation:")
            print(json.dumps(eval_report, indent=2))

        detector.save(args.model_file)
        return

    if args.command == "train":
        if not args.file:
            print("[error] data file required for training")
            sys.exit(1)

        if args.file.endswith(".json"):
            flows = parse_flow_json(args.file)
        else:
            flows = parse_flow_csv(args.file)

        if not flows:
            print("[error] no flow data loaded")
            sys.exit(1)

        train_stats = detector.train(flows)
        print(json.dumps(train_stats, indent=2))
        detector.save(args.model_file)

    elif args.command == "predict":
        if not Path(args.model_file).exists():
            print(f"[error] model not found: {args.model_file}")
            sys.exit(1)

        detector.load(args.model_file)

        if not args.file:
            print("[error] data file required for prediction")
            sys.exit(1)

        if args.file.endswith(".json"):
            flows = parse_flow_json(args.file)
        else:
            flows = parse_flow_csv(args.file)

        results = detector.predict(flows)
        print_results(results, args.json, args.show_normal)

    elif args.command == "evaluate":
        if not Path(args.model_file).exists():
            print(f"[error] model not found: {args.model_file}")
            sys.exit(1)

        detector.load(args.model_file)

        if not args.file:
            print("[error] labeled data file required")
            sys.exit(1)

        if args.file.endswith(".json"):
            flows = parse_flow_json(args.file)
        else:
            flows = parse_flow_csv(args.file)

        report = detector.evaluate(flows)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
