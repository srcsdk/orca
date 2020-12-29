#!/usr/bin/env python3
"""ml model evasion testing for anomaly detection systems"""

import argparse
import copy
import json
import os
import pickle
import sys
import time
from pathlib import Path

import numpy as np

try:
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("[error] sklearn required: pip install scikit-learn", file=sys.stderr)
    sys.exit(1)


SAFETY_DISCLAIMER = (
    "sike is an adversarial testing tool for validating ml-based detection systems. "
    "only use against your own models and infrastructure. "
    "all generated traffic is synthetic and never leaves the local system."
)


def verify_safety():
    """ensure tool is being used responsibly"""
    env_check = os.environ.get("SIKE_AUTHORIZED", "")
    if env_check != "1" and not sys.stdin.isatty():
        print("[warn] set SIKE_AUTHORIZED=1 to confirm authorized usage")
    return True


def load_model(model_path):
    """load a probaduce model for testing"""
    try:
        with open(model_path, "rb") as f:
            data = pickle.load(f)
        return data["model"], data["scaler"]
    except (FileNotFoundError, KeyError) as e:
        print(f"[error] failed to load model: {e}")
        sys.exit(1)


class FeaturePerturbation:
    """perturb flow features to test model boundaries"""

    def __init__(self, model, scaler):
        self.model = model
        self.scaler = scaler
        self.rng = np.random.RandomState(42)

    def _score_features(self, features):
        """get anomaly score for a feature vector"""
        scaled = self.scaler.transform(features.reshape(1, -1))
        score = self.model.decision_function(scaled)[0]
        prediction = self.model.predict(scaled)[0]
        return score, prediction

    def gradient_estimate(self, features, epsilon=0.01):
        """estimate gradient of decision function numerically"""
        base_score, _ = self._score_features(features)
        gradients = np.zeros_like(features)

        for i in range(len(features)):
            perturbed = features.copy()
            perturbed[i] += epsilon
            new_score, _ = self._score_features(perturbed)
            gradients[i] = (new_score - base_score) / epsilon

        return gradients

    def targeted_perturbation(self, features, max_steps=100, step_size=0.1):
        """perturb features to cross decision boundary"""
        current = features.copy()
        trajectory = []

        for step in range(max_steps):
            score, pred = self._score_features(current)
            trajectory.append({
                "step": step,
                "score": float(score),
                "prediction": int(pred),
                "features": current.tolist(),
            })

            if pred == 1:  # successfully evaded (classified as normal)
                return current, trajectory

            gradients = self.gradient_estimate(current)
            grad_norm = np.linalg.norm(gradients)
            if grad_norm > 0:
                current = current + step_size * (gradients / grad_norm)

            # keep features physically plausible
            current = np.maximum(current, 0)

        return current, trajectory

    def random_perturbation(self, features, n_attempts=100, noise_scale=0.5):
        """random perturbation search for evasion"""
        base_score, base_pred = self._score_features(features)
        results = []

        for i in range(n_attempts):
            noise = self.rng.normal(0, noise_scale, size=features.shape)
            perturbed = np.maximum(features + noise, 0)
            score, pred = self._score_features(perturbed)

            results.append({
                "attempt": i,
                "score": float(score),
                "prediction": int(pred),
                "evaded": pred == 1,
                "l2_distance": float(np.linalg.norm(perturbed - features)),
            })

        return results

    def boundary_search(self, features, feature_idx, n_points=50):
        """find decision boundary along a single feature dimension"""
        base_val = features[feature_idx]
        search_range = np.linspace(0, base_val * 5, n_points)
        boundary_points = []

        prev_pred = None
        for val in search_range:
            test = features.copy()
            test[feature_idx] = val
            score, pred = self._score_features(test)
            boundary_points.append({
                "value": float(val),
                "score": float(score),
                "prediction": int(pred),
            })
            if prev_pred is not None and pred != prev_pred:
                boundary_points[-1]["boundary"] = True
            prev_pred = pred

        return boundary_points


class TrafficMutator:
    """mutate synthetic traffic to test detection robustness"""

    def __init__(self, model, scaler):
        self.model = model
        self.scaler = scaler
        self.rng = np.random.RandomState(42)

    def generate_anomalous_flow(self, attack_type="scan"):
        """generate a synthetic anomalous flow"""
        if attack_type == "scan":
            return np.array([
                0.5,      # short duration
                200,      # low src bytes
                50,       # very low dst bytes
                100,      # many src packets
                5,        # few dst packets
                4.0,      # high byte ratio
                20.0,     # high packet ratio
                2.0,      # small src packets
                10.0,     # small dst packets
                5.0,      # high port entropy
                50,       # many unique ports
                2.5,      # small avg packet
            ])
        elif attack_type == "exfil":
            return np.array([
                300,      # long duration
                5000000,  # very high src bytes
                1000,     # low dst bytes
                5000,     # many src packets
                10,       # few dst packets
                5000.0,   # extreme byte ratio
                500.0,    # extreme packet ratio
                1000.0,   # large src packets
                100.0,    # small dst packets
                0.5,      # low port entropy
                1,        # single port
                1000.0,   # large avg packet
            ])
        else:  # c2 beacon
            return np.array([
                60,       # regular interval
                500,      # small symmetric
                500,      # small symmetric
                5,        # few packets
                5,        # few packets
                1.0,      # even ratio
                1.0,      # even ratio
                100.0,    # consistent size
                100.0,    # consistent size
                0.1,      # single port
                1,        # single port
                100.0,    # consistent
            ])

    def mutate_to_evade(self, flow_features, strategy="blend"):
        """apply mutation strategy to evade detection"""
        mutated = flow_features.copy()

        if strategy == "blend":
            # blend anomalous features toward normal ranges
            normal_center = np.array([
                30, 3000, 10000, 20, 30, 0.3, 0.67,
                150, 333, 2.5, 2, 250,
            ])
            blend_factor = 0.3 + self.rng.random() * 0.4
            mutated = flow_features * (1 - blend_factor) + normal_center * blend_factor

        elif strategy == "padding":
            # add padding bytes to normalize ratios
            mutated[2] = mutated[1] * (0.8 + self.rng.random() * 1.5)  # balance bytes
            mutated[4] = mutated[3] * (0.5 + self.rng.random())  # balance packets
            mutated[5] = mutated[1] / max(mutated[2], 1)
            mutated[6] = mutated[3] / max(mutated[4], 1)

        elif strategy == "split":
            # split into multiple smaller flows
            split_factor = self.rng.randint(2, 6)
            mutated[1] /= split_factor
            mutated[2] /= split_factor
            mutated[3] /= split_factor
            mutated[4] /= split_factor
            mutated[0] /= split_factor

        elif strategy == "noise":
            # add gaussian noise
            noise = self.rng.normal(0, 0.3, size=mutated.shape) * np.abs(mutated)
            mutated = np.maximum(mutated + noise, 0)

        return mutated

    def evaluate_mutations(self, attack_type="scan", n_mutations=50):
        """test multiple mutation strategies against the model"""
        base_flow = self.generate_anomalous_flow(attack_type)
        base_scaled = self.scaler.transform(base_flow.reshape(1, -1))
        base_score = self.model.decision_function(base_scaled)[0]
        base_pred = self.model.predict(base_scaled)[0]

        results = {
            "attack_type": attack_type,
            "base_score": float(base_score),
            "base_detected": base_pred == -1,
            "strategies": {},
        }

        for strategy in ["blend", "padding", "split", "noise"]:
            evasions = 0
            scores = []
            for _ in range(n_mutations):
                mutated = self.mutate_to_evade(base_flow, strategy)
                scaled = self.scaler.transform(mutated.reshape(1, -1))
                score = self.model.decision_function(scaled)[0]
                pred = self.model.predict(scaled)[0]
                scores.append(float(score))
                if pred == 1:
                    evasions += 1

            results["strategies"][strategy] = {
                "evasion_rate": evasions / n_mutations,
                "mean_score": float(np.mean(scores)),
                "min_score": float(np.min(scores)),
                "max_score": float(np.max(scores)),
            }

        return results


def print_evasion_report(results, as_json=False):
    if as_json:
        print(json.dumps(results, indent=2))
        return

    print(f"\n[sike] evasion test: {results['attack_type']}")
    print(f"base detection: {'detected' if results['base_detected'] else 'missed'} "
          f"(score: {results['base_score']:.3f})")
    print()

    for strategy, stats in results["strategies"].items():
        evasion_pct = stats["evasion_rate"] * 100
        bar = "#" * int(evasion_pct / 2)
        print(f"  {strategy:10s} evasion: {evasion_pct:5.1f}% {bar}")
        print(f"             scores: mean={stats['mean_score']:.3f} "
              f"range=[{stats['min_score']:.3f}, {stats['max_score']:.3f}]")


def main():
    parser = argparse.ArgumentParser(description="ml model evasion testing")
    parser.add_argument("command", choices=["test", "boundary", "perturb", "full"],
                        help="test mode")
    parser.add_argument("-m", "--model", required=True, help="model file (probaduce format)")
    parser.add_argument("--attack", default="scan",
                        choices=["scan", "exfil", "c2"],
                        help="attack type to test")
    parser.add_argument("--feature", type=int, help="feature index for boundary search")
    parser.add_argument("--json", action="store_true", help="json output")
    parser.add_argument("-n", "--iterations", type=int, default=50, help="test iterations")
    args = parser.parse_args()

    verify_safety()
    print(f"[sike] {SAFETY_DISCLAIMER[:80]}...")
    print()

    model, scaler = load_model(args.model)

    if args.command == "test":
        mutator = TrafficMutator(model, scaler)
        results = mutator.evaluate_mutations(args.attack, args.iterations)
        print_evasion_report(results, args.json)

    elif args.command == "boundary":
        perturbation = FeaturePerturbation(model, scaler)
        mutator = TrafficMutator(model, scaler)
        flow = mutator.generate_anomalous_flow(args.attack)
        feature_idx = args.feature if args.feature is not None else 0
        points = perturbation.boundary_search(flow, feature_idx)

        if args.json:
            print(json.dumps(points, indent=2))
        else:
            for p in points:
                marker = " <-- BOUNDARY" if p.get("boundary") else ""
                status = "normal" if p["prediction"] == 1 else "anomaly"
                print(f"  value={p['value']:10.2f} score={p['score']:8.3f} "
                      f"pred={status}{marker}")

    elif args.command == "perturb":
        perturbation = FeaturePerturbation(model, scaler)
        mutator = TrafficMutator(model, scaler)
        flow = mutator.generate_anomalous_flow(args.attack)
        evaded, trajectory = perturbation.targeted_perturbation(flow)

        if args.json:
            print(json.dumps(trajectory, indent=2))
        else:
            print(f"[sike] targeted perturbation ({len(trajectory)} steps)")
            for t in trajectory[:5] + trajectory[-5:]:
                status = "evaded" if t["prediction"] == 1 else "detected"
                print(f"  step {t['step']:3d}: score={t['score']:.3f} ({status})")

    elif args.command == "full":
        mutator = TrafficMutator(model, scaler)
        all_results = {}
        for attack in ["scan", "exfil", "c2"]:
            results = mutator.evaluate_mutations(attack, args.iterations)
            all_results[attack] = results
            print_evasion_report(results, False)

        if args.json:
            print(json.dumps(all_results, indent=2))

        print("\n[sike] model robustness summary:")
        for attack, results in all_results.items():
            max_evasion = max(
                s["evasion_rate"] for s in results["strategies"].values()
            )
            print(f"  {attack}: max evasion rate = {max_evasion * 100:.1f}%")


if __name__ == "__main__":
    main()
