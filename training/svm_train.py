#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

FEATURE_COLUMNS = [
    "is_to_victim",
    "packet_rate_ewma",
    "packet_count_1s",
    "byte_count_1s",
    "avg_pkt_size",
    "pkt_size_std",
    "inter_arrival_std",
]


def _resolve_base_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    if (repo_root / "data" / "raw").exists():
        return repo_root

    kali_root = Path("/home/kali/sdn-icmp")
    if (kali_root / "data" / "raw").exists():
        return kali_root

    return repo_root


def _load_labeled_dataset(base_dir: Path) -> pd.DataFrame:
    normal_path = base_dir / "data" / "raw" / "feature_dataset_normal.csv"
    attack_path = base_dir / "data" / "raw" / "feature_dataset_attack.csv"

    missing = [str(p) for p in [normal_path, attack_path] if not p.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing dataset file(s): " + ", ".join(missing)
        )

    normal_df = pd.read_csv(normal_path)
    attack_df = pd.read_csv(attack_path)

    normal_df["label"] = 0
    attack_df["label"] = 1

    return pd.concat([normal_df, attack_df], ignore_index=True)


def _prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    missing_features = [f for f in FEATURE_COLUMNS if f not in df.columns]
    if missing_features:
        raise ValueError(
            "Required feature columns missing: " + ", ".join(missing_features)
        )

    X = df[FEATURE_COLUMNS].copy()
    for col in FEATURE_COLUMNS:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.fillna(0.0)

    y = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    return X, y


def main() -> None:
    base_dir = _resolve_base_dir()
    models_dir = base_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Base directory: {base_dir}")

    df = _load_labeled_dataset(base_dir)
    X, y = _prepare_features(df)

    print(f"[INFO] Total rows: {len(df)}")
    print(f"[INFO] Normal rows: {(y == 0).sum()} | Attack rows: {(y == 1).sum()}")
    print(f"[INFO] Feature set: {FEATURE_COLUMNS}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = SVC(kernel="rbf", C=10.0, gamma="scale", random_state=42)
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_test_scaled)
    cm = confusion_matrix(y_test, y_pred)

    print("\n=== CONFUSION MATRIX ===")
    print(cm)
    print("\n=== CLASSIFICATION REPORT ===")
    print(classification_report(y_test, y_pred, digits=4))

    model_path = models_dir / "svm_model.pkl"
    scaler_path = models_dir / "svm_scaler.pkl"
    feature_names_path = models_dir / "svm_feature_names.pkl"

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(FEATURE_COLUMNS, feature_names_path)

    print("\n=== SAVED ARTIFACTS ===")
    print(f"Model        : {model_path}")
    print(f"Scaler       : {scaler_path}")
    print(f"Feature names: {feature_names_path}")


if __name__ == "__main__":
    main()
