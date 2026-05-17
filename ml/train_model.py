"""
train_model.py — SessionSentry ML Training Pipeline

Run this once to generate a synthetic dataset and train the Random Forest model.
Usage:
    cd SessionSentry
    python ml/train_model.py
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix,
                             classification_report)
from sklearn.preprocessing import StandardScaler
import joblib

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.feature_extractor import FEATURE_COLUMNS

np.random.seed(42)

DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dataset', 'session_dataset.csv')
MODEL_PATH   = os.path.join(os.path.dirname(__file__), 'rf_model.pkl')
SCALER_PATH  = os.path.join(os.path.dirname(__file__), 'scaler.pkl')


# ─── Synthetic Data Generation ───────────────────────────────────────────────

def generate_normal_sessions(n=500):
    rows = []
    for _ in range(n):
        row = {
            'ip_change':              np.random.choice([0, 0, 0, 1], p=[0.95, 0.0, 0.0, 0.05]),
            'ip_frequency':           np.random.randint(1, 3),
            'ip_mismatch':            np.random.choice([0, 1], p=[0.97, 0.03]),
            'browser_change':         np.random.choice([0, 1], p=[0.97, 0.03]),
            'os_change':              np.random.choice([0, 1], p=[0.98, 0.02]),
            'cookie_reuse':           np.random.choice([0, 1], p=[0.96, 0.04]),
            'session_duration':       np.random.normal(600, 200),
            'session_idle_time':      np.random.normal(120, 60),
            'request_rate':           np.random.normal(8, 3),
            'request_variance':       np.random.normal(50, 20),
            'post_get_ratio':         np.random.normal(0.15, 0.05),
            'total_requests':         np.random.randint(5, 40),
            'page_depth':             np.random.randint(2, 10),
            'page_sequence_entropy':  np.random.uniform(0.2, 0.8),
            'admin_page_attempt':     0,
            'direct_page_access':     np.random.choice([0, 1], p=[0.9, 0.1]),
            'click_interval_avg':     np.random.normal(8, 3),
            'click_interval_std':     np.random.normal(4, 1),
            'night_activity_flag':    np.random.choice([0, 1], p=[0.92, 0.08]),
            'label':                  0
        }
        rows.append(row)
    return rows


def generate_hijacked_sessions(n=200):
    rows = []
    for _ in range(n):
        row = {
            'ip_change':              np.random.choice([0, 1], p=[0.1, 0.9]),
            'ip_frequency':           np.random.randint(2, 6),
            'ip_mismatch':            np.random.choice([0, 1], p=[0.05, 0.95]),
            'browser_change':         np.random.choice([0, 1], p=[0.15, 0.85]),
            'os_change':              np.random.choice([0, 1], p=[0.2, 0.8]),
            'cookie_reuse':           np.random.choice([0, 1], p=[0.1, 0.9]),
            'session_duration':       np.random.normal(180, 90),
            'session_idle_time':      np.random.normal(10, 5),
            'request_rate':           np.random.normal(45, 15),
            'request_variance':       np.random.normal(5, 3),
            'post_get_ratio':         np.random.normal(0.8, 0.2),
            'total_requests':         np.random.randint(30, 120),
            'page_depth':             np.random.randint(1, 5),
            'page_sequence_entropy':  np.random.uniform(0.0, 0.3),
            'admin_page_attempt':     np.random.choice([0, 1], p=[0.4, 0.6]),
            'direct_page_access':     np.random.choice([0, 1], p=[0.2, 0.8]),
            'click_interval_avg':     np.random.normal(0.5, 0.3),
            'click_interval_std':     np.random.normal(0.2, 0.1),
            'night_activity_flag':    np.random.choice([0, 1], p=[0.4, 0.6]),
            'label':                  1
        }
        rows.append(row)
    return rows


# ─── Training Pipeline ────────────────────────────────────────────────────────

def train():
    print("=" * 60)
    print("  SessionSentry — ML Training Pipeline")
    print("=" * 60)

    # Generate dataset
    print("\n[1/5] Generating synthetic dataset...")
    normal_data   = generate_normal_sessions(500)
    hijack_data   = generate_hijacked_sessions(200)
    all_data      = normal_data + hijack_data

    df = pd.DataFrame(all_data)

    # Clip negatives
    numeric_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    for col in ['session_duration', 'session_idle_time', 'request_rate',
                'request_variance', 'post_get_ratio', 'click_interval_avg',
                'click_interval_std']:
        df[col] = df[col].clip(lower=0)

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    print(f"    ✓ Dataset saved: {DATASET_PATH}")
    print(f"    ✓ Total samples: {len(df)} (Normal: 500, Hijacked: 200)")

    # Prepare features
    print("\n[2/5] Preprocessing features...")
    X = df[FEATURE_COLUMNS]
    y = df['label']

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, SCALER_PATH)
    print(f"    ✓ Scaler saved: {SCALER_PATH}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    ✓ Train: {len(X_train)} | Test: {len(X_test)}")

    # Train
    print("\n[3/5] Training Random Forest Classifier...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    print("    ✓ Model trained")

    # Evaluate
    print("\n[4/5] Evaluating model...")
    y_pred = clf.predict(X_test)
    acc   = accuracy_score(y_test, y_pred)
    prec  = precision_score(y_test, y_pred)
    rec   = recall_score(y_test, y_pred)
    f1    = f1_score(y_test, y_pred)
    cm    = confusion_matrix(y_test, y_pred)

    print(f"\n  {'Metric':<20} {'Score':>10}")
    print(f"  {'-'*32}")
    print(f"  {'Accuracy':<20} {acc*100:>9.2f}%")
    print(f"  {'Precision':<20} {prec*100:>9.2f}%")
    print(f"  {'Recall':<20} {rec*100:>9.2f}%")
    print(f"  {'F1 Score':<20} {f1*100:>9.2f}%")
    print(f"\n  Confusion Matrix:")
    print(f"  {cm}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Hijacked']))

    # Save
    print("\n[5/5] Saving model...")
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"    ✓ Model saved: {MODEL_PATH}")

    print("\n" + "=" * 60)
    print("  Training complete! Model ready for real-time detection.")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    train()
