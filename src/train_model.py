"""
MeTHash - Model Training Pipeline
Trains a Random Forest classifier to detect malicious URLs.
"""

import argparse
import os
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.feature_engineering import extract_features, get_feature_names

warnings.filterwarnings('ignore')

# ── Constants ───────────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).resolve().parent.parent / 'data'
MODEL_DIR = Path(__file__).resolve().parent.parent / 'models'
MODEL_DIR.mkdir(exist_ok=True)

LABEL_MAP = {'benign': 0, 'phishing': 1, 'malware': 2, 'defacement': 3}
LABEL_INV = {v: k for k, v in LABEL_MAP.items()}


def load_data(filepath: str) -> pd.DataFrame:
    """
    Load CSV dataset and encode labels.

    Expected columns: 'url' (str), 'type' (str: benign/phishing/malware/defacement)
    """
    print(f"[*] Loading dataset from: {filepath}")
    df = pd.read_csv(filepath)

    # Detect the label column automatically
    possible_label_cols = ['type', 'label', 'category', 'class', 'Type', 'Label']
    label_col = None
    for col in possible_label_cols:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        # Assume the last column is the label
        label_col = df.columns[-1]
        print(f"[!] No known label column found. Using '{label_col}' as label.")

    # Rename for consistency
    df.rename(columns={label_col: 'type'}, inplace=True)

    # Normalize labels
    df['type'] = df['type'].str.lower().str.strip()
    df['type'] = df['type'].map(LABEL_MAP)

    # Drop rows with unknown labels
    before = len(df)
    df = df.dropna(subset=['type'])
    df['type'] = df['type'].astype(int)

    # Ensure URL column exists
    possible_url_cols = ['url', 'URL', 'Url', 'domain']
    url_col = None
    for col in possible_url_cols:
        if col in df.columns:
            url_col = col
            break

    if url_col is None:
        raise ValueError("No URL column found in dataset!")

    df.rename(columns={url_col: 'url'}, inplace=True)
    df = df[['url', 'type']].dropna()

    print(f"[✓] Loaded {len(df)} samples (dropped {before - len(df)} invalid).")
    print(f"    Class distribution:\n{df['type'].value_counts().rename(LABEL_INV)}")
    return df


def extract_all_features(df: pd.DataFrame) -> pd.DataFrame:
    """Apply feature extraction to every URL in the DataFrame."""
    print("[*] Extracting features from URLs...")
    records = df['url'].apply(extract_features)
    features_df = pd.DataFrame(records.tolist())
    print(f"[✓] Extracted {features_df.shape[1]} features from {len(features_df)} URLs.")
    return features_df


def train_model(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """Train a Random Forest classifier with SMOTE."""
    print("[*] Applying SMOTE for class balancing...")
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
    print(f"    After SMOTE: {X_resampled.shape[0]} samples")

    print("[*] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=30,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced',
        verbose=1,
    )
    model.fit(X_resampled, y_resampled)
    print("[✓] Training complete!")
    return model


def evaluate_model(model: RandomForestClassifier, X_test: np.ndarray,
                   y_test: np.ndarray, feature_names: list):
    """Print classification report and feature importance."""
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\nAccuracy: {accuracy:.4f}")
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=list(LABEL_MAP.keys())))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"           {'  '.join(f'{k:>10}' for k in LABEL_MAP.keys())}")
    for i, label in enumerate(LABEL_MAP.keys()):
        row = f'{label:>12} ' + '  '.join(f'{v:>10}' for v in cm[i])
        print(row)

    # Feature importance
    print("\nTop 15 Most Important Features:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:15]
    for i, idx in enumerate(indices):
        print(f"  {i+1:>2}. {feature_names[idx]:<25s} {importances[idx]:.4f}")

    return accuracy


def save_model(model: RandomForestClassifier, feature_names: list, accuracy: float):
    """Save the trained model and feature list."""
    model_path = MODEL_DIR / 'url_model.sav'
    features_path = MODEL_DIR / 'feature_names.joblib'

    joblib.dump(model, model_path)
    joblib.dump(feature_names, features_path)

    # Save metadata alongside
    metadata = {
        'accuracy': accuracy,
        'feature_count': len(feature_names),
        'features': feature_names,
        'model_type': 'RandomForest',
    }
    joblib.dump(metadata, MODEL_DIR / 'metadata.joblib')

    print(f"\n[✓] Model saved to: {model_path}")
    print(f"[✓] Features saved to: {features_path}")
    print(f"[✓] Metadata saved to: {MODEL_DIR / 'metadata.joblib'}")
    print(f"\n    Model size: {os.path.getsize(model_path) / 1024 / 1024:.2f} MB")


def main():
    parser = argparse.ArgumentParser(description='Train URL malicious detection model')
    parser.add_argument('--data', type=str, default=str(DATA_DIR / 'malicious_phish.csv'),
                        help='Path to the CSV dataset')
    parser.add_argument('--test-size', type=float, default=0.3,
                        help='Proportion of data for testing (default: 0.3)')
    parser.add_argument('--random-state', type=int, default=42,
                        help='Random seed for reproducibility')
    args = parser.parse_args()

    # ── 1. Load data ─────────────────────────────────────────────────────
    df = load_data(args.data)

    # ── 2. Feature engineering ───────────────────────────────────────────
    X = extract_all_features(df)
    feature_names = list(X.columns)
    y = df['type'].values

    # ── 3. Train/test split ──────────────────────────────────────────────
    print(f"[*] Splitting data (train={1-args.test_size:.0%}, test={args.test_size:.0%})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state,
        stratify=y,
    )
    print(f"    Train: {X_train.shape[0]} samples, Test: {X_test.shape[0]} samples")

    # ── 4. Train model ───────────────────────────────────────────────────
    model = train_model(X_train.values, y_train)

    # ── 5. Evaluate ──────────────────────────────────────────────────────
    accuracy = evaluate_model(model, X_test.values, y_test, feature_names)

    # ── 6. Save ──────────────────────────────────────────────────────────
    save_model(model, feature_names, accuracy)

    print("\n" + "=" * 60)
    print("🎯 TRAINING PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == '__main__':
    main()
