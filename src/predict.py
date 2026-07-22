"""
MeTHash - Prediction Module
Loads the trained model and makes predictions on single or batch URLs.
"""

import argparse
import sys
import warnings
from pathlib import Path

import numpy as np
import joblib
import pandas as pd

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.feature_engineering import extract_features, get_feature_names

warnings.filterwarnings('ignore')

# Constants
MODEL_DIR = Path(__file__).resolve().parent.parent / 'models'

LABEL_NAMES = {0: 'benign', 1: 'phishing', 2: 'malware', 3: 'defacement'}
LABEL_EMOJIS = {0: '🟢', 1: '🔴', 2: '🟠', 3: '🟡'}


class URLPredictor:
    """Loads model and features, then predicts URL classifications."""

    def __init__(self, model_path: str = None, features_path: str = None):
        model_path = model_path or str(MODEL_DIR / 'url_model.sav')
        features_path = features_path or str(MODEL_DIR / 'feature_names.joblib')

        print(f"[*] Loading model from: {model_path}")
        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(features_path)
        print(f"[✓] Model loaded successfully!")
        print(f"    Features: {len(self.feature_names)}")

    def predict(self, url: str) -> dict:
        """
        Predict the category of a single URL.

        Returns
        -------
        dict with keys: url, prediction, probability, label
        """
        features = extract_features(url)
        # Ensure feature ordering matches training
        X = np.array([[features.get(f, 0) for f in self.feature_names]])

        pred_idx = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]

        label = LABEL_NAMES.get(pred_idx, 'unknown')
        probs = {LABEL_NAMES.get(i, f'class_{i}'): float(prob)
                 for i, prob in enumerate(probabilities)}

        return {
            'url': url,
            'prediction': label,
            'emoji': LABEL_EMOJIS.get(pred_idx, '⚪'),
            'probability': float(probabilities[pred_idx]),
            'probabilities': probs,
            'class_id': int(pred_idx),
        }

    def predict_batch(self, urls: list) -> list:
        """Predict categories for a list of URLs."""
        return [self.predict(url) for url in urls]

    def predict_dataframe(self, df: pd.DataFrame, url_col: str = 'url') -> pd.DataFrame:
        """Add predictions as new columns to a DataFrame."""
        results = df[url_col].apply(self.predict)
        df['prediction'] = results.apply(lambda r: r['prediction'])
        df['probability'] = results.apply(lambda r: r['probability'])
        return df


def main():
    parser = argparse.ArgumentParser(description='Predict URL maliciousness')
    parser.add_argument('--url', type=str, help='Single URL to analyze')
    parser.add_argument('--file', type=str, help='CSV file with URLs to analyze')
    parser.add_argument('--url-col', type=str, default='url',
                        help='Column name for URLs in CSV (default: url)')
    parser.add_argument('--output', type=str, help='Output CSV file for batch results')
    args = parser.parse_args()

    predictor = URLPredictor()

    if args.url:
        # Single URL prediction
        result = predictor.predict(args.url)
        print('\n' + '=' * 50)
        print(f'   URL: {result["url"]}')
        print(f'   Prédiction: {result["emoji"]} {result["prediction"].upper()}')
        print(f'   Confiance: {result["probability"]:.2%}')
        print('=' * 50)
        print('   Probabilités détaillées:')
        for label, prob in sorted(result['probabilities'].items()):
            bar = '█' * int(prob * 50)
            print(f'     {label:<12s} {prob:>6.2%} |{bar}')
        print()

    elif args.file:
        # Batch prediction from CSV
        print(f'[*] Loading URLs from: {args.file}')
        df = pd.read_csv(args.file)
        if args.url_col not in df.columns:
            print(f'[!] Column "{args.url_col}" not found. Available: {list(df.columns)}')
            return

        print(f'[*] Predicting {len(df)} URLs...')
        df = predictor.predict_dataframe(df, url_col=args.url_col)

        if args.output:
            df.to_csv(args.output, index=False)
            print(f'[✓] Results saved to: {args.output}')
        else:
            print(df[['url', 'prediction', 'probability']].to_string())

        # Summary
        print(f'\n📊 Summary:')
        print(df['prediction'].value_counts().to_string())

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
