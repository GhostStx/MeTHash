"""
MeTHash - Flask Web Application
Provides a web interface for malicious URL detection.
"""

import io
import os
import sys
from pathlib import Path

import pandas as pd
from flask import Flask, render_template, request, jsonify, send_file

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.predict import URLPredictor

# ── App Initialization ──────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load the ML model at startup
MODEL_DIR = Path(__file__).resolve().parent.parent / 'models'
model_path = MODEL_DIR / 'url_model.sav'
features_path = MODEL_DIR / 'feature_names.joblib'

predictor = None

def get_predictor():
    """Lazy-load the predictor (available after training)."""
    global predictor
    if predictor is None:
        if not model_path.exists():
            return None
        try:
            predictor = URLPredictor(
                model_path=str(model_path),
                features_path=str(features_path),
            )
        except Exception as e:
            print(f"[!] Failed to load model: {e}")
            return None
    return predictor


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Render the main prediction page."""
    model_loaded = get_predictor() is not None
    return render_template('index.html', model_loaded=model_loaded)


@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict the category of a submitted URL.

    Accepts either:
      - Form data: request.form['url']
      - JSON:      {"url": "http://..."}
    """
    predictor_model = get_predictor()
    if predictor_model is None:
        return render_template('index.html',
                               error="Le modèle n'est pas encore entraîné. "
                                     "Exécutez d'abord: python src/train_model.py",
                               model_loaded=False)

    # Get URL from request
    url = None
    if request.is_json:
        data = request.get_json()
        url = data.get('url', '')
    else:
        url = request.form.get('url', '')

    url = url.strip()
    if not url:
        return render_template('index.html',
                               error="Veuillez entrer une URL valide.",
                               model_loaded=True)

    # Add scheme if missing
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url

    try:
        result = predictor_model.predict(url)

        if request.is_json:
            return jsonify({
                'success': True,
                'url': result['url'],
                'prediction': result['prediction'],
                'emoji': result['emoji'],
                'confidence': f"{result['probability']:.2%}",
                'probabilities': result['probabilities'],
            })

        return render_template('result.html',
                               url=result['url'],
                               prediction=result['prediction'],
                               emoji=result['emoji'],
                               confidence=f"{result['probability']:.2%}",
                               probabilities=result['probabilities'],
                               model_loaded=True)

    except Exception as e:
        error_msg = f"Erreur lors de l'analyse : {str(e)}"
        if request.is_json:
            return jsonify({'success': False, 'error': error_msg}), 500
        return render_template('index.html',
                               error=error_msg,
                               model_loaded=True)


# ── Batch analysis (CSV upload) ─────────────────────────────────────────

@app.route('/batch', methods=['GET', 'POST'])
def batch_analyze():
    """
    Upload a CSV file and analyze all URLs in batch.
    """
    predictor_model = get_predictor()
    model_loaded = predictor_model is not None

    if request.method == 'GET':
        return render_template('batch.html', model_loaded=model_loaded)

    if predictor_model is None:
        return render_template('batch.html',
                               error="Le modèle n'est pas encore entraîné.",
                               model_loaded=False)

    if 'file' not in request.files:
        return render_template('batch.html',
                               error="Aucun fichier fourni.",
                               model_loaded=True)

    file = request.files['file']
    if file.filename == '':
        return render_template('batch.html',
                               error="Nom de fichier vide.",
                               model_loaded=True)

    url_col = request.form.get('url_col', 'url').strip()

    try:
        df = pd.read_csv(file)
        if url_col not in df.columns:
            return render_template('batch.html',
                                   error=f'Colonne "{url_col}" introuvable. Colonnes disponibles: {list(df.columns)}',
                                   model_loaded=True)

        urls = df[url_col].dropna().tolist()
        results = []
        for u in urls:
            u = str(u).strip()
            if not u.startswith(('http://', 'https://', 'ftp://')):
                u = 'http://' + u
            try:
                r = predictor_model.predict(u)
                results.append({
                    'url': r['url'],
                    'prediction': r['prediction'],
                    'emoji': r['emoji'],
                    'confidence': f"{r['probability']:.2%}",
                })
            except Exception as e:
                results.append({
                    'url': u,
                    'prediction': 'error',
                    'emoji': '❌',
                    'confidence': str(e),
                })

        # Store in app config for download
        app.config['BATCH_RESULTS'] = results

        return render_template('batch.html',
                               results=results,
                               model_loaded=True)

    except Exception as e:
        return render_template('batch.html',
                               error=f"Erreur lors du traitement: {str(e)}",
                               model_loaded=True)


@app.route('/batch/download')
def batch_download():
    """Download batch results as CSV."""
    results = app.config.get('BATCH_RESULTS', [])
    if not results:
        return "Aucun résultat à télécharger.", 404

    output = io.StringIO()
    output.write('url,prediction,confidence\n')
    for r in results:
        output.write(f'{r["url"]},{r["prediction"]},{r["confidence"]}\n')

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='methash_results.csv',
    )


@app.route('/api/predict', methods=['POST'])
def api_predict():
    """
    JSON API endpoint for programmatic access.

    Request:  {"url": "http://example.com"}
    Response: {"success": true, "prediction": "benign", ...}
    """
    if not request.is_json:
        return jsonify({'success': False, 'error': 'JSON required'}), 400

    predictor_model = get_predictor()
    if predictor_model is None:
        return jsonify({'success': False,
                        'error': 'Model not trained. Run: python src/train_model.py'}), 503

    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'success': False, 'error': 'URL is required'}), 400

    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url

    try:
        result = predictor_model.predict(url)
        return jsonify({
            'success': True,
            'url': result['url'],
            'prediction': result['prediction'],
            'confidence': result['probability'],
            'probabilities': result['probabilities'],
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/health')
def health():
    """Health check endpoint."""
    predictor_model = get_predictor()
    return jsonify({
        'status': 'ok',
        'model_loaded': predictor_model is not None,
        'model_path': str(model_path) if model_path.exists() else None,
    })


# ── Main ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 55)
    print("  🔗 MeTHash - URL Malicious Detection")
    print("=" * 55)

    if get_predictor() is None:
        print("  ⚠️  Modèle non trouvé. Entraînez-le d'abord :")
        print("     python src/train_model.py --data data/malicious_phish.csv")
    else:
        print("  ✅ Modèle chargé avec succès !")

    print("  🌐 http://127.0.0.1:5000")
    print("=" * 55)

    app.run(host='127.0.0.1', port=5000, debug=True)
