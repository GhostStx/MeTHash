#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# MeTHash - Script de configuration
# ═══════════════════════════════════════════════════════════════════════════

set -e

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║         🔗 MeTHash - Setup Script           ║"
echo "  ║   URL Malicious Detection with ML           ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Créer l'environnement virtuel ──────────────────────────────────
if [ ! -d "url-venv" ]; then
    echo "[1/4] Création de l'environnement virtuel..."
    python3 -m venv url-venv
    echo "      ✅ url-venv créé"
else
    echo "[1/4] ✅ url-venv existe déjà"
fi

# ── 2. Activer et installer les dépendances ────────────────────────────
echo "[2/4] Installation des dépendances..."
source url-venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "      ✅ Dépendances installées"

# ── 3. Vérifier la présence du dataset ─────────────────────────────────
echo "[3/4] Vérification du dataset..."
if [ -f "data/malicious_phish.csv" ]; then
    echo "      ✅ Dataset trouvé dans data/malicious_phish.csv"
else
    echo "      ⚠️  Dataset non trouvé dans data/"
    echo "      📥 Téléchargez-le depuis Kaggle:"
    echo "         https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset"
    echo ""
    echo "      Ou utilisez kagglehub:"
    echo "         pip install kagglehub"
    echo "         python -c \"import kagglehub; kagglehub.dataset_download('sid321axn/malicious-urls-dataset')\""
fi

# ── 4. Initialiser Git ─────────────────────────────────────────────────
echo "[4/4] Initialisation Git..."
if [ ! -d ".git" ]; then
    git init
    git add -A
    git commit -m "Initial commit: MeTHash project structure"
    echo "      ✅ Dépôt Git initialisé"
else
    echo "      ✅ Dépôt Git existe déjà"
fi

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║         ✅ Configuration terminée !          ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""
echo "  📋 Prochaines étapes :"
echo ""
echo "  1. Entraîner le modèle :"
echo "     $ source url-venv/bin/activate"
echo "     $ python src/train_model.py --data data/malicious_phish.csv"
echo ""
echo "  2. Lancer l'application web :"
echo "     $ python app/app.py"
echo ""
echo "  3. Ouvrir le navigateur :"
echo "     http://127.0.0.1:5000"
echo ""
