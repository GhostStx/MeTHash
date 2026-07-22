# 🔗 MeTHash — Malicious URL Detection with Machine Learning

> Analysez et prédisez si une URL est **bénigne, malveillante, de phishing ou de défacement** grâce au Machine Learning.

## 📋 Table des matières

- [Aperçu](#aperçu)
- [Architecture du Projet](#architecture-du-projet)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Pipeline ML](#pipeline-ml)
- [Caractéristiques (Features)](#caractéristiques-features)
- [Améliorations Futures](#améliorations-futures)
- [Licence](#licence)

---

## 🔍 Aperçu

Ce projet implémente un **pipeline complet de Machine Learning** pour la détection d'URLs malveillantes. Il utilise un **classifieur Random Forest** entraîné sur des caractéristiques extraites des URLs (longueur, présence de chiffres, protocole, etc.) pour classer chaque URL en 4 catégories.

Le modèle atteint des performances élevées grâce à :
- Un **feature engineering** ciblé (16+ caractéristiques numériques)
- La gestion du déséquilibre des classes avec **SMOTE**
- Un algorithme **Random Forest** robuste et interprétable

## 🏗 Architecture du Projet

```
MeTHash/
├── data/                   # Jeux de données (à télécharger)
├── notebooks/              # Jupyter Notebooks d'exploration
├── src/                    # Code source Python
│   ├── feature_engineering.py   # Extraction des features
│   ├── train_model.py           # Entraînement du modèle
│   └── predict.py               # Prédiction unitaire
├── app/                    # Application Web Flask
│   ├── app.py              # Point d'entrée Flask
│   ├── templates/          # Templates HTML
│   └── static/             # Fichiers statiques (CSS)
├── models/                 # Modèles entraînés (ignorés par git)
├── requirements.txt        # Dépendances Python
└── README.md
```

## ⚙️ Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-utilisateur/MeTHash.git
cd MeTHash
```

### 2. Créer un environnement virtuel

```bash
python3 -m venv url-venv
source url-venv/bin/activate  # Linux/macOS
# ou
url-venv\Scripts\activate     # Windows
```

### 3. Installer les dépendances

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Télécharger le jeu de données

Téléchargez le dataset **malicious_phish** depuis [Kaggle](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) et placez le fichier CSV dans le dossier `data/`.

Ou utilisez directement :

```bash
# Exemple avec Kaggle API
kaggle datasets download -d sid321axn/malicious-urls-dataset -p data/ --unzip
```

### 5. Entraîner le modèle

```bash
python src/train_model.py --data data/malicious_phish.csv
```

## 🚀 Utilisation

### Application Web Flask

```bash
python app/app.py
```

Ouvrez votre navigateur à l'adresse : **http://127.0.0.1:5000**

Saisissez une URL dans le champ prévu et cliquez sur **Analyser** pour obtenir la prédiction.

### Prédiction en Ligne de Commande

```bash
python src/predict.py --url "http://example.com"
```

### Exemple de Résultat

```
URL: http://example.com
Prédiction: 🟢 Bénigne
Probabilités:
  - Bénigne:      0.9823
  - Phishing:     0.0102
  - Malware:      0.0045
  - Defacement:   0.0030
```

## 🧠 Pipeline ML

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Collecte des   │────▶│  Feature         │────▶│  SMOTE Oversampling │
│  Données (CSV)  │     │  Engineering     │     │  (équilibrage)      │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
                                                          │
                                                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Application    │◀────│  Modèle          │◀────│  Random Forest      │
│  Web (Flask)    │     │  (.sav)          │     │  Entraînement       │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
```

### Étapes détaillées

1. **Chargement** du dataset CSV avec Pandas
2. **Encodage** des labels (benign→0, phishing→1, malware→2, defacement→3)
3. **Extraction** de 16+ caractéristiques numériques depuis chaque URL
4. **Division** train/test (70%/30%) avec stratification
5. **Application** de SMOTE sur l'ensemble d'entraînement
6. **Entraînement** d'un Random Forest Classifier
7. **Évaluation** (Précision, Rappel, F1-score) sur le test set
8. **Sauvegarde** du modèle et de la liste des features avec joblib
9. **Déploiement** via une interface web Flask

## 📊 Caractéristiques (Features)

| Feature | Description |
|---------|-------------|
| `url_len` | Longueur totale de l'URL |
| `digits_count` | Nombre de chiffres dans l'URL |
| `special_chars_count` | Nombre de caractères spéciaux |
| `shortened` | Utilisation d'un raccourcisseur (bit.ly, tinyurl...) |
| `secure_http` | Présence du protocole HTTPS |
| `have_ip` | Présence d'une adresse IP dans le domaine |
| `nb_dots` | Nombre de points dans l'URL |
| `nb_hyphens` | Nombre de tirets |
| `nb_slash` | Nombre de slashes |
| `nb_question_mark` | Nombre de points d'interrogation |
| `nb_eq` | Nombre de signes égal |
| `nb_at` | Nombre de @ |
| `nb_and` | Nombre de & |
| `nb_or` | Nombre de | |
| `url_depth` | Profondeur de l'URL (nombre de / dans le path) |
| `hostname_len` | Longueur du hostname |
| `path_len` | Longueur du chemin |
| `query_len` | Longueur de la chaîne de requête |
| `is_encoded` | Si l'URL contient du encodage (%xx) |
| `tld_length` | Longueur du TLD (.com, .org...) |
| `domain_entropy` | Entropie du nom de domaine (caractères aléatoires) |
| `root_domain` | Hachage MD5 du domaine principal |

## 🚀 Améliorations Futures (Phase 6)

- [ ] **Deep Learning** : CNN ou modèles hybrides pour améliorer la précision
- [ ] **Analyse par lots** : Upload de fichier CSV pour analyser plusieurs URLs
- [ ] **Pipeline MLOps** : Apache Airflow + MLflow + Docker
- [ ] **Analyse réseau** : Détection d'intrusion avec UNSW-NB15
- [ ] **API REST** : Endpoint JSON pour intégration tierce

## 📄 Licence

Ce projet est fourni à titre éducatif. Utilisez-le de manière responsable.
