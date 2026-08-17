# Pipeline de collecte et de prédiction d'exploitabilité des vulnérabilités CVE par Machine Learning

Projet de fin d'étude — DU Data Analytics, Paris 1 Panthéon-Sorbonne (2025-2026)

## Contexte

Le score CVSS mesure la sévérité théorique d'une vulnérabilité, pas sa probabilité d'être réellement exploitée. Ce projet construit un pipeline ML qui prédit si une CVE sera exploitée dans la nature, à partir des données disponibles au moment de sa publication, et compare ce modèle au score EPSS.

## Sources de données

| Source | Usage |
|---|---|
| [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0) | Description, CVSS v3, CWE, références |
| [EPSS API](https://api.first.org/data/v1/epss) | Score et percentile d'exploitation (feature + baseline) |
| [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Label cible `is_exploited` |

## Architecture

```
[NVD API] ──┐
[EPSS API] ─┼──► Collecte & stockage ──► Feature engineering ──► Modèle ML ──► Dashboard
[CISA KEV] ─┘
```

## Structure du repo

```
data/
├── raw/          # données brutes des APIs
└── processed/    # features engineered
src/
├── collect/      # scripts de collecte NVD, EPSS, KEV
├── features/     # feature engineering
├── models/       # entraînement, évaluation
└── dashboard/    # app Streamlit
notebooks/        # exploration EDA
tests/
```

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp .env.example .env    # puis renseigner NVD_API_KEY (optionnel, gratuit)
```

## Pipeline

```bash
python -m src.collect.run_collect --incremental   # ou --full pour tout l'historique NVD
python -m src.features.build_features
python -m src.models.train
```

## Modélisation

- Cible : `is_exploited` (binaire, depuis CISA KEV) — fortement déséquilibrée (~0.4% de CVE exploitées sur 378k)
- Modèles : XGBoost (principal), LightGBM, Random Forest, régression logistique (baselines)
- Split train/test **temporel** (les CVE les plus anciennes en train, les plus récentes en test — pas de split aléatoire)
- Déséquilibre : `class_weight='balanced'` (RF, LogReg) et `scale_pos_weight` (XGBoost). **LightGBM est volontairement laissé sans repondération** — `is_unbalance=True` fait chuter son AUC de test de 0.95 à 0.69 sur ce ratio ~200:1, contrairement aux autres modèles
- Suivi des expériences : MLflow (store local SQLite sous `mlruns/`) — `mlflow ui --backend-store-uri sqlite:///mlruns/mlflow.db`
- Interprétabilité : SHAP (`src/models/interpret.py`) — importance globale et explication par CVE (`explain_cve`), réutilisées par le futur dashboard
- Résultats détaillés et visualisations (EDA, courbes ROC/PR, SHAP) : [`notebooks/01_results_overview.ipynb`](notebooks/01_results_overview.ipynb)

### Résultats (test set, split temporel)

| Modèle | ROC-AUC | PR-AUC | F1 | Bat EPSS ? |
|---|---|---|---|---|
| Régression logistique | 0.992 | 0.552 | 0.207 | ✅ (AUC) |
| **XGBoost** | **0.992** | **0.566** | **0.547** | ✅ |
| Baseline EPSS | 0.982 | 0.540 | 0.540 | — |
| Random Forest | 0.977 | 0.543 | 0.420 | ❌ |
| LightGBM | 0.946 | 0.341 | 0.482 | ❌ |

XGBoost offre le meilleur compromis global (PR-AUC et F1 les plus élevés) et dépasse la baseline EPSS sur toutes les métriques.

## Métriques de succès

- ✅ AUC-ROC > 0.80 sur le test set (tous les modèles)
- ✅ Le modèle bat EPSS seul comme baseline (XGBoost)
- ⬜ Dashboard fonctionnel avec prédiction en temps réel sur un CVE-ID saisi
- ⬜ Rapport d'analyse rédigé (méthodologie, résultats, limites)
