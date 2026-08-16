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
cp .env.example .env    # puis renseigner NVD_API_KEY (optionnel)
```

## Modélisation

- Cible : `is_exploited` (binaire, depuis CISA KEV), déséquilibrée
- Modèles : XGBoost (principal), LightGBM, Random Forest, régression logistique (baselines)
- Split train/test **temporel** (pas aléatoire)
- Évaluation : AUC-ROC, precision-recall, F1 sur la classe positive
- Interprétabilité : SHAP

## Métriques de succès

- AUC-ROC > 0.80 sur le test set
- Le modèle bat EPSS seul comme baseline
- Dashboard fonctionnel avec prédiction en temps réel sur un CVE-ID saisi
- Rapport d'analyse rédigé (méthodologie, résultats, limites)
