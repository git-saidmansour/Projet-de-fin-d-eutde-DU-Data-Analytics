"""Streamlit dashboard for the CVE exploitability predictor.

Talks to the FastAPI backend (src.dashboard.api) over HTTP so the two
can be deployed and scaled independently.
"""

import os

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

API_URL = os.environ.get("API_URL", "http://localhost:8000")


def clean_feature_name(name: str) -> str:
    return name.split("__", 1)[-1].replace("_", " ")


@st.cache_data(ttl=300)
def fetch_vendor_categories() -> list[str]:
    resp = requests.get(f"{API_URL}/meta/vendor-categories", timeout=10)
    resp.raise_for_status()
    return resp.json()


@st.cache_data(ttl=300)
def fetch_cwe_categories() -> list[str]:
    resp = requests.get(f"{API_URL}/meta/cwe-categories", timeout=10)
    resp.raise_for_status()
    return resp.json()


@st.cache_data(ttl=60)
def fetch_cves(**params) -> pd.DataFrame:
    resp = requests.get(f"{API_URL}/cves", params=params, timeout=30)
    resp.raise_for_status()
    return pd.DataFrame(resp.json())


def fetch_cve_detail(cve_id: str):
    resp = requests.get(f"{API_URL}/cves/{cve_id}", timeout=10)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


st.set_page_config(page_title="CVE Exploitability Predictor", layout="wide")
st.title("Prédiction d'exploitabilité des CVE")
st.caption(
    "Score ML (XGBoost) vs score EPSS — priorisation des vulnérabilités à partir des données "
    "disponibles à leur publication (NVD, EPSS, CISA KEV)."
)

with st.sidebar:
    st.header("Rechercher une CVE")
    cve_id_input = st.text_input("CVE-ID", placeholder="CVE-2024-12345")
    search = st.button("Analyser", type="primary")

    st.divider()
    st.header("Filtres")
    try:
        vendor_options = fetch_vendor_categories()
        cwe_options = fetch_cwe_categories()
        api_available = True
    except requests.RequestException:
        vendor_options, cwe_options = [], []
        api_available = False
        st.error(f"API indisponible sur {API_URL}")

    vendor_filter = st.selectbox("Vendor category", ["(tous)"] + vendor_options)
    cwe_filter = st.selectbox("CWE category", ["(tous)"] + cwe_options)
    cvss_range = st.slider("Plage CVSS", 0.0, 10.0, (0.0, 10.0))
    n_results = st.slider("Nombre de résultats", 10, 200, 50)

if search and cve_id_input and api_available:
    detail = fetch_cve_detail(cve_id_input.strip().upper())
    if detail is None:
        st.warning(f"{cve_id_input} introuvable dans le jeu de données collecté.")
    else:
        st.subheader(f"{detail['cve_id']}")
        if detail.get("description"):
            st.write(detail["description"])

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Probabilité prédite (ML)", f"{detail['predicted_probability']:.1%}")
        col2.metric("Score EPSS", f"{detail['epss_score']:.1%}" if detail["epss_score"] is not None else "n/a")
        col3.metric("CVSS", detail["cvss_base_score"] if detail["cvss_base_score"] is not None else "n/a")
        col4.metric("Exploitée (CISA KEV) ?", "Oui" if detail["is_exploited"] else "Non")

        st.markdown("**Pourquoi ce score ?** (contributions SHAP)")
        contrib_df = pd.DataFrame(detail["top_contributions"])
        contrib_df["feature"] = contrib_df["feature"].apply(clean_feature_name)
        contrib_df["direction"] = contrib_df["shap_value"].apply(lambda v: "augmente le risque" if v > 0 else "diminue le risque")

        fig = px.bar(
            contrib_df.sort_values("shap_value"),
            x="shap_value",
            y="feature",
            color="direction",
            orientation="h",
            color_discrete_map={"augmente le risque": "#C44E52", "diminue le risque": "#4C72B0"},
        )
        fig.update_layout(yaxis_title="", xaxis_title="Valeur SHAP", legend_title="")
        st.plotly_chart(fig, width='stretch')
        st.divider()

st.subheader("CVE récentes triées par risque prédit")

if api_available:
    params = {"limit": n_results}
    if vendor_filter != "(tous)":
        params["vendor_category"] = vendor_filter
    if cwe_filter != "(tous)":
        params["cwe_category"] = cwe_filter
    params["cvss_min"], params["cvss_max"] = cvss_range

    df = fetch_cves(**params)

    if df.empty:
        st.info("Aucune CVE ne correspond à ces filtres.")
    else:
        display_df = df.copy()
        display_df["predicted_probability"] = display_df["predicted_probability"].map(lambda v: f"{v:.1%}")
        display_df["epss_score"] = display_df["epss_score"].map(lambda v: f"{v:.1%}" if pd.notna(v) else "n/a")
        st.dataframe(
            display_df[
                [
                    "cve_id",
                    "published_date",
                    "cvss_base_score",
                    "epss_score",
                    "predicted_probability",
                    "vendor_category",
                    "cwe_category",
                    "is_exploited",
                ]
            ],
            width='stretch',
            hide_index=True,
        )

        st.subheader("Score ML vs score EPSS")
        scatter_fig = px.scatter(
            df,
            x="epss_score",
            y="predicted_probability",
            color=df["is_exploited"].map({0: "Non exploitée", 1: "Exploitée (KEV)"}),
            hover_data=["cve_id", "cvss_base_score"],
            labels={"epss_score": "Score EPSS", "predicted_probability": "Probabilité prédite (ML)", "color": ""},
        )
        scatter_fig.add_shape(type="line", x0=0, y0=0, x1=1, y1=1, line=dict(color="gray", dash="dash"))
        st.plotly_chart(scatter_fig, width='stretch')
