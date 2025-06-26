# cyber-digital-twin
# 🛡️ Cyber Digital Twin for Vulnerability Management

Ce projet implémente un jumeau numérique en cybersécurité basé sur un Knowledge Graph fusionné des vulnérabilités (NVD) et des données d’audit réseau (Nessus).

## 📁 Structure du projet


## 🚀 Fonctionnalités

- Extraction automatique des CVEs depuis la NVD (API REST)
- Insertion des scans Nessus
- Alignement et fusion sémantique
- Raisonnement (propagation d'impact)
- Embeddings KG (TransE, RotatE)
- Prédiction de vulnérabilités (R-GCN)
- Visualisation interactive (Streamlit, PyVis)
- Pipeline automatisé via GitHub Actions

## 📦 Installation

```bash
pip install -r requirements.txt
#"💻 Exécution manuelle"
# Exécution manuelle complète du pipeline :
python cskg/collect_nvd.py
python cskg/inject_nessus.py
python cskg/align_and_merge.py
python cskg/propagate_impacts.py
python cskg/embeddings_train.py
python cskg/r_gcn_predict.py
python cskg/visualization.py

# Lancer l'interface utilisateur
streamlit run cskg/app.py
