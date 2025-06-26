# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
import pandas as pd
import os

# ======================== 2. CONNEXION NEO4J ========================
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")
graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ======================== 3. CHARGEMENT CSV NESSUS ========================
NESSUS_CSV_PATH = "data/nessus_sample.csv"

def load_nessus_data(path):
    df = pd.read_csv(path)
    df = df.fillna("")  # éviter les NaN
    return df

# ======================== 4. INJECTION DANS NEO4J ========================
def inject_nessus_to_neo4j(df):
    for idx, row in df.iterrows():
        host_ip = row.get("Host", "")
        plugin_id = str(row.get("Plugin ID", "")).strip()
        plugin_name = row.get("Name", "")
        port = str(row.get("Port", ""))
        protocol = row.get("Protocol", "")
        cve_list = str(row.get("CVE", "")).split(",")

        # 🔹 Noeud Host
        host_node = Node("Host", name=host_ip)
        graph.merge(host_node, "Host", "name")

        # 🔹 Noeud Plugin
        plugin_node = Node("Plugin", id=plugin_id, name=plugin_name)
        graph.merge(plugin_node, "Plugin", "id")

        # 🔹 Port
        if port:
            port_node = Node("Port", number=port, protocol=protocol)
            graph.merge(port_node, "Port", "number")
            graph.merge(Relationship(host_node, "EXPOSES", port_node))
            graph.merge(Relationship(port_node, "RUNS_PLUGIN", plugin_node))
        else:
            graph.merge(Relationship(host_node, "RUNS_PLUGIN", plugin_node))

        # 🔹 CVE(s)
        for cve in cve_list:
            cve = cve.strip()
            if cve.startswith("CVE-"):
                cve_node = Node("CVE", name=cve, source="Nessus")
                graph.merge(cve_node, "CVE", "name")
                graph.merge(Relationship(plugin_node, "DETECTS", cve_node))

# ======================== 5. PIPELINE ========================
def pipeline_kg2():
    print("📥 Chargement des données Nessus...")
    df = load_nessus_data(NESSUS_CSV_PATH)
    print(f"📊 {len(df)} lignes détectées.")
    inject_nessus_to_neo4j(df)
    print("✅ Données Nessus injectées dans le graphe.")

# ======================== 6. EXÉCUTION ========================
if __name__ == "__main__":
    pipeline_kg2()

