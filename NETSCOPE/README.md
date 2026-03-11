# NETSCOPE v2.0 — Analyseur de Trafic Réseau

**NETSCOPE** est un outil d'audit réseau développé en **Python (Flask)** utilisant **Tshark** comme moteur de capture. Il analyse le trafic Wi-Fi ou Ethernet en temps réel, calcule un **Score de Santé (0-100)**, détecte les anomalies via Machine Learning et expose une interface web complète de type SOC-lite.

---

## Fonctionnalités

### Dashboard
- **Score de Santé (0-100)** calculé en temps réel selon le trafic détecté
- **Bannière d'alerte** si le score descend sous un seuil configurable
- **5 KPIs** : paquets totaux, IPs uniques, alertes, flux externes, score
- **Top Talkers** : top 5 sources IP et services par volume
- **Donut Chart** : répartition des protocoles (Chart.js)
- **Top IPs Externes** avec géolocalisation automatique (ip-api.com — drapeaux, ville, pays, ISP)
- **Sankey Diagram** (optionnel, Plotly) : visualisation interactive des flux src → dst

### Détection & Alertes
| Détection | Description |
|-----------|-------------|
| **Blacklist IP** | Alerte immédiate si une IP source/dest figure dans la blacklist (-15 pts/IP) |
| **Scan de Ports** | Détection si un hôte sonde > 15 ports distincts (-25 pts) |
| **Volume Anormal** | Alerte si un hôte transfère > 5× la moyenne ou > 500 KB (-10 pts) |
| **HTTP en clair** | Alerte si des credentials sont transmis en HTTP Basic Auth (-5 pts) |
| **TLS Suspect** | Certificat auto-signé ou empreinte JA3 malveillante connue (-10 pts) |
| **IA — Isolation Forest** | Détection d'anomalies statistiques (5 features : taille, protocole, port, IP externe, heure) |

### Analyse Modules (activables dans l'Admin)
- **Capture Haute Performance** : buffer mémoire élargi pour les liens 10Gbps+ (dumpcap/MMAP)
- **Fingerprint MAC** : résolution fabricant via base OUI (`mac-vendor-lookup`)
- **Analyse TLS/JA3** : extraction SNI, empreinte JA3, certificat X.509, détection C2 connus
- **IA — Isolation Forest** : `scikit-learn`, 5 features, filtre anti-bruit (seuil confiance 25%)
- **Sankey Visualization** : diagramme de flux interactif
- **Threat Intel — MISP** : vérification d'IPs et domaines contre une instance MISP
- **SOC/SIEM Webhook** : export JSON ou CEF vers Splunk HEC, Elastic, QRadar, ArcSight

### Journal des Flux
- Tableau paginé avec tri multi-colonnes et filtres par colonne
- **Lignes rouges** pour les paquets dont l'IP est blacklistée (badge `BL`)
- **Badge `EXT`** sur les connexions vers des IPs publiques
- **Lignes vertes** pour les IPs whitelistées
- Fenêtre modale d'inspection paquet (arborescence couches OSI complète)
- **Export CSV** avec BOM UTF-8 (compatible Excel) — inclut colonnes Externe/Blacklisté

### Historique
- Tableau de tous les scans passés avec durée, score, paquets, alertes
- **Graphique d'évolution du score** (Chart.js, 20 derniers scans, points colorés)
- Rechargement d'un rapport depuis le fichier JSON
- Purge individuelle ou globale

### Onglet Anomalies
- **5 compteurs** par catégorie : Blacklist / Scans de ports / IA / Volumes / TLS
- Alertes groupées par type avec code couleur et icône
- Vue détaillée de chaque alerte

### Administration
- **Modules** sous forme de cartes toggle (activation/désactivation visuelle)
- **SOC/SIEM** configurable depuis l'UI : URL webhook, token, format JSON ou CEF
- **Gouvernance** : whitelist et blacklist IP (une entrée par ligne)
- **Profils de scan** : sauvegarder/charger des configurations de scan dans `localStorage`
- **Seuil d'alerte** : déclenchement de bannière si score < N (configurable)
- **Statistiques de maintenance** : nb scans, score moyen, alertes totales, paquets totaux
- **Export/Import Config** : sauvegarde/restauration complète en JSON
- Toast notifications (remplacement des `alert()` natifs)

### Rapport PDF
- En-tête sombre avec logo NETSCOPE
- Block de score coloré avec label (SÉCURISÉ / ATTENTION / CRITIQUE)
- 5 KPIs en en-tête
- Alertes catégorisées avec couleurs par type
- Répartition protocoles avec barres de progression
- Top IPs Externes avec géolocalisation si disponible
- **Recommandations générées dynamiquement** selon les alertes réelles détectées

---

## Architecture

```
NETSCOPE/
├── app.py              # Serveur Flask — routes API, gestion historique/settings
├── analyzer.py         # Moteur d'analyse tshark — blacklist, ports, volumes, géo
├── capture_engine.py   # Capture réseau (tshark/dumpcap, mode standard/haute perf)
├── ai_engine.py        # Détection anomalies IsolationForest (scikit-learn)
├── tls_engine.py       # Analyse TLS — JA3 fingerprint, X.509, SNI
├── threat_intel.py     # Intégration MISP (PyMISP)
├── soc_engine.py       # Export SOC/SIEM — JSON ou CEF
├── requirements.txt
├── templates/
│   └── index.html      # Interface web (Chart.js, Plotly, vanilla JS)
├── static/
│   └── logo.png
└── captures/           # Stockage .pcap, rapports .json, historique
    ├── history.json
    ├── whitelist.json
    └── blacklist.json
```

### Pipeline d'analyse (par scan)
```
Capture (tshark/dumpcap)
    ↓
Analyse trafic (analyzer.py)
  → Blacklist/Whitelist check
  → Détection scan de ports
  → Volumes anormaux
  → TLS/JA3 (optionnel)
    ↓
Anomalies IA (ai_engine.py) — optionnel
    ↓
Threat Intel MISP (threat_intel.py) — optionnel
    ↓
Export SOC/SIEM (soc_engine.py) — optionnel
    ↓
Sauvegarde rapport JSON + historique
```

---

## Prérequis

| Composant | Version | Lien |
|-----------|---------|------|
| Python | 3.9+ | https://python.org |
| Wireshark / tshark | 4.x recommandé | https://www.wireshark.org/download.html |
| Droits admin/root | — | Nécessaires pour la capture réseau |

---

## Installation

### 1. Cloner le projet

```bash
git clone https://github.com/JustNS23/netscope.git
cd netscope/NETSCOPE
```

### 2. Installer les dépendances Python

```bash
pip install -r requirements.txt
```

Installation minimale (sans MISP) :
```bash
pip install Flask requests numpy scikit-learn mac-vendor-lookup
```

### 3. Installer Wireshark

Téléchargez et installez Wireshark depuis https://www.wireshark.org/download.html
**Cocher "tshark"** lors de l'installation (inclus par défaut).

Windows : tshark est cherché dans `C:\Program Files\Wireshark\tshark.exe`
Linux/macOS : `tshark` doit être dans le PATH système.

### 4. Lancer NETSCOPE

**Windows (avec droits admin) :**
```bash
python app.py
```

**Linux/macOS :**
```bash
sudo python3 app.py
```

L'application est accessible sur : **http://localhost:5000**

---

## Configuration

### Blacklist / Whitelist

Dans l'onglet **ADMINISTRATION → Gouvernance**, entrez une IP par ligne :

```
# Blacklist (IPs malveillantes)
185.15.22.1
45.33.32.156

# Whitelist (IPs de confiance — jamais alertées)
192.168.1.1
10.0.0.0
```

### Intégration MISP

1. Activer "Threat Intel — MISP" dans l'admin
2. Entrer l'URL de votre instance MISP et la clé API
3. Cliquer "Sauvegarder les paramètres"

Lors de chaque scan, les IPs publiques détectées seront vérifiées contre votre base MISP.

### Intégration SOC/SIEM

1. Activer "SOC/SIEM — Webhook" dans l'admin
2. Configurer l'URL du webhook (Splunk HEC, Elastic, n8n, etc.)
3. Choisir le format : **JSON** (Elastic/Splunk) ou **CEF** (ArcSight/QRadar)

Format JSON envoyé :
```json
{
  "@timestamp": "2025-01-15T14:30:00",
  "event_type": "netscope_audit",
  "severity": "high",
  "score": 42,
  "alerts": ["[BLACKLIST] IP malveillante : 185.15.22.1"],
  "stats": { "packets_count": 1250, "protocols": {"HTTPS": 800, "DNS": 300} }
}
```

### Profils de Scan

Dans le dashboard, configurez vos paramètres de scan (interface, durée, filtres, modules)
puis cliquez **💾 Sauvegarder Profil** pour le conserver entre les sessions.

---

## Dépendances détaillées

| Package | Usage | Obligatoire |
|---------|-------|-------------|
| `Flask` | Serveur web, API REST | ✅ Oui |
| `requests` | Export SOC/SIEM, géolocalisation | ✅ Oui |
| `numpy` | Calculs matriciels IsolationForest | ✅ Si module IA |
| `scikit-learn` | Détection anomalies ML | ✅ Si module IA |
| `mac-vendor-lookup` | Résolution fabricant MAC | ⚪ Optionnel |
| `pymisp` | Intégration Threat Intel MISP | ⚪ Optionnel |
| `tshark` (système) | Capture et décodage paquets | ✅ Oui |

**Frontend (CDN, pas d'installation) :**
- [Chart.js](https://www.chartjs.org/) — Donut protocoles, graphique score historique
- [Plotly.js](https://plotly.com/javascript/) — Diagramme Sankey
- Google Fonts — Roboto + JetBrains Mono

---

## Usage

### Lancer un scan

1. Sélectionner l'interface réseau (Wi-Fi, Ethernet...)
2. Définir la durée (5–300 secondes)
3. Optionnel : appliquer un filtre rapide ou un filtre BPF personnalisé
4. Cliquer **LANCER SCAN**

### Lire les résultats

| Indicateur | Signification |
|-----------|--------------|
| Score > 80 | ✅ Réseau sain |
| Score 50–80 | ⚠️ Anomalies mineures |
| Score < 50 | 🚨 Menaces détectées |
| Badge `BL` rouge | IP présente dans la blacklist |
| Badge `EXT` orange | Connexion vers une IP publique |

### Exporter les données

- **CSV** : bouton `📊 EXPORT CSV` — exporte le tableau filtré (compatible Excel)
- **PDF** : bouton `📄 RAPPORT PDF` — rapport complet avec recommandations
- **PCAP** : bouton `💾 TÉLÉCHARGER .PCAP` — capture brute analysable dans Wireshark

---

## Remarques

- NETSCOPE est un **outil pédagogique et d'audit réseau local**. Ne l'utilisez que sur des réseaux dont vous avez l'autorisation d'analyser le trafic.
- La géolocalisation utilise l'API gratuite [ip-api.com](http://ip-api.com) (100 req/min, HTTP uniquement).
- L'IA nécessite un minimum de **20 paquets** pour s'activer.
- Les rapports et captures sont stockés localement dans `captures/`.
