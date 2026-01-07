# 📡 NETSCOPE - Network Traffic Analyzer

NETSCOPE est un outil d'analyse réseau léger basé sur **Python (Flask)** et **Tshark** (Wireshark). Il permet de scanner le trafic, d'attribuer un score de sécurité et de visualiser les connexions en temps réel via une interface Web.

## 🚀 Fonctionnalités

- **Score de Santé Réseau :** Analyse heuristique (0-100) basée sur les risques détectés.
- **Détection de Menaces :** Identifie les mots de passe en clair (HTTP Basic Auth) et le trafic non chiffré.
- **Analyse Intelligente :** Reconnaissance des services (Netflix, Google, etc.) via DNS/SNI.
- **Visualisation :** Tableau de bord web avec pagination et filtres dynamiques.

## 🛠️ Prérequis

1. **Python 3.x**
2. **Wireshark** (installé sur la machine).
   - *Important :* Assurez-vous que `tshark` est installé (inclus par défaut avec Wireshark).

## 📦 Installation

1. Cloner le dépôt :
   ```bash
   git clone [https://github.com/JustNS23/oscope.git](https://github.com/JustNS23/oscope.git)
   cd oscope