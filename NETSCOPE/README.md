# NETSCOPE - Analyseur de Trafic Réseau

**NETSCOPE** est un outil pédagogique d'analyse réseau développé en **Python (Flask)** et utilisant **Tshark** (Wireshark). Il permet de scanner le trafic Wi-Fi ou Ethernet, d'attribuer un "Score de Santé" global et de visualiser les connexions (HTTP, DNS, TLS) via une interface Web.

## Fonctionnalités principales

- **Score de Santé (0-100)** : Calcul en temps réel basé sur la sécurité des paquets analysés.
- **Alertes de Sécurité** : Détection immédiate des mots de passe transmis en clair (HTTP Basic Auth).
- **Analyse Intelligente** : Reconnaissance automatique des services tiers (Google, Netflix, Instagram...).
- **Interface Web** : Tableau de bord complet avec filtrage (DNS, HTTPS, Suspect) et pagination.

## Prérequis

- **Python 3.x** installé sur la machine.
- **Wireshark** installé (assurez-vous que **Tshark** est inclus lors de l'installation).

## Installation

Installer les dépendances Installez les bibliothèques Python nécessaires via pip :
```bashpip install -r requirements.txt```

1. **Cloner le projet**
   Récupérez le code source via Git :
   ```bash
   git clone [https://github.com/JustNS23/netscope.git](https://github.com/JustNS23/netscope.git)
   cd netscope