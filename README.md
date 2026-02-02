# NETSCOPE

<p align="center"><img width="120" height="515" alt="logo" src="https://github.com/user-attachments/assets/8114d0e2-c064-4d6c-9cc9-fdc1210a0ab0" />

</p>

<p align="center">
  <b>Plateforme d'Analyse Réseau & Audit de Cybersécurité</b>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img alt="Flask" src="https://img.shields.io/badge/Flask-Framework-000000?style=for-the-badge&logo=flask&logoColor=white">
  <img alt="Tshark" src="https://img.shields.io/badge/Powered_by-Tshark-16a085?style=for-the-badge&logo=wireshark&logoColor=white">
  <img alt="©" src="https://img.shields.io/badge/License-©-yellow?style=for-the-badge">
</p>

---

## Présentation

**NETSCOPE** est une solution logicielle d’audit et de surveillance des flux réseau, pensée pour les équipes sécurité, les pentesters et les administrateurs systèmes. Elle offre une visibilité granulaire sur le trafic local et évalue dynamiquement le niveau de risque de votre infrastructure.  

Développé en Python et basé sur la puissance de **Tshark**, NETSCOPE automatise la collecte, l’analyse et la mise en forme des données réseau afin de produire des tableaux de bord exploitables et des rapports d’audit professionnels.

---

## 🚀 Fonctionnalités Clés

| Module | Description Analytique |
|---|---|
| **Score de Santé** | Algorithme de notation en temps réel basé sur la conformité des protocoles, les bonnes pratiques de configuration et la détection d’activités suspectes. |
| **Alertes Critiques** | Détection immédiate d’éléments sensibles circulant en clair (mots de passe, identifiants, requêtes non chiffrées) et de comportements anormaux. |
| **Fingerprinting** | Identification automatique des types de terminaux (Apple, Samsung, IoT, etc.) via l’analyse des OUI (Organizationally Unique Identifiers) des adresses MAC. |
| **Top Talkers** | Classement des IP sources/destinations et des services les plus bavards ou les plus gourmands en bande passante. |
| **Rapport PDF Pro** | Génération de rapports d’audit détaillés, prêts à être partagés avec des clients, des RSSI ou intégrés à une documentation de conformité. |

---

## 🧩 Synthèse du Projet

**NETSCOPE** est un outil de cybersécurité et d'audit réseau *tout-en-un* développé en Python (Flask).  
Il s'appuie sur le moteur de capture de paquets **Tshark** (Wireshark) pour offrir une visibilité exhaustive sur le trafic local à travers une interface web moderne au style "Cyber".

---

## 🛠️ Fonctionnalités détaillées

NETSCOPE transforme des données réseau brutes en informations directement exploitables grâce à plusieurs modules :

- **Analyse de flux en temps réel**  
  Capture et tri des paquets (TCP, UDP, HTTP, DNS, TLS, etc.) pour identifier qui communique avec qui sur le réseau.

- **Score de Santé (Health Score)**  
  Algorithme qui évalue dynamiquement la sécurité du réseau sur une échelle de 0 à 100.  
  Chaque menace détectée fait chuter ce score.

- **Détection d'anomalies & alertes**  
  Identification immédiate des comportements à risque :  
  - Transmission de mots de passe en clair (ex : HTTP non chiffré)  
  - Scans de ports suspects  
  - Trafic anormalement volumineux ou inhabituel

- **Fingerprinting d'appareils**  
  Analyse des adresses MAC et des bases de constructeurs pour identifier la marque des appareils connectés (Apple, Samsung, Dell, IoT, etc.).

- **Intelligence de service**  
  Reconnaissance automatique des services tiers utilisés (Google, Netflix, Instagram, etc.) pour mieux comprendre les usages du réseau.

- **Reporting professionnel**  
  Génération de rapports PDF structurés incluant :  
  - Graphiques de répartition  
  - Top talkers  
  - Journal d'audit complet  
  - Score de santé global

- **Gestion administrative**  
  - Listes blanches : IP de confiance  
  - Listes noires : IP suspectes  
  Ces listes permettent d’affiner la détection et de réduire le bruit.

- **Interopérabilité**  
  Possibilité d’envoyer les rapports vers des plateformes d’automatisation comme **n8n** via des Webhooks.

---

## ⚙️ Prérequis Système

- **OS :** Windows 10/11, Linux (Debian/Ubuntu/Kali), macOS  
- **Python :** Version 3.10 ou supérieure  
- **Dépendance réseau :** Wireshark avec **Tshark** accessible dans le `PATH` système (vérifiable via `tshark -v`)  
- **Navigateur :** Un navigateur moderne (Chrome, Firefox, Edge) pour accéder à l’interface web Flask  

## 🔧 Prérequis techniques

- **Python 3.x** installé sur la machine.
- **Wireshark** installé (assurez-vous que **Tshark** est inclus lors de l'installation).

### Installation

Installer les dépendances Installez les bibliothèques Python nécessaires via pip :

```bash
pip install -r requirements.txt
```

---

## 📥 Installation

Cloner le dépôt puis installer les dépendances Python :

```bash
git clone https://github.com/<ton-compte>/netscope.git
cd netscope
pip install -r requirements.txt
```

## 🚀 Lancement & Utilisation

Lancer l’application :

```bash
python app.py
```
## 🔗 Ouvrir votre navigateur à l’adresse :

```text
http://127.0.0.1:5000
```

## 🖌️ Sélectionner :

- L’interface réseau à auditer (Wi-Fi, Ethernet, etc.)
- La durée du scan / de la capture
- Cliquer sur « Lancer l'Audit ».

## 👀 Consulter :

- Le score de santé du réseau
- Les top talkers et services détectés
- Les alertes de sécurité
- Les rapports PDF générés


## ⚖️ Mentions Légales & Responsabilités

### Cadre d’usage
#### NETSCOPE est conçu exclusivement à des fins :
- Éducatives
- De recherche en cybersécurité
- De diagnostic sur des infrastructures dont vous êtes le propriétaire ou l’administrateur dûment autorisé.

#### Interdictions
- L’interception, l’analyse ou le stockage de données circulant sur un réseau tiers sans le consentement explicite et écrit de son propriétaire constitue un délit pénal.

#### Responsabilité
L’utilisateur est seul responsable de l’usage qu’il fait de cet outil.
L’auteur de NETSCOPE décline toute responsabilité en cas d’utilisation malveillante ou illégale.

<div align="center">
<sub>© 2026 NETSCOPE Audit Framework – Projet open source à visée pédagogique</sub>
</div>

