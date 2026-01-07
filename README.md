# 📡 NETSCOPE - Analyseur de Trafic Réseau

**NETSCOPE ** est un outil pédagogique d'analyse réseau basé sur **Python (Flask)** et **Tshark** (Wireshark). Il permet de scanner le trafic Wi-Fi/Ethernet, d'attribuer un "Score de Santé" et de visualiser les connexions (HTTP, DNS, TLS) via une interface Web moderne.

## 🚀 Fonctionnalités

- **Score de Santé (0-100) :** Calcul en temps réel basé sur la sécurité des paquets.
- **Alertes de Sécurité :** Détection immédiate des mots de passe en clair (HTTP Basic Auth).
- **Analyse Intelligente :** Reconnaissance automatique des services (Google, Netflix, Instagram...).
- **Interface Web :** Tableau de bord avec filtres (DNS, HTTPS, Suspect) et pagination.

## 🛠️ Prérequis

1. **Python 3.x** installé.
2. **Wireshark** installé sur la machine (avec Tshark inclus).

## 📦 Installation

1. Cloner ce projet :
   ```bash
   git clone [https://github.com/JustNS23/netscope.git](https://github.com/JustNS23/netscope.git)
   cd netscope
Installer les dépendances :

Bash

pip install -r requirements.txt
Configuration (Windows uniquement) :

Ouvrez app.py et analyzer.py.

Vérifiez que la ligne suivante pointe bien vers votre installation de Wireshark :

Python

TSHARK_CMD = r"C:\Program Files\Wireshark\tshark.exe"
▶️ Utilisation
Lancer l'application :

Bash

python app.py
Ouvrir le navigateur sur : http://127.0.0.1:5000

Sélectionner l'interface réseau dans le menu déroulant et cliquer sur Lancer l'Analyse.

⚠️ Avertissement
Cet outil est destiné à des fins éducatives et de diagnostic réseau uniquement. L'analyse de réseaux tiers sans autorisation est illégale.


---

### Une fois le fichier enregistré, tu passes aux commandes :

Maintenant que ton dossier contient le fichier `README.md`, tu retournes dans ton **Invite de Commande (CMD)** et tu lances la suite que tu m'as montrée :

1.  `git init`
2.  `git add .`
3.  `git commit -m "Premier commit"`
4.  Les 3 commandes que GitHub t'a données (`git branch...`, `git remote...`, `git push...`).

Dis-moi si tu as réussi à voir ton code en ligne !

## 🖼️ Captue visuel

<img width="1919" height="917" alt="image" src="https://github.com/user-attachments/assets/bb7c7e17-7676-4799-a827-f84b13a2f8d7" />

## 🖼️ Captue exemple visuel

<img width="1920" height="917" alt="image" src="https://github.com/user-attachments/assets/aad7c959-4040-4985-8366-658f2ed52154" />
