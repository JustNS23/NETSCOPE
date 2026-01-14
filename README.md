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

## Configuration (Windows)
Une version de Wireshark portable est déjà présente mais il est possible de spécifier le chemin vers l'exécutable Tshark.
Ouvrez les fichiers app.py et analyzer.py dans votre éditeur de code.

Localisez la variable TSHARK_CMD.

Assurez-vous qu'elle pointe vers votre dossier d'installation Wireshark (exemple ci-dessous) :
```bash TSHARK_CMD = r"C:\Program Files\Wireshark\tshark.exe"```

## Utilisation
1.Lancer l'application Exécutez la commande suivante dans le terminal :
```bash python app.py```

2.Accéder à l'interface Ouvrez votre navigateur et allez à l'adresse : http://127.0.0.1:5000

3.Démarrer l'analyse Sélectionnez votre interface réseau (Wi-Fi ou Ethernet) dans le menu déroulant et cliquez sur "Lancer l'Analyse".

## Avertissement légal
Cet outil est conçu exclusivement à des fins éducatives et de diagnostic réseau sur votre propre infrastructure. L'interception ou l'analyse de réseaux tiers sans consentement explicite est illégale et punissable par la loi.

## Commande de test

```bash curl -X POST -d "username=admin&password=MonMotDePasseSecret123" http://httpbin.org/post ```

1. curl : C'est l'outil standard pour faire des requêtes réseau en ligne de commande.

2. -X POST : Simule l'envoi d'un formulaire (comme quand tu cliques sur "Se connecter").

3. -d "..." : Ce sont les données (Data). Ici, on envoie explicitement les champs username et password avec une fausse valeur.

4. http://... : C'est le point crucial. On utilise HTTP (port 80) et non HTTPS (port 443).
   En HTTPS, ton script Netscope verrait des données chiffrées illisibles (ex: a8f9z3...).
   En HTTP, ton script Netscope va voir passer le texte brut : password=MonMotDePasseSecret123.
   
## Aperçu de l'interface
