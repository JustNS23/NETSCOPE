import os
import subprocess
import time
import re
from flask import Flask, render_template, jsonify, request
from analyzer import analyser_trafic

app = Flask(__name__)

# --- CONFIGURATION ---
# IMPORTANT : Garde ton chemin correct ici
TSHARK_CMD = r"C:\Program Files\Wireshark\tshark.exe"
OUTPUT_DIR = "captures"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def lister_interfaces():
    """Demande à Tshark la liste et nettoie les noms pour ne garder que (Wi-Fi), (Ethernet), etc."""
    try:
        # On lance 'tshark -D' pour avoir la liste brute
        output = subprocess.check_output([TSHARK_CMD, "-D"], encoding='utf-8', errors='ignore')
        
        interfaces = []
        for line in output.splitlines():
            line = line.strip()
            if not line: continue

            # --- NETTOYAGE INTELLIGENT ---
            # Format Tshark habituel sur Windows : 
            # "5. \Device\NPF_{GUID_BIZARRE} (Wi-Fi)"
            
            # On cherche le chiffre au début (l'ID)
            # Et on cherche ce qu'il y a entre les parenthèses à la fin
            match = re.search(r"^(\d+)\.\s+.*\((.*)\)$", line)
            
            if match:
                id_interface = match.group(1)   # Ex: 5
                nom_propre = match.group(2)     # Ex: Wi-Fi
                interfaces.append({"id": id_interface, "name": nom_propre})
            
            else:
                # Si le format est différent (pas de parenthèses), on prend l'ancien système
                match_old = re.match(r"(\d+)\.\s+(.*)", line)
                if match_old:
                    interfaces.append({"id": match_old.group(1), "name": match_old.group(2)})
                    
        return interfaces
        
    except Exception as e:
        print(f"Erreur liste interfaces: {e}")
        return []

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/interfaces')
def api_interfaces():
    """Envoie la liste des interfaces au format JSON pour le menu déroulant"""
    liste = lister_interfaces()
    return jsonify(liste)

@app.route('/scan', methods=['POST'])
def scan():
    # 1. Récupération des choix de l'utilisateur
    duree = int(request.form.get('duree', 10))
    interface_choisie = request.form.get('interface') # <-- C'est ici qu'on récupère le choix !

    if not interface_choisie:
        return jsonify({"status": "error", "message": "Aucune interface sélectionnée"})

    nom_fichier = os.path.join(OUTPUT_DIR, f"capture_{int(time.time())}.pcap")

    print(f"Lancement du scan sur l'interface #{interface_choisie} pour {duree}s...")

    try:
        # Lancement de Tshark avec l'interface choisie
        subprocess.run(
            [TSHARK_CMD, "-i", interface_choisie, "-a", f"duration:{duree}", "-w", nom_fichier],
            check=True
        )
        
        # Lancement de l'analyse
        print("Analyse en cours...")
        resultats = analyser_trafic(nom_fichier)
        
        # Nettoyage (optionnel)
        # if os.path.exists(nom_fichier):
        #    os.remove(nom_fichier)

        return jsonify({"status": "success", "data": resultats})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": "Tshark a planté ou l'interface est invalide."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)