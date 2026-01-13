from flask import Flask, render_template, jsonify, request, send_from_directory
import subprocess
import json
import os
import time
import re
from analyzer import analyser_trafic, TSHARK_PATH

app = Flask(__name__)

# --- CORRECTION CHEMINS ABSOLUS ---
# On récupère le dossier où se trouve app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# On crée le chemin complet vers "captures"
OUTPUT_DIR = os.path.join(BASE_DIR, "captures")

print(f"DEBUG: Les captures seront stockées dans : {OUTPUT_DIR}")

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def lister_interfaces():
    try:
        output = subprocess.check_output([TSHARK_PATH, "-D"], encoding='utf-8', errors='ignore')
        interfaces = []
        for line in output.splitlines():
            line = line.strip()
            if not line: continue
            match = re.search(r"^(\d+)\.\s+.*\((.*)\)$", line)
            if match:
                interfaces.append({"id": match.group(1), "name": match.group(2)})
            else:
                match_old = re.match(r"(\d+)\.\s+(.*)", line)
                if match_old:
                    interfaces.append({"id": match_old.group(1), "name": match_old.group(2)})
        return interfaces
    except Exception as e:
        print(f"Erreur Tshark: {e}")
        return []

def nettoyer_vieux_fichiers():
    """Supprime les fichiers du scan PRÉCÉDENT"""
    print("Nettoyage du dossier captures...")
    for filename in os.listdir(OUTPUT_DIR):
        file_path = os.path.join(OUTPUT_DIR, filename)
        try:
            if filename.endswith(".pcap") or filename.endswith(".json"):
                os.remove(file_path)
        except Exception as e:
            print(f"Erreur suppression {filename}: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify(lister_interfaces())

# --- ROUTE TÉLÉCHARGEMENT CORRIGÉE ---
@app.route('/download/<filename>')
def download_file(filename):
    print(f"DEBUG: Demande de téléchargement pour {filename}")
    try:
        # On force l'utilisation du dossier ABSOLU
        return send_from_directory(directory=OUTPUT_DIR, path=filename, as_attachment=True)
    except FileNotFoundError:
        print(f"ERREUR: Fichier {filename} introuvable dans {OUTPUT_DIR}")
        return "Fichier introuvable sur le serveur.", 404

@app.route('/scan', methods=['POST'])
def scan():
    nettoyer_vieux_fichiers()

    duree = int(request.form.get('duree', 10))
    interface_choisie = request.form.get('interface')
    raw_filter = request.form.get('raw_filter') 
    
    if not interface_choisie:
        return jsonify({"status": "error", "message": "Aucune interface sélectionnée"})

    nom_fichier_court = f"capture_{int(time.time())}.pcap"
    # Chemin complet absolu
    nom_fichier_complet = os.path.join(OUTPUT_DIR, nom_fichier_court)

    print(f"Scan sur {interface_choisie} -> {nom_fichier_complet}")

    try:
        subprocess.run(
            [TSHARK_PATH, "-i", interface_choisie, "-a", f"duration:{duree}", "-w", nom_fichier_complet],
            check=True
        )
        
        print("Analyse en cours...")
        resultats = analyser_trafic(nom_fichier_complet, tshark_filter=raw_filter)
        
        return jsonify({
            "status": "success", 
            "data": resultats, 
            "pcap_file": nom_fichier_court 
        })

    except Exception as e:
        if os.path.exists(nom_fichier_complet):
            os.remove(nom_fichier_complet)
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)