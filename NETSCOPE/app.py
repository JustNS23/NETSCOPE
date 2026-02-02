from flask import Flask, render_template, jsonify, request, send_from_directory
import subprocess
import os
import time
import json
import uuid
from datetime import datetime
import re
# Assurez-vous que analyzer.py est dans le même dossier
from analyzer import analyser_trafic, TSHARK_PATH

app = Flask(__name__)

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "captures")
HISTORY_FILE = os.path.join(OUTPUT_DIR, "history.json")
WHITELIST_FILE = os.path.join(OUTPUT_DIR, "whitelist.json")
BLACKLIST_FILE = os.path.join(OUTPUT_DIR, "blacklist.json")

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# --- 1. GESTION DES LISTES (ADMIN) ---
def get_security_lists():
    """Charge les listes blanches et noires"""
    lists = {"whitelist": [], "blacklist": []}
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f: lists["whitelist"] = json.load(f)
        except: pass
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r') as f: lists["blacklist"] = json.load(f)
        except: pass
    return lists

def save_security_lists(whitelist, blacklist):
    """Sauvegarde les listes nettoyées"""
    # On enlève les lignes vides
    clean_white = [x.strip() for x in whitelist if x.strip()]
    clean_black = [x.strip() for x in blacklist if x.strip()]
    try:
        with open(WHITELIST_FILE, 'w') as f: json.dump(clean_white, f, indent=4)
        with open(BLACKLIST_FILE, 'w') as f: json.dump(clean_black, f, indent=4)
        return True
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")
        return False

# --- 2. GESTION DE L'HISTORIQUE ---
def get_history():
    if not os.path.exists(HISTORY_FILE): return []
    try:
        with open(HISTORY_FILE, 'r') as f: return json.load(f)
    except: return []

def save_to_history(metadata):
    history = get_history()
    history.insert(0, metadata) # Ajout au début
    with open(HISTORY_FILE, 'w') as f: json.dump(history, f, indent=4)

def delete_from_history(job_id):
    history = get_history()
    job = next((j for j in history if j['id'] == job_id), None)
    if job:
        # Suppression physique des fichiers
        try: os.remove(os.path.join(OUTPUT_DIR, job['report_file']))
        except: pass
        try: os.remove(os.path.join(OUTPUT_DIR, job['pcap_file']))
        except: pass
        
        # Mise à jour liste
        new_history = [j for j in history if j['id'] != job_id]
        with open(HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=4)
        return True
    return False

# --- ROUTES API ---

@app.route('/api/admin/lists', methods=['GET', 'POST'])
def api_admin_lists():
    if request.method == 'GET':
        return jsonify(get_security_lists())
    if request.method == 'POST':
        data = request.json
        if save_security_lists(data.get('whitelist', []), data.get('blacklist', [])):
            return jsonify({"status": "success"})
        return jsonify({"status": "error"}), 500

@app.route('/api/history', methods=['GET'])
def api_get_history(): return jsonify(get_history())

@app.route('/api/history/<job_id>', methods=['GET'])
def api_load_job(job_id):
    history = get_history()
    job = next((j for j in history if j['id'] == job_id), None)
    if not job: return jsonify({"error": "Non trouvé"}), 404
    
    # Chargement du rapport JSON détaillé
    try:
        with open(os.path.join(OUTPUT_DIR, job['report_file']), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify({"meta": job, "data": data})
    except:
        return jsonify({"error": "Fichier corrompu"}), 404

@app.route('/api/history/<job_id>', methods=['DELETE'])
def api_delete_job(job_id):
    if delete_from_history(job_id): return jsonify({"status": "success"})
    return jsonify({"error": "Erreur"}), 500

@app.route('/api/history/clear', methods=['POST'])
def api_clear_history():
    history = get_history()
    for job in history:
        try: os.remove(os.path.join(OUTPUT_DIR, job['report_file']))
        except: pass
        try: os.remove(os.path.join(OUTPUT_DIR, job['pcap_file']))
        except: pass
    if os.path.exists(HISTORY_FILE): os.remove(HISTORY_FILE)
    return jsonify({"status": "success"})

# --- ROUTES PRINCIPALES ---

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/interfaces')
def api_interfaces():
    try:
        output = subprocess.check_output([TSHARK_PATH, "-D"], encoding='utf-8', errors='ignore')
        interfaces = []
        for line in output.splitlines():
            if not line.strip(): continue
            match = re.search(r"^(\d+)\.\s+.*\((.*)\)$", line)
            if match: interfaces.append({"id": match.group(1), "name": match.group(2)})
            else:
                parts = line.split('.', 1)
                if len(parts) > 1: interfaces.append({"id": parts[0].strip(), "name": parts[1].strip()})
        return jsonify(interfaces)
    except: return jsonify([])

# --- ROUTE POUR TÉLÉCHARGER LE FICHIER WIRESHARK ---
@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_from_directory(directory=OUTPUT_DIR, path=filename, as_attachment=True)
    except FileNotFoundError:
        return "Fichier introuvable.", 404

@app.route('/scan', methods=['POST'])
def scan():
    duree = int(request.form.get('duree', 10))
    interface_choisie = request.form.get('interface')
    raw_filter = request.form.get('raw_filter') 
    use_fingerprint = request.form.get('fingerprint') == 'true'

    if not interface_choisie: return jsonify({"status": "error", "message": "Interface manquante"})

    job_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nom_pcap = f"capture_{job_id}.pcap"
    nom_json = f"report_{job_id}.json"
    
    path_pcap = os.path.join(OUTPUT_DIR, nom_pcap)
    path_json = os.path.join(OUTPUT_DIR, nom_json)

    print(f"--- SCAN {job_id} ---")
    try:
        # 1. Capture Tshark
        subprocess.run([TSHARK_PATH, "-i", interface_choisie, "-a", f"duration:{duree}", "-w", path_pcap], check=True)
        
        # 2. Analyse Python
        resultats = analyser_trafic(path_pcap, tshark_filter=raw_filter, activer_fingerprint=use_fingerprint)
        
        # 3. Sauvegarde Rapport
        with open(path_json, 'w', encoding='utf-8') as f: json.dump(resultats, f, ensure_ascii=False)
            
        # 4. Sauvegarde Historique
        meta = {
            "id": job_id, "date": timestamp, "interface": interface_choisie,
            "score": resultats['score_global'], "paquets": resultats['total_paquets'],
            "alertes": len(resultats['alertes_securite']), 
            "pcap_file": nom_pcap, # Important pour le téléchargement
            "report_file": nom_json
        }
        save_to_history(meta)
        
        # 5. Réponse au client
        return jsonify({
            "status": "success", 
            "data": resultats, 
            "pcap_file": nom_pcap # Le nom du fichier pour le bouton de téléchargement
        })

    except Exception as e:
        if os.path.exists(path_pcap): os.remove(path_pcap)
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)