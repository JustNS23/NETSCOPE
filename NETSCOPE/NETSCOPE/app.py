from flask import Flask, render_template, jsonify, request, send_from_directory
import subprocess
import os
import time
import json
import uuid
from datetime import datetime
import re
from analyzer import analyser_trafic, TSHARK_PATH
from capture_engine import CaptureEngine
# NOUVEAU: Import des moteurs
from ai_engine import ai_engine 
from threat_intel import intel_engine
from soc_engine import soc_engine

app = Flask(__name__)

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "captures")
HISTORY_FILE = os.path.join(OUTPUT_DIR, "history.json")
WHITELIST_FILE = os.path.join(OUTPUT_DIR, "whitelist.json")
BLACKLIST_FILE = os.path.join(OUTPUT_DIR, "blacklist.json")
SETTINGS_FILE = os.path.join(OUTPUT_DIR, "settings.json")

capture_engine = CaptureEngine(tshark_path=TSHARK_PATH)

if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)

# --- GESTION PARAMETRES ---
def get_settings():
    # Valeurs par défaut étendues
    default = {
        "high_perf": False, "tls_analysis": False, "ai_analysis": False,
        "threat_intel": False, "misp_url": "", "misp_key": "",
        "soc_integration": False, "soc_url": "", "soc_token": "", "soc_format": "JSON"
    }
    if not os.path.exists(SETTINGS_FILE): return default
    try:
        with open(SETTINGS_FILE, 'r') as f: 
            saved = json.load(f)
            return {**default, **saved} # Fusion sûre
    except: return default

def save_settings(new_settings):
    try:
        with open(SETTINGS_FILE, 'w') as f: json.dump(new_settings, f, indent=4)
        return True
    except: return False

# --- UTILS (IDENTIQUES) ---
def get_security_lists():
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
    clean_white = [x.strip() for x in whitelist if x.strip()]
    clean_black = [x.strip() for x in blacklist if x.strip()]
    try:
        with open(WHITELIST_FILE, 'w') as f: json.dump(clean_white, f, indent=4)
        with open(BLACKLIST_FILE, 'w') as f: json.dump(clean_black, f, indent=4)
        return True
    except: return False

def get_history():
    if not os.path.exists(HISTORY_FILE): return []
    try: 
        with open(HISTORY_FILE, 'r') as f: return json.load(f)
    except: return []

def save_to_history(metadata):
    history = get_history()
    history.insert(0, metadata)
    with open(HISTORY_FILE, 'w') as f: json.dump(history, f, indent=4)

def delete_from_history(job_id):
    history = get_history()
    job = next((j for j in history if j['id'] == job_id), None)
    if job:
        try: os.remove(os.path.join(OUTPUT_DIR, job['report_file']))
        except: pass
        try: os.remove(os.path.join(OUTPUT_DIR, job['pcap_file']))
        except: pass
        new_history = [j for j in history if j['id'] != job_id]
        with open(HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=4)
        return True
    return False

def lister_interfaces():
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
        return interfaces
    except: return []

# --- ROUTES ---
@app.route('/api/admin/settings', methods=['GET', 'POST'])
def api_admin_settings():
    if request.method == 'GET': return jsonify(get_settings())
    if request.method == 'POST':
        if save_settings(request.json): return jsonify({"status": "success"})
        return jsonify({"status": "error"}), 500

@app.route('/api/admin/lists', methods=['GET', 'POST'])
def api_admin_lists():
    if request.method == 'GET': return jsonify(get_security_lists())
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
    try:
        with open(os.path.join(OUTPUT_DIR, job['report_file']), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify({"meta": job, "data": data})
    except: return jsonify({"error": "Fichier corrompu"}), 404

@app.route('/api/history/<job_id>', methods=['DELETE'])
def api_delete_job(job_id):
    return jsonify({"status": "success"}) if delete_from_history(job_id) else (jsonify({"error": "Erreur"}), 500)

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

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/interfaces')
def api_interfaces(): return jsonify(lister_interfaces())

@app.route('/download/<filename>')
def download_file(filename):
    try: return send_from_directory(directory=OUTPUT_DIR, path=filename, as_attachment=True)
    except FileNotFoundError: return "Fichier introuvable.", 404

@app.route('/scan', methods=['POST'])
def scan():
    duree = int(request.form.get('duree', 10))
    interface_choisie = request.form.get('interface')
    raw_filter = request.form.get('raw_filter') 
    use_fingerprint = request.form.get('fingerprint') == 'true'
    
    # CHARGEMENT CONFIG GLOBALE
    settings = get_settings()
    
    # Options (Formulaire > Settings > False)
    use_high_perf = request.form.get('high_perf') == 'true' or settings.get('high_perf', False)
    use_tls_analysis = request.form.get('tls_analysis') == 'true' or settings.get('tls_analysis', False)
    use_ai = request.form.get('ai_analysis') == 'true' or settings.get('ai_analysis', False)
    
    # Options Admin Uniquement
    use_threat_intel = settings.get('threat_intel', False)
    use_soc = settings.get('soc_integration', False)

    if not interface_choisie: return jsonify({"status": "error", "message": "Interface manquante"})

    job_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nom_pcap = f"capture_{job_id}.pcap"
    nom_json = f"report_{job_id}.json"
    path_pcap = os.path.join(OUTPUT_DIR, nom_pcap)
    path_json = os.path.join(OUTPUT_DIR, nom_json)

    print(f"--- SCAN {job_id} [HP={use_high_perf}, IA={use_ai}, SOC={use_soc}] ---")
    
    try:
        # 1. Capture
        capture_engine.start_capture(
            interface=interface_choisie, duration=duree, output_file=path_pcap,
            filter_bpf=raw_filter, high_perf=use_high_perf
        )
        
        # 2. Analyse Base
        resultats = analyser_trafic(path_pcap, tshark_filter=None, activer_fingerprint=use_fingerprint, activer_tls=use_tls_analysis)
        resultats['interface'] = interface_choisie # Ajout meta pour le SOC

        # 3. Intelligence Artificielle
        if use_ai:
            ai_alerts = ai_engine.detect_anomalies(resultats['details_trafic'])
            if ai_alerts:
                resultats['alertes_securite'].extend(ai_alerts)
                resultats['score_global'] = max(0, resultats['score_global'] - (len(ai_alerts) * 5))

        # 4. Threat Intelligence (MISP)
        if use_threat_intel and settings.get('misp_url'):
            if intel_engine.connect(settings['misp_url'], settings.get('misp_key')):
                unique_ips = set(p['dst'] for p in resultats['details_trafic'])
                ti_alerts = intel_engine.check_indicators(unique_ips, [])
                if ti_alerts:
                    resultats['alertes_securite'].extend(ti_alerts)
                    resultats['score_global'] = max(0, resultats['score_global'] - 20)

        # 5. Export SOC / SIEM
        if use_soc and settings.get('soc_url'):
            print("Envoi vers SOC...")
            soc_engine.send_report(resultats, settings)

        resultats['config_used'] = get_security_lists()

        with open(path_json, 'w', encoding='utf-8') as f: json.dump(resultats, f, ensure_ascii=False)
            
        meta = {
            "id": job_id, "date": timestamp, "interface": interface_choisie,
            "score": resultats['score_global'], "paquets": resultats['total_paquets'],
            "alertes": len(resultats['alertes_securite']), "pcap_file": nom_pcap, "report_file": nom_json
        }
        save_to_history(meta)
        
        return jsonify({"status": "success", "data": resultats, "pcap_file": nom_pcap})

    except Exception as e:
        if os.path.exists(path_pcap): os.remove(path_pcap)
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)