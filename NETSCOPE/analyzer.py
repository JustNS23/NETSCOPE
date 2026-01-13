import json
import subprocess
import collections
import os
from datetime import datetime
import sys

# --- CONFIGURATION DU CHEMIN RELATIF (PORTABLE) ---
# On récupère le dossier où se trouve ce fichier python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# On construit le chemin vers le tshark.exe qui est DANS le dossier du projet
# Chemin typique de la version Portable : /Wireshark/App/Wireshark/tshark.exe
TSHARK_PATH = os.path.join(BASE_DIR, "Wireshark", "App", "Wireshark", "tshark.exe")

# Sécurité : Si on ne le trouve pas en portable, on essaie le chemin classique ou le PATH
if not os.path.exists(TSHARK_PATH):
    print(f"ATTENTION: Tshark portable non trouvé ici : {TSHARK_PATH}")
    print("Tentative avec le chemin système par défaut...")
    TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

def extraire_service(texte):
    if not texte or not isinstance(texte, str): return "Autre"
    
    GERS = ['google', 'facebook', 'instagram', 'whatsapp', 'netflix', 'youtube', 'spotify', 'apple', 'microsoft', 'amazon', 'tiktok', 'snapchat', 'twitch', 'discord']
    texte_lower = texte.lower()
    
    for geant in GERS:
        if geant in texte_lower: return geant.capitalize()
    
    try:
        parties = texte.split('.')
        if len(parties) >= 2:
            candidat = parties[-2]
            if len(candidat) > 2: return candidat.capitalize()
    except:
        pass
    return "Autre"

def analyser_trafic(fichier_pcap, tshark_filter=None):
    
    cmd = [TSHARK_PATH, "-r", fichier_pcap, "-T", "json"]
    
    if tshark_filter and tshark_filter.strip():
        cmd.extend(["-Y", tshark_filter])

    print(f"DEBUG: Lancement analyse Tshark sur {fichier_pcap}")

    try:
        if not os.path.exists(fichier_pcap):
            return {"score_global": 0, "total_paquets": 0, "details_trafic": [], "alertes_securite": [], "repartition_protocoles": {}}

        output = subprocess.check_output(cmd, encoding='utf-8', errors='ignore')
        
        if not output:
            return {"score_global": 100, "total_paquets": 0, "details_trafic": [], "alertes_securite": [], "repartition_protocoles": {}}

        paquets = json.loads(output)
        print(f"DEBUG: JSON chargé. {len(paquets)} paquets trouvés.")

    except Exception as e:
        print(f"ERREUR CRITIQUE TSHARK: {e}")
        return {"error": str(e), "score_global": 0, "details_trafic": [], "alertes_securite": [], "total_paquets": 0}

    score = 100
    protocoles = collections.Counter()
    alertes = []
    details_trafic = []
    
    # --- INTELLIGENCE : Dictionnaire pour traquer les scans ---
    # Clé = (IP_Source, IP_Destination)
    # Valeur = Set des ports touchés (pour éviter les doublons)
    tracker_scan = collections.defaultdict(set)
    
    for i, paquet in enumerate(paquets):
        try:
            layers = paquet.get('_source', {}).get('layers', {})
            
            # --- DATE ROBUSTE ---
            ts_raw = layers.get('frame', {}).get('frame.time_epoch', '0')
            ts_str = str(ts_raw)
            heure = "00:00:00"

            if 'T' in ts_str:
                try: heure = ts_str.split('T')[1].split('.')[0]
                except: heure = datetime.now().strftime('%H:%M:%S')
            else:
                try: heure = datetime.fromtimestamp(float(ts_raw)).strftime('%H:%M:%S')
                except: heure = datetime.now().strftime('%H:%M:%S')

            # --- IP ---
            src = layers.get('ip', {}).get('ip.src', '?')
            dst = layers.get('ip', {}).get('ip.dst', '?')

            # --- PROTOCOLE ---
            proto = "AUTRE"
            info_brute = ""
            service_nom = ""
            port_dst = None # On stocke le port pour la détection d'attaque

            if 'tcp' in layers: 
                proto = "TCP"
                port_dst = layers['tcp'].get('tcp.dstport')
            elif 'udp' in layers: 
                proto = "UDP"
                port_dst = layers['udp'].get('udp.dstport')

            if 'dns' in layers:
                proto = "DNS"
                queries = layers['dns'].get('Queries', {})
                if isinstance(queries, dict):
                    for key, val in queries.items():
                        if isinstance(val, dict) and 'dns.qry.name' in val:
                            info_brute = val['dns.qry.name']
                            service_nom = extraire_service(info_brute)
                            break
            
            elif 'http' in layers:
                proto = "HTTP"
                host = layers['http'].get('http.host', '')
                uri = layers['http'].get('http.request.uri', '')
                info_brute = str(host) + str(uri)
                service_nom = extraire_service(str(host))
                score -= 0.5
                if 'http.authorization' in layers['http']:
                    score -= 5
                    alertes.append(f"Mot de passe clair vers {service_nom}")
            
            elif 'tls' in layers:
                proto = "HTTPS"
                service_nom = "Web Sécurisé"

            if not service_nom:
                if port_dst:
                    info_brute = f"Port {port_dst}"
                    p_str = str(port_dst)
                    if p_str == '443': service_nom = "Web Sécurisé"
                    elif p_str == '80': service_nom = "Web"
                    elif p_str == '53': service_nom = "DNS"
                    elif p_str == '22': service_nom = "SSH"
                    elif p_str == '445': service_nom = "SMB"
                    else: service_nom = "-"

            # --- INTELLIGENCE : ENREGISTREMENT DU SCAN ---
            if src != '?' and dst != '?' and port_dst:
                # On note que SRC a touché le port PORT_DST sur la machine DST
                tracker_scan[(src, dst)].add(str(port_dst))

            protocoles[proto] += 1
            
            couches_brutes = {
                "frame": layers.get("frame", {}),
                "ip": layers.get("ip", {}),
                "transport": layers.get("tcp", {}) if "tcp" in layers else layers.get("udp", {})
            }

            details_trafic.append({
                "heure": heure,
                "src": src,
                "dst": dst,
                "proto": proto,
                "service": service_nom,
                "info": str(info_brute),
                "layers": couches_brutes
            })

        except Exception as e:
            if i == 0: print(f"🛑 ERREUR LECTURE PAQUET {i}: {e}")
            continue

    # --- ANALYSE FINALE DES SCANS (NMAP / RECONNAISSANCE) ---
    # On regarde si quelqu'un a touché trop de ports différents
    for (attaquant, victime), ports_touches in tracker_scan.items():
        nb_ports = len(ports_touches)
        
        # SEUIL D'ALERTE : Si plus de 15 ports différents visés
        if nb_ports > 15:
            msg = f"SCAN DE PORTS DÉTECTÉ : {attaquant} a scanné {nb_ports} ports sur {victime}"
            alertes.append(msg)
            score -= 25 # Grosse pénalité sur le score
            print(f"ALERTE: {msg}")

    # --- FINALISATION ---
    score = max(0, int(score))
    
    a_trouve_faille_critique = False
    for alerte in alertes:
        if "Mot de passe" in alerte:
            a_trouve_faille_critique = True
            break
    if a_trouve_faille_critique: score = min(score, 45)

    details_trafic.reverse()

    # LIMITE AUGMENTÉE A 10000 POUR LES GRANDS SCANS
    if len(details_trafic) > 10000:
        details_trafic = details_trafic[:10000]

    return {
        "score_global": score,
        "total_paquets": len(paquets),
        "repartition_protocoles": dict(protocoles),
        "alertes_securite": list(set(alertes)),
        "details_trafic": details_trafic
    }