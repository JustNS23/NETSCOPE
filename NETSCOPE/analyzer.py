import os
import sys
import json
import argparse
import subprocess
import collections
import time
from datetime import datetime
from tls_engine import tls_engine # NOUVEAU

# --- GESTION LIBRAIRIE MAC ---
try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None

# --- CONFIGURATION CHEMINS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TSHARK_PATH = os.path.join(BASE_DIR, "Wireshark", "App", "Wireshark", "tshark.exe")

if not os.path.exists(TSHARK_PATH):
    if os.name == 'nt':
        tshark_sys = r"C:\Program Files\Wireshark\tshark.exe"
        TSHARK_PATH = tshark_sys if os.path.exists(tshark_sys) else "tshark"
    else:
        TSHARK_PATH = "tshark"

# --- CACHE ---
mac_lookup_instance = None
mac_cache = {} 

def init_mac_lookup():
    global mac_lookup_instance
    if MacLookup is None: return False
    try:
        mac_lookup_instance = MacLookup()
        try: mac_lookup_instance.lookup("00:00:00:00:00:00")
        except: mac_lookup_instance.update_vendors()
    except:
        mac_lookup_instance = None
        return False
    return True

def get_vendor(mac_address):
    if not mac_lookup_instance or not mac_address: return ""
    if mac_address in mac_cache: return mac_cache[mac_address]
    try:
        vendor = mac_lookup_instance.lookup(mac_address)
        mac_cache[mac_address] = vendor
        return vendor
    except:
        mac_cache[mac_address] = "" 
        return ""

def extraire_service(texte):
    if not texte or not isinstance(texte, str): return "Autre"
    GERS = ['google', 'facebook', 'instagram', 'whatsapp', 'netflix', 'youtube', 'spotify', 'apple', 'microsoft', 'amazon', 'tiktok', 'snapchat', 'twitch', 'discord']
    for geant in GERS:
        if geant in texte.lower(): return geant.capitalize()
    return "Autre"

# --- MODIFICATION DE LA SIGNATURE ---
def analyser_trafic(fichier_pcap, tshark_filter=None, activer_fingerprint=True, activer_tls=False):
    if activer_fingerprint and MacLookup: init_mac_lookup()

    # Ajout des champs TLS à l'extraction Tshark pour avoir les infos nécessaires
    # On ajoute -e tls.handshake... si on veut être précis, mais ici on prend le JSON full
    cmd = [TSHARK_PATH, "-r", fichier_pcap, "-T", "json"]
    if tshark_filter and tshark_filter.strip():
        cmd.extend(["-Y", tshark_filter])

    print(f"DEBUG: Analyse {fichier_pcap} (TLS={activer_tls})...")

    try:
        if not os.path.exists(fichier_pcap): return {"error": "Fichier introuvable", "score_global": 0}
        output = subprocess.check_output(cmd, encoding='utf-8', errors='ignore')
        if not output: return {"score_global": 100, "total_paquets": 0, "details_trafic": [], "alertes_securite": [], "repartition_protocoles": {}}
        paquets = json.loads(output)
    except Exception as e:
        print(f"ERREUR TSHARK: {e}")
        return {"error": str(e), "score_global": 0}

    score = 100
    protocoles = collections.Counter()
    alertes = []
    details_trafic = []
    tracker_scan = collections.defaultdict(set)
    appareils_detectes = {} 

    for i, paquet in enumerate(paquets):
        try:
            layers = paquet.get('_source', {}).get('layers', {})
            
            # --- DATE ---
            ts_raw = layers.get('frame', {}).get('frame.time_epoch', time.time())
            if isinstance(ts_raw, list): ts_raw = ts_raw[0]
            try: heure = datetime.fromtimestamp(float(ts_raw)).strftime('%H:%M:%S')
            except: heure = datetime.now().strftime('%H:%M:%S')

            # --- IP/MAC ---
            src_ip = layers.get('ip', {}).get('ip.src')
            dst_ip = layers.get('ip', {}).get('ip.dst')
            if not src_ip: src_ip = layers.get('ipv6', {}).get('ipv6.src', '?')
            if not dst_ip: dst_ip = layers.get('ipv6', {}).get('ipv6.dst', '?')
            
            if isinstance(src_ip, list): src_ip = src_ip[0]
            if isinstance(dst_ip, list): dst_ip = dst_ip[0]

            src_mac = layers.get('eth', {}).get('eth.src')
            if not src_mac: src_mac = layers.get('wlan', {}).get('wlan.sa')
            if isinstance(src_mac, list): src_mac = src_mac[0]

            # --- VENDOR ---
            vendor_str = ""
            if activer_fingerprint and src_mac:
                vendor_str = get_vendor(src_mac)
                if src_ip != '?' and src_ip not in appareils_detectes:
                    appareils_detectes[src_ip] = {"mac": src_mac, "vendor": vendor_str}

            # --- PROTO ---
            proto = "AUTRE"
            info_brute = ""
            service_nom = ""
            port_dst = None
            tls_info = None # Pour stocker le résultat JA3

            if 'tcp' in layers: 
                proto = "TCP"
                port_dst = layers['tcp'].get('tcp.dstport')
            elif 'udp' in layers: 
                proto = "UDP"
                port_dst = layers['udp'].get('udp.dstport')

            if 'dns' in layers:
                proto = "DNS"
                info_brute = "DNS Query"
                queries = layers['dns'].get('Queries', {})
                if isinstance(queries, dict):
                    for k,v in queries.items():
                        if isinstance(v, dict) and 'dns.qry.name' in v:
                            info_brute = v['dns.qry.name']
                            service_nom = extraire_service(info_brute)
                            break
            elif 'http' in layers:
                proto = "HTTP"
                host = layers['http'].get('http.host', '')
                uri = layers['http'].get('http.request.uri', '')
                info_brute = f"{host}{uri}"
                service_nom = extraire_service(str(host))
                score -= 0.5
                if 'http.authorization' in layers['http']:
                    score -= 5
                    alertes.append(f"Mot de passe clair vers {service_nom}")
            
            elif 'tls' in layers:
                proto = "HTTPS"
                service_nom = "Web Sécurisé"
                
                # --- NOUVEAU : ANALYSE CHIFFRÉE ---
                if activer_tls:
                    tls_result = tls_engine.process_packet(layers['tls'])
                    if tls_result['sni']:
                        info_brute = f"SNI: {tls_result['sni']}"
                        service_nom = extraire_service(tls_result['sni'])
                    
                    if tls_result['ja3_hash']:
                        # On ajoute le hash JA3 dans l'info pour l'expert
                        info_brute += f" [JA3: {tls_result['ja3_hash'][:6]}...]"
                    
                    if tls_result['is_suspicious']:
                        score -= 10
                        alertes.append(f"TLS Suspect ({src_ip}): {', '.join(tls_result['risk_reason'])}")
                        
                    tls_info = tls_result # On stocke pour le détail
                else:
                    # Mode simple
                    if 'tls.handshake.extensions_server_name' in layers.get('tls', {}):
                        info_brute = layers['tls']['tls.handshake.extensions_server_name']
                        service_nom = extraire_service(info_brute)

            if not service_nom and port_dst:
                 p = str(port_dst) if not isinstance(port_dst, list) else str(port_dst[0])
                 if p=='443': service_nom="HTTPS"
                 elif p=='80': service_nom="HTTP"
                 elif p=='53': service_nom="DNS"
                 elif p=='22': service_nom="SSH"
                 else: service_nom="-"

            if src_ip != '?' and dst_ip != '?' and port_dst:
                tracker_scan[(src_ip, dst_ip)].add(str(port_dst))

            protocoles[proto] += 1
            
            # Construction de la ligne
            packet_data = {
                "heure": heure,
                "src": src_ip,
                "dst": dst_ip,
                "vendor": vendor_str, 
                "mac": src_mac, 
                "proto": proto,
                "service": service_nom,
                "info": str(info_brute),
                "layers": layers
            }
            # Si on a des infos TLS avancées, on les ajoute
            if tls_info:
                packet_data["tls_analysis"] = tls_info

            details_trafic.append(packet_data)

        except Exception as e:
            continue

    for (attaquant, victime), ports in tracker_scan.items():
        if len(ports) > 15:
            alertes.append(f"SCAN DE PORTS : {attaquant} -> {victime} ({len(ports)} ports)")
            score -= 25

    score = max(0, min(100, int(score)))
    liste_appareils = [{"ip": k, "mac": v["mac"], "vendor": v["vendor"]} for k, v in appareils_detectes.items()]
    
    if len(details_trafic) > 3000: details_trafic = details_trafic[:3000]

    return {
        "score_global": score,
        "total_paquets": len(paquets),
        "repartition_protocoles": dict(protocoles),
        "alertes_securite": list(set(alertes)),
        "appareils_detectes": liste_appareils,
        "details_trafic": details_trafic
    }

if __name__ == "__main__":
    # Test simple
    pass