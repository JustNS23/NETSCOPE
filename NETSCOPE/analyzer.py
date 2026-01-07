import json
import subprocess
import collections
import os
from datetime import datetime

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

def extraire_service(texte):
    """
    Essaie de deviner le nom du service à partir d'une URL
    Ex: 'www.google.com' -> 'Google'
    Ex: 'api.netflix.com' -> 'Netflix'
    """
    if not texte: return ""
    
    # Liste de mots clés connus pour forcer l'affichage propre
    GERS = ['google', 'facebook', 'instagram', 'whatsapp', 'netflix', 'youtube', 'spotify', 'apple', 'microsoft', 'amazon', 'tiktok', 'snapchat', 'twitch', 'discord']
    
    texte_lower = texte.lower()
    for geant in GERS:
        if geant in texte_lower:
            return geant.capitalize() # Renvoie "Google" avec majuscule
            
    # Sinon, on prend le mot avant le .com / .fr
    # Ex: machin.ynov.com -> on garde "ynov"
    parties = texte.split('.')
    if len(parties) >= 2:
        # On évite les "com", "org", "net"
        candidat = parties[-2]
        if len(candidat) > 2:
            return candidat.capitalize()
            
    return "Autre"

def analyser_trafic(fichier_pcap):
    cmd = [TSHARK_PATH, "-r", fichier_pcap, "-T", "json"]
    
    try:
        output = subprocess.check_output(cmd, encoding='utf-8', errors='ignore')
        paquets = json.loads(output)
    except Exception as e:
        return {"error": str(e), "score_global": 0, "details_trafic": [], "alertes_securite": [], "total_paquets": 0, "repartition_protocoles": {}}

    score = 100
    protocoles = collections.Counter()
    alertes = []
    details_trafic = [] 
    
    for paquet in paquets:
        try:
            layers = paquet.get('_source', {}).get('layers', {})
            
            # Timestamp
            ts = float(paquet.get('_source', {}).get('layers', {}).get('frame', {}).get('frame.time_epoch', 0))
            heure = datetime.fromtimestamp(ts).strftime('%H:%M:%S')

            # IP
            src = layers.get('ip', {}).get('ip.src', '?')
            dst = layers.get('ip', {}).get('ip.dst', '?')

            # --- INTELLIGENCE ---
            proto = "TCP/UDP"
            info_brute = ""      # L'URL complète (ex: www.google.com)
            service_nom = ""     # Le nom simplifié (ex: Google)
            
            # A. DNS
            if 'dns' in layers:
                proto = "DNS"
                queries = layers['dns'].get('Queries', {})
                if isinstance(queries, dict):
                    for key, val in queries.items():
                        if 'dns.qry.name' in val:
                            info_brute = val['dns.qry.name']
                            service_nom = extraire_service(info_brute)
                            break

            # B. HTTP
            elif 'http' in layers:
                proto = "HTTP"
                host = layers['http'].get('http.host', '')
                uri = layers['http'].get('http.request.uri', '')
                info_brute = host + uri
                service_nom = extraire_service(host)
                score -= 0.5
                if 'http.authorization' in layers['http']:
                    score -= 5
                    alertes.append(f"Mot de passe clair vers {service_nom}")

            # C. HTTPS / TLS
            elif 'tls' in layers:
                proto = "HTTPS"
                tls = layers['tls']
                try:
                    handshake = tls.get('tls.handshake', {})
                    import re
                    # Recherche du Server Name Indication (SNI)
                    match = re.search(r"server_name: ([a-zA-Z0-9.-]+)", str(handshake))
                    if match:
                        info_brute = match.group(1)
                        service_nom = extraire_service(info_brute)
                except:
                    pass

            # Si on n'a pas trouvé de nom, on regarde les ports
            if not service_nom:
                port_dst = layers.get('tcp', {}).get('tcp.dstport') or layers.get('udp', {}).get('udp.dstport')
                if port_dst == '443': service_nom = "Web Sécurisé"
                elif port_dst == '80': service_nom = "Web"
                elif port_dst == '53': service_nom = "DNS"
                else: service_nom = "-"

            # On ne garde que les paquets qui ont un peu d'info (pour éviter de polluer le tableau)
            # ou alors on garde tout. Ici je filtre un peu les trucs vides.
            protocoles[proto] += 1
            
            details_trafic.append({
                "heure": heure,
                "src": src,
                "dst": dst,
                "proto": proto,
                "service": service_nom,  # <--- NOUVELLE COLONNE
                "info": info_brute       # L'info technique
            })

        except Exception as e:
            continue

# ... (Tout ton code d'analyse reste au dessus) ...

    # --- NOUVEAU : LA SANCTION CRITIQUE ---
    # C'est ici qu'on corrige la logique.
    
    # 1. On empêche le score d'être négatif
    score = max(0, int(score))

    # 2. Si une alerte critique est présente, on plafonne le score (Kill Switch)
    a_trouve_faille_critique = False
    
    for alerte in alertes:
        if "Mot de passe" in alerte:
            a_trouve_faille_critique = True
            break
    
    if a_trouve_faille_critique:
        # Si on a vu un mot de passe, le score ne peut PAS dépasser 45/100
        # Même si tout le reste est parfait.
        score = min(score, 45)

    # 3. Préparation des données pour le retour
    # On limite aux 500 derniers paquets pour la pagination (ou retire la limite si tu veux tout)
    # details_trafic = details_trafic[-500:] # Optionnel
    details_trafic.reverse()

    return {
        "score_global": score,
        "total_paquets": len(paquets),
        "repartition_protocoles": dict(protocoles),
        "alertes_securite": list(set(alertes)),
        "details_trafic": details_trafic
    }