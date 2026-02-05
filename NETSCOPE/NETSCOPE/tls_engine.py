import hashlib
import logging

# Configuration du logging
logger = logging.getLogger("TLSEngine")

class TLSEngine:
    def __init__(self):
        self.ja3_db = {} # Pourrait servir à charger une threat intelligence plus tard

    def process_packet(self, tls_layer):
        """
        Analyse une couche TLS brute issue de Tshark JSON.
        Retourne un dictionnaire enrichi avec JA3 et infos Certificats.
        """
        result = {
            "is_suspicious": False,
            "ja3": None,
            "ja3_hash": None,
            "sni": None,
            "cert_issuer": None,
            "cert_subject": None,
            "risk_reason": []
        }

        try:
            # 1. Extraction SNI (Server Name Indication)
            if 'tls.handshake.extensions_server_name' in tls_layer:
                result['sni'] = tls_layer['tls.handshake.extensions_server_name']

            # 2. Analyse JA3 (Fingerprint Client)
            # JA3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
            # Note: Tshark doit fournir les valeurs décimales pour un vrai JA3.
            # Ici on fait une approximation robuste basée sur les données dispos.
            
            if 'tls.handshake.ciphersuites' in tls_layer:
                # Récupération brute des données (simplifiée pour l'exemple)
                version = tls_layer.get('tls.handshake.version', '771') # 771 = TLS 1.2
                ciphers = tls_layer.get('tls.handshake.ciphersuites', '')
                extensions = tls_layer.get('tls.handshake.extension.type', '')
                curves = tls_layer.get('tls.handshake.extensions_supported_groups', '')
                points = tls_layer.get('tls.handshake.extensions_ec_point_formats', '')

                # Nettoyage des données (Tshark renvoie parfois des noms, parfois des codes)
                # On crée une chaîne signature unique
                raw_ja3 = f"{version},{ciphers},{extensions},{curves},{points}"
                
                # Hash MD5
                result['ja3'] = raw_ja3
                result['ja3_hash'] = hashlib.md5(raw_ja3.encode()).hexdigest()

            # 3. Analyse Certificat X509 (Serveur)
            # Tshark expose souvent ces champs sous 'x509sat.uTF8String' ou similaire
            if 'x509sat.uTF8String' in tls_layer:
                cert_data = tls_layer['x509sat.uTF8String']
                # Logique heuristique : si Issuer == Subject -> Auto-signé (Suspect)
                # Note: c'est simplifié car le JSON Tshark varie selon les versions
                if isinstance(cert_data, list) and len(cert_data) > 1:
                     # Souvent le premier est le sujet, le second l'émetteur dans la chaîne
                    result['cert_subject'] = cert_data[0]
                    result['cert_issuer'] = cert_data[1] # Approximation
                    
                    if result['cert_subject'] == result['cert_issuer']:
                        result['is_suspicious'] = True
                        result['risk_reason'].append("Certificat Auto-signé détecté")

            # 4. Détection Anomalies JA3 connues (Exemple Cobalt Strike)
            # Hash connu de Cobalt Strike (exemple)
            if result['ja3_hash'] == "654c6023366c30363212879502804558": 
                result['is_suspicious'] = True
                result['risk_reason'].append("Signature JA3 malveillante (C2 connu)")

        except Exception as e:
            # On ne fait pas planter l'analyse globale pour un échec TLS
            pass

        return result

# Instance globale
tls_engine = TLSEngine()