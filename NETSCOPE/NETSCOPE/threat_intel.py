import logging

# Configuration du logging
logger = logging.getLogger("ThreatIntel")

try:
    from pymisp import PyMISP
    MISP_AVAILABLE = True
except ImportError:
    MISP_AVAILABLE = False
    logger.warning("PyMISP non installé. Module Threat Intel désactivé.")

class ThreatIntelEngine:
    def __init__(self):
        self.misp = None
        self.connected = False

    def connect(self, url, key, verify_cert=False):
        """Initialise la connexion à l'instance MISP"""
        if not MISP_AVAILABLE: return False
        try:
            self.misp = PyMISP(url, key, ssl=verify_cert, debug=False)
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"Erreur connexion MISP: {e}")
            self.connected = False
            return False

    def check_indicators(self, unique_ips, unique_domains):
        """
        Vérifie une liste d'IPs et de Domaines contre la base MISP.
        Retourne une liste d'alertes enrichies.
        """
        if not self.connected or not self.misp:
            return []

        alerts = []
        
        # Vérification des IPs (On filtre les IPs privées pour éviter les requêtes inutiles)
        public_ips = [ip for ip in unique_ips if not ip.startswith(('192.168.', '10.', '172.16.', '127.'))]
        
        # Recherche par batch ou itérative (simplifiée ici)
        for ip in public_ips:
            try:
                res = self.misp.search(controller='attributes', value=ip, type_attribute='ip-dst')
                if res and 'Attribute' in res and len(res['Attribute']) > 0:
                    event_info = res['Attribute'][0].get('Event', {}).get('info', 'Menace Inconnue')
                    alerts.append(f"[MISP] IP Malveillante connue : {ip} ({event_info})")
            except: pass

        # Vérification des Domaines
        for domain in unique_domains:
            if not domain: continue
            try:
                res = self.misp.search(controller='attributes', value=domain, type_attribute='domain')
                if res and 'Attribute' in res and len(res['Attribute']) > 0:
                    event_info = res['Attribute'][0].get('Event', {}).get('info', 'Menace Inconnue')
                    alerts.append(f"[MISP] Domaine Malveillant connu : {domain} ({event_info})")
            except: pass

        return alerts

# Instance globale
intel_engine = ThreatIntelEngine()