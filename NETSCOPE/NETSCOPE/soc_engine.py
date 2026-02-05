import requests
import json
import logging
import datetime

# Configuration simple du logging pour le moteur
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SOCEngine")

class SOCEngine:
    def __init__(self):
        pass

    def _format_cef(self, report):
        """
        Formate le rapport en Common Event Format (CEF) pour les SIEM (ArcSight, QRadar, Splunk...).
        Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        events = []
        
        # 1. Événement de synthèse (Score)
        score = report.get('score_global', 0)
        severity = "1" if score > 80 else ("5" if score > 50 else "10")
        msg_summary = f"CEF:0|NETSCOPE|AuditEngine|1.0|100|Audit Summary|{severity}|msg=Audit completed score={score} packets={report.get('total_paquets')}"
        events.append(msg_summary)

        # 2. Événements par alerte
        for alert in report.get('alertes_securite', []):
            alert_sev = "5"
            if "Mot de passe" in alert or "Critique" in alert: alert_sev = "10"
            elif "Scan" in alert: alert_sev = "7"
            
            # Nettoyage des caractères spéciaux pour le CEF
            clean_alert = alert.replace('|', '/').replace('=', ':')
            msg = f"CEF:0|NETSCOPE|AuditEngine|1.0|200|Security Alert|{alert_sev}|msg={clean_alert}"
            events.append(msg)
            
        return "\n".join(events)

    def send_report(self, report, config):
        """
        Envoie le rapport vers le endpoint configuré (Webhook/SIEM).
        """
        url = config.get('soc_url')
        if not url: return False

        token = config.get('soc_token', '')
        format_type = config.get('soc_format', 'JSON') # JSON ou CEF
        
        headers = {
            'User-Agent': 'Netscope-SOC-Connector/1.0'
        }
        if token:
            headers['Authorization'] = f"Bearer {token}"
            headers['X-API-Key'] = token # Support large pour différents systèmes

        try:
            payload = None
            if format_type == 'CEF':
                # Envoi format texte/syslog-over-http
                payload = self._format_cef(report)
                headers['Content-Type'] = 'text/plain'
                response = requests.post(url, data=payload, headers=headers, timeout=5)
            else:
                # Envoi JSON standard (Structure allégée pour l'ingestion)
                soc_payload = {
                    "@timestamp": datetime.datetime.now().isoformat(),
                    "event_type": "netscope_audit",
                    "severity": "high" if report.get('score_global', 100) < 50 else "low",
                    "score": report.get('score_global'),
                    "alerts": report.get('alertes_securite', []),
                    "stats": {
                        "packets_count": report.get('total_paquets'),
                        "protocols": report.get('repartition_protocoles')
                    },
                    "meta": {
                        "interface": report.get('interface', 'unknown'),
                        "duration": report.get('duration', 0)
                    }
                }
                headers['Content-Type'] = 'application/json'
                response = requests.post(url, json=soc_payload, headers=headers, timeout=5)

            if response.status_code < 300:
                logger.info(f"✅ Rapport envoyé au SOC ({format_type}): {response.status_code}")
                return True
            else:
                logger.error(f"❌ Erreur SOC: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"❌ Echec connexion SOC: {e}")
            return False

# Instance globale
soc_engine = SOCEngine()