import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    IA_AVAILABLE = True
except ImportError:
    IA_AVAILABLE = False
    print("ATTENTION: scikit-learn non installé. L'IA est désactivée.")

class AIEngine:
    def __init__(self):
        if IA_AVAILABLE:
            # contamination=0.01 : On s'attend à 1% d'anomalies max (moins sensible)
            self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
            self.scaler = StandardScaler()
        else:
            self.model = None

    @staticmethod
    def _est_ip_privee(ip):
        if not ip or ip == '?': return True
        parts = ip.split('.')
        if len(parts) != 4: return True
        try:
            a, b = int(parts[0]), int(parts[1])
            return (a == 10 or a == 127 or
                    (a == 172 and 16 <= b <= 31) or
                    (a == 192 and b == 168))
        except:
            return True

    def detect_anomalies(self, traffic_data):
        """
        Détecte les anomalies avec 5 features : taille paquet, protocole,
        port destination, IP externe (0/1), heure (secondes).
        """
        if not IA_AVAILABLE or not traffic_data or len(traffic_data) < 20:
            return []

        features = []
        mapping = []

        # 1. Extraction des caractéristiques enrichies
        for pkt in traffic_data:
            try:
                layers = pkt.get('layers', {})

                # Feature 1 : Taille du paquet
                length = int(layers.get('frame', {}).get('frame.len', 0))

                # Feature 2 : Protocole en valeur numérique
                proto_val = 0
                p_str = pkt.get('proto', 'AUTRE')
                if p_str == 'TCP': proto_val = 10
                elif p_str == 'UDP': proto_val = 20
                elif p_str == 'HTTP': proto_val = 80
                elif p_str == 'HTTPS': proto_val = 443
                elif p_str == 'DNS': proto_val = 53

                # Feature 3 : Port destination (0 si inconnu)
                port_val = 0
                tcp_layer = layers.get('tcp', {})
                udp_layer = layers.get('udp', {})
                raw_port = tcp_layer.get('tcp.dstport') or udp_layer.get('udp.dstport')
                if raw_port:
                    if isinstance(raw_port, list): raw_port = raw_port[0]
                    try: port_val = int(raw_port)
                    except: pass

                # Feature 4 : IP externe (1 = externe, 0 = interne)
                dst_ip = pkt.get('dst', '')
                ext_val = 0 if self._est_ip_privee(dst_ip) else 1

                # Feature 5 : Heure en secondes (0-86400)
                heure_str = pkt.get('heure', '00:00:00')
                try:
                    h, m, s = heure_str.split(':')
                    heure_sec = int(h) * 3600 + int(m) * 60 + int(s)
                except:
                    heure_sec = 0

                features.append([length, proto_val, port_val, ext_val, heure_sec])
                mapping.append(pkt)
            except: continue

        if not features: return []

        # 2. Analyse
        X = np.array(features)
        
        # Entraînement sur les données actuelles
        self.model.fit(X)
        
        # Prédiction (-1 = Anomalie, 1 = Normal)
        predictions = self.model.predict(X)
        # Score brut (plus c'est négatif, plus c'est anormal)
        raw_scores = self.model.decision_function(X)

        alerts = []
        
        for i, pred in enumerate(predictions):
            if pred == -1:
                pkt = mapping[i]
                
                # Normalisation du score en pourcentage (0-100%)
                # On inverse la valeur car decision_function renvoie du négatif pour les anomalies
                anomaly_score = abs(raw_scores[i]) * 100 
                severity = int(anomaly_score)

                # --- FILTRE ANTI-BRUIT ---
                # On ignore tout ce qui est inférieur à 25% de certitude
                if severity < 25:
                    continue 
                
                # Analyse de la cause probable pour le message (5 features)
                f = features[i]
                reason = "Flux atypique"
                if f[0] > 1400: reason = "Gros volume de données (Exfiltration ?)"
                elif f[0] < 60: reason = "Paquet suspect (Trop petit)"
                elif f[3] == 1 and f[2] > 0 and str(f[2]) not in {'80', '443', '53', '22'}:
                    reason = f"Port inhabituel vers IP externe (:{int(f[2])})"
                elif f[4] < 21600 or f[4] > 79200:
                    reason = "Activité hors heures normales (nuit)"
                
                # Formattage de l'alerte
                alert_msg = f"[IA] {reason} (Src: {pkt['src']}, Confiance: {severity}%)"
                alerts.append(alert_msg)
        
        # On dédoublonne pour éviter le spam
        return list(set(alerts))

# Instance globale
ai_engine = AIEngine()