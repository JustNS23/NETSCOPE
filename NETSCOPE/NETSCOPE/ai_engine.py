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

    def detect_anomalies(self, traffic_data):
        """
        Détecte les anomalies et filtre le bruit statistique.
        """
        if not IA_AVAILABLE or not traffic_data or len(traffic_data) < 20:
            return []

        features = []
        mapping = []

        # 1. Extraction des caractéristiques
        for pkt in traffic_data:
            try:
                length = int(pkt.get('layers', {}).get('frame', {}).get('frame.len', 0))
                
                # Conversion Protocole en valeur numérique pour l'IA
                proto_val = 0
                p_str = pkt.get('proto', 'AUTRE')
                if p_str == 'TCP': proto_val = 10
                elif p_str == 'UDP': proto_val = 20
                elif p_str == 'HTTP': proto_val = 80
                elif p_str == 'HTTPS': proto_val = 443
                elif p_str == 'DNS': proto_val = 53
                
                # On nourrit l'IA avec : [Taille du paquet, Type de protocole]
                features.append([length, proto_val])
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
                
                # Analyse de la cause probable pour le message
                reason = "Flux atypique"
                if features[i][0] > 1400: reason = "Gros volume de données (Exfiltration ?)"
                elif features[i][0] < 60: reason = "Paquet suspect (Trop petit)"
                
                # Formattage de l'alerte
                alert_msg = f"[IA] {reason} (Src: {pkt['src']}, Confiance: {severity}%)"
                alerts.append(alert_msg)
        
        # On dédoublonne pour éviter le spam
        return list(set(alerts))

# Instance globale
ai_engine = AIEngine()