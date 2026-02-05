import os
import subprocess
import platform
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CaptureEngine")

class CaptureEngine:
    def __init__(self, tshark_path="tshark"):
        self.tshark_path = tshark_path
        self.os_type = platform.system()
        
        # Détection de dumpcap (Moteur C natif)
        self.dumpcap_path = self._find_dumpcap()

    def _find_dumpcap(self):
        if not self.tshark_path: return "dumpcap"
        base_dir = os.path.dirname(self.tshark_path)
        if self.os_type == "Windows":
            candidate = os.path.join(base_dir, "dumpcap.exe")
        else:
            candidate = os.path.join(base_dir, "dumpcap")
        if os.path.exists(candidate):
            return candidate
        return "dumpcap"

    def start_capture(self, interface, duration, output_file, filter_bpf=None, high_perf=False):
        """
        Lance la capture.
        - high_perf=True : Active AF_PACKET/MMAP (Linux) ou High Buffer (Windows).
        - high_perf=False : Capture standard Tshark (plus compatible).
        """
        cmd = []
        
        if not high_perf:
            # --- MODE STANDARD (COMPATIBILITÉ MAXIMALE) ---
            logger.info("📡 Démarrage Capture Standard")
            cmd = [
                self.tshark_path,
                "-i", interface,
                "-a", f"duration:{duration}",
                "-w", output_file,
                "-q"
            ]
        else:
            # --- MODE HAUTE PERFORMANCE ---
            if self.os_type == "Linux":
                logger.info("🚀 Démarrage Moteur Linux (AF_PACKET/MMAP)")
                # Dumpcap utilise nativement PACKET_MMAP sous Linux
                cmd = [
                    self.dumpcap_path,
                    "-i", interface,
                    "-a", f"duration:{duration}",
                    "-w", output_file,
                    "-q"
                ]
            else:
                logger.info("🚀 Démarrage Moteur Windows (High Buffer)")
                # Augmentation du buffer mémoire pour éviter les drops
                cmd = [
                    self.tshark_path,
                    "-i", interface,
                    "-a", f"duration:{duration}",
                    "-w", output_file,
                    "-B", "256", 
                    "-q"
                ]

        if filter_bpf:
            cmd.extend(["-f", filter_bpf])

        try:
            process = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode('utf-8', errors='ignore')
            logger.error(f"❌ Erreur Capture: {err}")
            raise Exception(f"Échec capture: {err}")

# Instance globale
engine = CaptureEngine()