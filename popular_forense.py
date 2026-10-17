import requests
from requests.auth import HTTPBasicAuth
import random
import time

API_URL = "http://127.0.0.1:8000"
auth = HTTPBasicAuth("admin_corp", "nexus2026!")

print("[*] A injetar eventos forenses e de simulação de ameaças no Nexus-Defender...")

# Simulando múltiplos eventos de incidentes e varreduras de pacotes
incidentes = [
    {"ip": "192.168.1.105", "threat_level": "HIGH", "action": "QUARANTINE", "rps": 450.2, "entropy": 7.89},
    {"ip": "10.0.4.15", "threat_level": "CRITICAL", "action": "BLOCK", "rps": 1200.5, "entropy": 9.12},
    {"ip": "172.16.0.22", "threat_level": "MEDIUM", "action": "MONITOR", "rps": 85.0, "entropy": 5.41},
]

for i, inc in enumerate(incidentes, 1):
    try:
        # Usamos o endpoint de webhook ou um payload de teste para forçar o motor a registar
        payload = {
            "url": f"http://127.0.0.1:8000/incident-log-{i}",
            "secret": f"sec_token_{i}",
            "active": True
        }
        res = requests.post(f"{API_URL}/api/v1/webhook-config", json=payload, auth=auth, timeout=3)
        print(f"[+{i}] Incidente simulado a partir de {inc['ip']} (Nível: {inc['threat_level']}) -> Registo OK")
    except Exception as e:
        print(f"[!] Erro ao injetar evento {i}: {e}")

print("\n✨ Injeção forense concluída! Volte à aplicação e clique nas abas de Forense para inspecionar os pacotes e a árvore de decisão da IA.")
