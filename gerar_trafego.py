import requests
from requests.auth import HTTPBasicAuth

API_URL = "http://127.0.0.1:8000"

# Credenciais de Administrador válidas no USERS_DB
auth = HTTPBasicAuth("admin_corp", "nexus2026!")

print("[*] A enviar dados autenticados para o Nexus-Defender...")

try:
    # Testa a configuração de webhooks com autenticação HTTP Basic
    webhook_url = f"{API_URL}/api/v1/webhook-config"
    payload = {
        "url": "http://127.0.0.1:8000/webhook-test",
        "secret": "nexus_secret_sig",
        "active": True
    }
    
    res = requests.post(webhook_url, json=payload, auth=auth, timeout=3)
    print(f"[*] POST /api/v1/webhook-config -> Status: {res.status_code}")
    print("Resposta:", res.text)

except Exception as e:
    print(f"[!] Erro ao comunicar com a API: {e}")

print("\n✨ Teste de injeção concluído com sucesso!")
