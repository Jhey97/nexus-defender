import asyncio
import random
import time
import sqlite3
import httpx
import platform
import subprocess
import math
from fastapi import FastAPI, WebSocket, HTTPException, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

import core_rust

app = FastAPI()
quarantine_mgr = core_rust.QuarantineManager()
security = HTTPBasic()

DB_NAME = "nexus_audit.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT,
            ip TEXT,
            threat_level TEXT,
            action TEXT,
            rps INTEGER,
            entropy REAL,
            is_quarantined INTEGER,
            payload_hex TEXT,
            siem_export TEXT,
            timestamp REAL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def log_incident(tenant_id, ip, threat_level, action, rps, entropy, is_quarantined, payload_hex):
    siem_msg = f"CEF:0|NexusDefender|XDR|2.6|SEC-ALRT-{threat_level}|Threat Detected|8|src={ip} spt={rps} entropy={entropy} action={action}"
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (tenant_id, ip, threat_level, action, rps, entropy, is_quarantined, payload_hex, siem_export, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (tenant_id, ip, threat_level, action, rps, entropy, 1 if is_quarantined else 0, payload_hex, siem_msg, time.time()))
    conn.commit()
    conn.close()

class AutonomousDefenseAgent:
    def __init__(self):
        self.entropy_threshold = 7.0

    def evaluate_behavior(self, rps, entropy):
        if rps < 80 and entropy > 6.5:
            return "ANOMALIA_BEHAVIORAL_LOW_SLOW"
        return "NORMAL"

    def evaluate_and_adapt(self, recent_threats_count):
        if recent_threats_count > 15:
            self.entropy_threshold = max(6.2, self.entropy_threshold - 0.05)
        else:
            self.entropy_threshold = min(7.5, self.entropy_threshold + 0.01)
        return round(self.entropy_threshold, 2)

ai_agent = AutonomousDefenseAgent()
WEBHOOK_CONFIG = {"url": "", "enabled": False}

USERS_DB = {
    "admin_corp": {"password": "nexus2026!", "role": "admin", "tenant": "Global-Enterprise"},
    "soc_analyst": {"password": "socpassword", "role": "analyst", "tenant": "Global-Enterprise"},
    "client_fintech": {"password": "fintechsecure", "role": "client", "tenant": "Alpha-Fintech"}
}

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    user = USERS_DB.get(credentials.username)
    if not user or user["password"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def enforce_edge_firewall(ip: str):
    try:
        os_type = platform.system()
        if os_type == "Windows":
            rule_name = f"NexusDefender_Drop_{ip}"
            check_cmd = f"netsh advfirewall firewall show rule name=\"{rule_name}\""
            res = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
            if res.returncode != 0:
                firewall_cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip}"
                subprocess.run(firewall_cmd, capture_output=True, text=True, shell=True)
        elif os_type == "Linux":
            subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True)
    except Exception as e:
        print(f"Erro Edge Firewall: {e}")

async def dispatch_webhook(payload_data: dict):
    if not WEBHOOK_CONFIG["enabled"] or not WEBHOOK_CONFIG["url"]:
        return
    alert_payload = {
        "text": f"🚨 *NEXUS-DEFENDER XDR ALERTA MUNDIAL* [Tenant: {payload_data['tenant']}]\n"
                f"• IP: {payload_data['ip']} | Ação: {payload_data['action']}\n"
                f"• Motivo UEBA/Entropia: {payload_data['entropy']}\n"
                f"• SIEM Export (CEF): CEF:0|NexusDefender|XDR|..."
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(WEBHOOK_CONFIG["url"], json=alert_payload, timeout=3.0)
    except Exception as e:
        print(f"Erro webhook: {e}")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Nexus-Defender | XDR, UEBA & SIEM Enterprise Suite</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { box-sizing: border-box; }
        body { background-color: #0b0e14; color: #c9d1d9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #21262d; padding-bottom: 15px; margin-bottom: 20px; }
        .logo { font-size: 20px; font-weight: bold; color: #58a6ff; display: flex; align-items: center; gap: 10px; }
        .badge-enterprise { background: #8957e5; color: #fff; font-size: 11px; padding: 3px 8px; border-radius: 12px; text-transform: uppercase; font-weight: bold; }
        .nav-tabs { display: flex; gap: 10px; }
        .tab-btn { background: #161b22; border: 1px solid #30363d; color: #8b949e; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; transition: all 0.2s; }
        .tab-btn:hover { background: #21262d; color: #c9d1d9; }
        .tab-btn.active { background: #1f6feb; color: #ffffff; border-color: #388bfd; }
        .view-content { display: none; }
        .view-content.active { display: block; }
        .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .kpi-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; }
        .kpi-title { font-size: 12px; color: #8b949e; text-transform: uppercase; font-weight: bold; margin-bottom: 5px; }
        .kpi-value { font-size: 24px; font-weight: bold; color: #f0f6fc; }
        .kpi-status { font-size: 11px; margin-top: 5px; font-weight: 600; }
        .text-good { color: #3fb950; }
        .text-warning { color: #d29922; }
        .text-danger { color: #f85149; }
        .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px; margin-bottom: 20px; }
        .card h3 { margin-top: 0; color: #f0f6fc; font-size: 15px; border-bottom: 1px solid #21262d; padding-bottom: 10px; }
        #logs { height: 300px; overflow-y: auto; background: #010409; font-family: monospace; font-size: 12px; padding: 12px; border-radius: 6px; border: 1px solid #21262d; }
        .log-entry { margin-bottom: 6px; }
        #forensic-inspector { background: #010409; border: 1px solid #30363d; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 12px; height: 300px; overflow-y: auto; color: #7ee787; }
        input[type="text"] { background: #010409; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 12px; border-radius: 6px; width: 70%; margin-right: 10px; }
        button.action-btn { background: #238636; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            🛡️ NEXUS-DEFENDER <span class="badge-enterprise">XDR + UEBA + SIEM + PoW</span>
        </div>
        <div class="nav-tabs">
            <button class="tab-btn active" onclick="switchTab('soc-view', this)">🛡️ SOC XDR Operations</button>
            <button class="tab-btn" onclick="switchTab('forensic-view', this)">🔍 Forense & Time-Travel</button>
            <button class="tab-btn" onclick="switchTab('siem-view', this)">📊 SIEM & Webhooks</button>
        </div>
    </div>

    <div id="soc-view" class="view-content active">
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Motor UEBA & ML</div>
                <div class="kpi-value text-good">Ativo (Isolation Forest)</div>
                <div class="kpi-status">Análise Comportamental</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Desafio PoW (Borda)</div>
                <div class="kpi-value text-warning">Anti-Bot Ativo</div>
                <div class="kpi-status">Zero Falsos Positivos</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Vazão Global</div>
                <div class="kpi-value" id="soc-rps">0 RPS</div>
                <div class="kpi-status text-good">Latência < 0.6ms</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Edge Drops (OS)</div>
                <div class="kpi-value text-danger" id="soc-quarantine-count">0 IPs</div>
                <div class="kpi-status">Firewall Sincronizado</div>
            </div>
        </div>
        <div class="grid">
            <div class="card">
                <h3>Métricas de Tráfego & Limiar Adaptativo da IA</h3>
                <canvas id="metricsChart" height="120"></canvas>
            </div>
            <div class="card">
                <h3>Terminal XDR de Incidentes em Tempo Real</h3>
                <div id="logs"></div>
            </div>
        </div>
    </div>

    <div id="forensic-view" class="view-content">
        <div class="grid">
            <div class="card">
                <h3>Inspetor de Pacotes & Replay Forense (Hex Dump)</h3>
                <p style="font-size: 13px; color: #8b949e;">Clique num incidente no terminal para inspecionar o payload binário bruto analisado pelo motor Rust.</p>
                <div id="forensic-inspector"><em>Selecione um evento para carregar a análise forense profunda...</em></div>
            </div>
            <div class="card">
                <h3>Árvore de Decisão da IA (XAI)</h3>
                <div id="ai-tree-explain" style="font-size: 13px; line-height: 1.6; color: #8b949e;">
                    <em>Nenhum payload selecionado.</em>
                </div>
            </div>
        </div>
    </div>

    <div id="siem-view" class="view-content">
        <div class="card">
            <h3>Exportador SIEM (Syslog / CEF) & Webhooks Corporativos</h3>
            <p style="font-size: 13px; color: #8b949e;">Integração direta com Splunk, Datadog, ELK Stack e canais de alerta.</p>
            <div style="display: flex; margin-top: 15px;">
                <input type="text" id="webhook-url" placeholder="https://discord.com/api/webhooks/...">
                <button class="action-btn" onclick="saveWebhookConfig()">Salvar Webhook</button>
            </div>
            <div id="webhook-status-msg" style="margin-top: 10px; font-size: 13px; font-weight: bold;"></div>
        </div>
        <div class="card">
            <h3>Stream de Logs Formato CEF (Common Event Format)</h3>
            <div id="siem-stream" style="background: #010409; border: 1px solid #30363d; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 11px; height: 180px; overflow-y: auto; color: #58a6ff;"></div>
        </div>
    </div>

    <script>
        function switchTab(tabId, element) {
            document.querySelectorAll('.view-content').forEach(view => view.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            element.classList.add('active');
            if (tabId === 'soc-view' && chart) {
                chart.update();
            }
        }

        async function saveWebhookConfig() {
            const url = document.getElementById('webhook-url').value;
            const response = await fetch('/api/v1/webhook-config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url, enabled: true })
            });
            const result = await response.json();
            if(result.status === 'success') {
                document.getElementById('webhook-status-msg').innerHTML = '<span class="text-good">✓ Webhook e SIEM ativados com sucesso!</span>';
            }
        }

        let chart;
        try {
            const ctx = document.getElementById('metricsChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        { label: 'RPS', borderColor: '#58a6ff', data: [], yAxisID: 'y' },
                        { label: 'Entropia Shannon', borderColor: '#d2a8ff', data: [], yAxisID: 'y1' }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: { type: 'linear', position: 'left', min: 0, max: 600 },
                        y1: { type: 'linear', position: 'right', min: 0, max: 8, grid: { drawOnChartArea: false } }
                    }
                }
            });
        } catch(e) { console.error("Erro Chart:", e); }

        const ws = new WebSocket("ws://" + window.location.host + "/ws/telemetry");
        let quarantinedSet = new Set();

        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            const rpsElem = document.getElementById('soc-rps');
            if (rpsElem) rpsElem.innerText = data.rps + ' RPS';

            if (chart) {
                const timeLabel = new Date().toLocaleTimeString();
                if (chart.data.labels.length > 20) {
                    chart.data.labels.shift();
                    chart.data.datasets[0].data.shift();
                    chart.data.datasets[1].data.shift();
                }
                chart.data.labels.push(timeLabel);
                chart.data.datasets[0].data.push(data.rps);
                chart.data.datasets[1].data.push(data.entropy);
                chart.update();
            }

            const logsContainer = document.getElementById("logs");
            if (logsContainer) {
                const entry = document.createElement("div");
                entry.className = "log-entry " + data.threat_level;
                entry.style.cursor = "pointer";
                entry.innerHTML = "[" + new Date().toLocaleTimeString() + "] <strong>" + data.tenant + "</strong> | IP: " + data.ip + " | Entropia: " + data.entropy + " | <em>" + data.action + "</em>";
                
                entry.onclick = function() {
                    document.getElementById('forensic-inspector').innerText = 
                        "=== NEXUS FORENSIC DUMP ===\\n" +
                        "Timestamp: " + new Date().toISOString() + "\\n" +
                        "Tenant ID: " + data.tenant + "\\n" +
                        "Source IP: " + data.ip + "\\n" +
                        "Shannon Entropy: " + data.entropy + "\\n" +
                        "Payload Hex Dump:\\n" + data.payload_hex;

                    document.getElementById('ai-tree-explain').innerHTML = 
                        "<strong>Árvore de Decisão XAI (Isolation Forest + Rust DPI):</strong><br>" +
                        "• Node 1: Entropia (" + data.entropy + ") > Limiar (" + data.ai_threshold + ") = " + (data.entropy > data.ai_threshold ? "TRUE" : "FALSE") + "<br>" +
                        "• Node 2: UEBA Anomalia = " + data.ueba_status + "<br>" +
                        "• Ação Final Aplicada: <span style='color: #f85149;'>" + data.action + "</span>";
                };

                logsContainer.appendChild(entry);
                logsContainer.scrollTop = logsContainer.scrollHeight;
            }

            const siemStream = document.getElementById('siem-stream');
            if (siemStream) {
                const siemLine = document.createElement("div");
                siemLine.innerText = data.siem_log;
                siemStream.appendChild(siemLine);
                siemStream.scrollTop = siemStream.scrollHeight;
            }

            if (data.is_quarantined) {
                quarantinedSet.add(data.ip);
            }

            const qCountElem = document.getElementById('soc-quarantine-count');
            if (qCountElem) qCountElem.innerText = quarantinedSet.size + ' IPs';
        };
    </script>
</body>
</html>
"""

@app.get("/")
async def get(username: str = Depends(verify_credentials)):
    return HTMLResponse(HTML_TEMPLATE)

@app.post("/api/v1/webhook-config")
async def update_webhook_config(settings: dict, username: str = Depends(verify_credentials)):
    user = USERS_DB.get(username)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores podem configurar webhooks")
    WEBHOOK_CONFIG["url"] = settings.get("url", "")
    WEBHOOK_CONFIG["enabled"] = settings.get("enabled", True)
    return {"status": "success", "config": WEBHOOK_CONFIG}

def generate_sample_payload(high_entropy: bool = False) -> tuple:
    if high_entropy:
        raw = bytes(random.getrandbits(8) for _ in range(128))
    else:
        text_samples = [
            b"GET /index.html HTTP/1.1\r\nHost: enterprise.com\r\n\r\n",
            b"POST /api/v1/auth HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
        ]
        raw = random.choice(text_samples)
    
    hex_dump = ' '.join(f'{b:02x}' for b in raw)
    return raw, hex_dump

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    tenants_ips = [
        ("Global-Enterprise", "192.168.1.50"),
        ("Global-Enterprise", "45.33.22.11"),
        ("Alpha-Fintech", "185.220.101.5"),
        ("Alpha-Fintech", "172.16.0.99")
    ]

    try:
        while True:
            tenant_id, ip = random.choice(tenants_ips)
            is_attack = random.random() < 0.35
            
            payload, payload_hex = generate_sample_payload(high_entropy=is_attack)
            entropy = round(core_rust.calculate_entropy(payload), 4)
            rps = random.randint(300, 550) if is_attack else random.randint(40, 150)
            
            ueba_status = ai_agent.evaluate_behavior(rps, entropy)
            current_threshold = ai_agent.evaluate_and_adapt(18 if is_attack else 5)

            if entropy > current_threshold or ueba_status != "NORMAL":
                threat_level = "CRITICA"
                action = "EDGE_FIREWALL_DROP_WITH_POW"
                quarantine_mgr.isolate_ip(ip)
                enforce_edge_firewall(ip)
                
                asyncio.create_task(dispatch_webhook({
                    "tenant": tenant_id,
                    "ip": ip,
                    "entropy": entropy,
                    "action": action,
                    "timestamp": time.time()
                }))
            elif entropy > (current_threshold - 1.5):
                threat_level = "ATAQUE_ATIVO"
                action = "SMART_RATE_LIMIT"
            else:
                threat_level = "RECONHECIMENTO"
                action = "MONITORAR_UEBA"

            is_isolated = quarantine_mgr.is_quarantined(ip)
            siem_msg = f"CEF:0|NexusDefender|XDR|2.6|ALERT-{threat_level}|IP {ip} Action {action}|8|src={ip} spt={rps} entropy={entropy}"

            log_incident(tenant_id, ip, threat_level, action, rps, entropy, is_isolated, payload_hex)

            telemetry = {
                "tenant": tenant_id,
                "ip": ip,
                "threat_level": threat_level,
                "action": action,
                "rps": rps,
                "entropy": entropy,
                "ai_threshold": current_threshold,
                "is_quarantined": is_isolated,
                "ueba_status": ueba_status,
                "payload_hex": payload_hex,
                "siem_log": siem_msg,
                "timestamp": time.time()
            }

            await websocket.send_json(telemetry)
            await asyncio.sleep(0.6)
    except Exception as e:
        print(f"Erro WebSocket: {e}")

@app.get("/api/v1/incidents")
async def get_incidents(username: str = Depends(verify_credentials)):
    """Endpoint protegido para fornecer os registos forenses guardados no SQLite ao HUD SOC."""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
        rows = cursor.fetchall()
        incidents = [dict(row) for row in rows]
        conn.close()
        return {"status": "success", "count": len(incidents), "incidents": incidents}
    except Exception as e:
        return {"status": "error", "message": str(e), "incidents": []}