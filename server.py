import asyncio
import random
import time
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse

app = FastAPI()

# HTML Frontend Embutido
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Nexus-Defender | Control Center</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-top: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; }
        #logs { height: 300px; overflow-y: auto; background: #010409; font-size: 12px; padding: 10px; border-radius: 4px; }
        .log-entry { margin-bottom: 4px; }
        .CRITICA { color: #ff7b72; font-weight: bold; }
        .ATIVO { color: #ffa657; }
        .RECONHECIMENTO { color: #7ee787; }
    </style>
</head>
<body>
    <h1>🛡️ NEXUS-DEFENDER — Real-time SOC Panel</h1>
    <div class="grid">
        <div class="card">
            <h3>Métricas de Fluxo (Entropia vs RPS)</h3>
            <canvas id="metricsChart" height="120"></canvas>
        </div>
        <div class="card">
            <h3>Terminal de Decisões do Agente RL</h3>
            <div id="logs"></div>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('metricsChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'RPS', borderColor: '#58a6ff', data: [], yAxisID: 'y' },
                    { label: 'Entropia (Payload)', borderColor: '#d2a8ff', data: [], yAxisID: 'y1' }
                ]
            },
            options: {
                scales: {
                    y: { type: 'linear', position: 'left', min: 0, max: 200 },
                    y1: { type: 'linear', position: 'right', min: 0, max: 10, grid: { drawOnChartArea: false } }
                }
            }
        });

        const ws = new WebSocket("ws://" + window.location.host + "/ws/telemetry");
        const logsContainer = document.getElementById("logs");

        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            // Atualiza Gráfico
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

            // Adiciona Log no Terminal
            const entry = document.createElement("div");
            entry.className = "log-entry " + data.threat_level;
            entry.innerText = `[${timeLabel}] IP: ${data.ip} | State: ${data.threat_level} | RL Action: ${data.action} (Score: ${data.score}) | Reward: ${data.reward}`;
            logsContainer.appendChild(entry);
            logsContainer.scrollTop = logsContainer.scrollHeight;
        };
    </script>
</body>
</html>
"""

@app.get("/")
async def get():
    return HTMLResponse(HTML_TEMPLATE)

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    ips = ["192.168.1.50", "45.33.22.11", "185.220.101.5", "172.16.0.99"]
    threats = [
        ("RECONHECIMENTO", "MONITORAR", 6.0),
        ("ANOMALIA_APLICACAO", "TARPIT", 0.0),
        ("ATAQUE_ATIVO", "BLOQUEAR_DROP", 9.0),
        ("CRITICA", "QUARENTENA_SANDBOX", 12.0)
    ]

    # Simulação da transmissão em tempo real do pipeline
    try:
        while True:
            ip = random.choice(ips)
            state, action, reward = random.choice(threats)
            score = round(random.uniform(0.5, 0.98), 4)
            rps = random.randint(40, 180)
            entropy = round(random.uniform(4.0, 7.9), 2)

            telemetry = {
                "ip": ip,
                "threat_level": state,
                "action": action,
                "score": score,
                "reward": reward,
                "rps": rps,
                "entropy": entropy,
                "timestamp": time.time()
            }

            await websocket.send_json(telemetry)
            await asyncio.sleep(0.8) # Ritmo dos eventos
    except Exception:
        pass