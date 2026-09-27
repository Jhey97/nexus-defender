import asyncio
import numpy as np
import core_rust

from common.events import EventoAnomaliaBruta, DiagnosticoAmeaca, NivelAmeaca
from services.diagnostic import processar_diagnosticos
from services.multi_agent_defense import RouterAndMultiAgentEngine
from analytics.graph_markov import AttackGraphAnalytics


async def simular_ingestao_eventos(queue_out: asyncio.Queue):
    """Simula a chegada de tráfego variado (DDoS, Exploit e Scan)."""
    eventos_simulados = [
        # Ataque Volumétrico (DDoS)
        EventoAnomaliaBruta(
            event_id="evt_01",
            ip_origem="203.0.113.5",
            timestamp=1700000000.0,
            entropia_payload=4.2,
            requisicoes_por_segundo=120,
            payload_sample="GET / HTTP/1.1",
        ),
        # Exploit / Payload Crítico
        EventoAnomaliaBruta(
            event_id="evt_02",
            ip_origem="198.51.100.42",
            timestamp=1700000001.0,
            entropia_payload=7.8,
            requisicoes_por_segundo=110,
            payload_sample="cat /etc/passwd | nc ...",
        ),
        # Scan / Mapeamento
        EventoAnomaliaBruta(
            event_id="evt_03",
            ip_origem="192.0.2.88",
            timestamp=1700000002.0,
            entropia_payload=5.1,
            requisicoes_por_segundo=55,
            payload_sample="Nmap SYN Scan",
        ),
    ]

    for evento in eventos_simulados:
        print(f"[SIMULADOR] Evento injetado | IP: {evento.ip_origem} | RPS: {evento.requisicoes_por_segundo}")
        await queue_out.put(evento)
        await asyncio.sleep(0.05)


async def main():
    print("==================================================")
    print("      NEXUS-DEFENDER: TESTE DE INTEGRAÇÃO GLOBAL   ")
    print("==================================================\n")

    # 1. Análise Topológica de Rede (Álgebra Linear / Grafos)
    print("--- 1. Análise Topológica e Centralidade de Ativos ---")
    adj_matrix = np.array([
        [0, 1, 1, 0],  # Edge
        [0, 0, 1, 1],  # Web App
        [0, 0, 0, 1],  # API Gateway
        [0, 0, 0, 0],  # DB Server
    ])
    base_risks = np.array([0.2, 0.5, 0.7, 0.95])
    analytics = AttackGraphAnalytics(adj_matrix, base_risks)

    v_pagerank, _ = analytics.calcular_pagerank_ameaca()
    db_risk = analytics.calcular_risco_acumulado_dfs(nodo=0)

    print(f"[GRAPH] Risco Acumulado no Movimento Lateral: {db_risk:.4f}")
    print(f"[MARKOV] Centralidade Ativo Crítico (DB Server): {v_pagerank[3]:.4f}\n")

    # 2. Inicialização do Pipeline e Motor Rust Native
    print("--- 2. Execução do Pipeline Assíncrono Multi-Agente ---")
    quarantine = core_rust.QuarantineManager()
    engine = RouterAndMultiAgentEngine(quarantine_manager=quarantine)

    q_detector_to_diag = asyncio.Queue()
    q_diag_to_router = asyncio.Queue()

    # Tarefas Assíncronas
    task_diag = asyncio.create_task(processar_diagnosticos(q_detector_to_diag, q_diag_to_router))
    task_router = asyncio.create_task(engine.event_router(q_diag_to_router))
    task_ddos = asyncio.create_task(engine.worker_ddos())
    task_exploit = asyncio.create_task(engine.worker_exploit())
    task_scan = asyncio.create_task(engine.worker_scan())

    # Ingestão de tráfego
    await simular_ingestao_eventos(q_detector_to_diag)

    # Aguarda o esvaziamento das filas
    await q_detector_to_diag.join()
    await q_diag_to_router.join()
    await engine.queue_ddos.join()
    await engine.queue_exploit.join()
    await engine.queue_scan.join()

    # Cancelamento gracioso das tarefas
    task_diag.cancel()
    task_router.cancel()
    task_ddos.cancel()
    task_exploit.cancel()
    task_scan.cancel()

    # 3. Validação do Estado Nativo em Rust
    print("\n--- 3. Verificação do Core Rust (FFI) ---")
    ips_isolados = quarantine.get_isolated_ips()
    print(f"[RUST CORE] IPs isolados na memória nativa: {ips_isolados}\n")

    print("==================================================")
    print("     TESTE CONCLUÍDO: TODOS OS SISTEMAS OK        ")
    print("==================================================")


if __name__ == "__main__":
    asyncio.run(main())