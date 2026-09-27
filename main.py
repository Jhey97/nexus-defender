# ==============================================================================
# NEXUS-DEFENDER — Autonomous Cyber Threat Mitigation & Event Pipeline
#
# Author: José Henrique Cordeiro Vieira
# Role: Lead Architect & Software Engineer
# Year: 2026
#
# Description:
#   A hybrid Python/Rust reactive pipeline utilizing Reinforcement Learning
#   and Markov Chain models for real-time traffic anomaly defense.
# ==============================================================================


import asyncio
import signal
import sys
import numpy as np
import core_rust

from common.events import EventoAnomaliaBruta
from services.detector import gerar_trafego_continuo
from services.diagnostic import processar_diagnosticos
from services.multi_agent_defense import RouterAndMultiAgentEngine
from analytics.graph_markov import AttackGraphAnalytics


def inicializar_analise_topologica():
    """Calcula a centralidade de ativos e riscos de rede antes da inicialização."""
    print("[INIT] Executando Análise Topológica de Rede (Álgebra Linear & Cadeias de Markov)...")
    
    # Topologia: Router (0), Web App (1), API Gateway (2), Database (3), Active Directory (4)
    adj_matrix = np.array([
        [0, 1, 1, 0, 0],
        [0, 0, 1, 1, 0],
        [0, 0, 0, 1, 1],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0]
    ])
    base_risks = np.array([0.2, 0.5, 0.6, 0.9, 0.95])
    
    analytics = AttackGraphAnalytics(adj_matrix, base_risks, alpha=0.85)
    risco_acumulado = analytics.calcular_risco_acumulado_dfs(nodo=0, max_depth=4)
    v_pagerank, iters = analytics.calcular_pagerank_ameaca()

    print(f"[INIT] Risco Acumulado do Movimento Lateral (Origem Node 0): {risco_acumulado:.4f}")
    print(f"[INIT] Markov Threat PageRank convergido em {iters} iterações.")
    print(f"[INIT] Maior Ativo Crítico Mapeado: Database Master (Score: {v_pagerank[3]:.4f})\n")


async def main():
    print("================================================================")
    print("             NEXUS-DEFENDER: SISTEMA AUTÔNOMO ATIVO             ")
    print("================================================================")

    # 1. Análise Matemática
    inicializar_analise_topologica()

    # 2. Inicialização das Filas e do Core Rust (FFI)
    print("[SYSTEM] Inicializando Gerenciador de Quarentena no Core Rust...")
    quarantine = core_rust.QuarantineManager()
    
    q_detector_to_diag = asyncio.Queue(maxsize=100)
    q_diag_to_router = asyncio.Queue(maxsize=100)

    # 3. Inicialização dos Agentes de Aprendizado por Reforço
    engine = RouterAndMultiAgentEngine(quarantine_manager=quarantine)

    print("[SYSTEM] Subindo corrotinas do pipeline reativo de segurança...")
    
    # Tarefas Assíncronas
    tasks = [
        asyncio.create_task(gerar_trafego_continuo(q_detector_to_diag)),
        asyncio.create_task(processar_diagnosticos(q_detector_to_diag, q_diag_to_router)),
        asyncio.create_task(engine.event_router(q_diag_to_router)),
        asyncio.create_task(engine.worker_ddos()),
        asyncio.create_task(engine.worker_exploit()),
        asyncio.create_task(engine.worker_scan()),
    ]

    print("[SYSTEM] Todos os serviços rodando! Pressione CTRL+C para interromper.\n")

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        print("\n[SYSTEM] Encerrando serviços assíncronos...")
    finally:
        ips_isolados = quarantine.get_isolated_ips()
        print(f"[RUST CORE] IPs mantidos em quarentena no encerramento: {ips_isolados}")
        print("[SYSTEM] Nexus-Defender finalizado com sucesso.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass