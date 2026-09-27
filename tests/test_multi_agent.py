import asyncio
from services.detector import processar_fluxo_trafego
from services.diagnostic import processar_diagnosticos
from services.multi_agent_defense import RouterAndMultiAgentEngine


async def main():
    fila_bruta = asyncio.Queue()
    fila_diagnosticos = asyncio.Queue()

    engine = RouterAndMultiAgentEngine()

    # Criação explícita de tasks
    t_detector = asyncio.create_task(processar_fluxo_trafego(fila_bruta))
    t_diagnostic = asyncio.create_task(processar_diagnosticos(fila_bruta, fila_diagnosticos))
    t_router = asyncio.create_task(engine.event_router(fila_diagnosticos))
    
    t_w_ddos = asyncio.create_task(engine.worker_ddos())
    t_w_exploit = asyncio.create_task(engine.worker_exploit())
    t_w_scan = asyncio.create_task(engine.worker_scan())

    # Aguarda o agendamento inicial das tarefas
    await asyncio.sleep(0.1)

    # Executa a simulação de tráfego por 6 segundos
    await asyncio.sleep(6)

    # Encerramento controlado
    t_detector.cancel()
    await asyncio.sleep(1)  # Dá tempo para esvaziar os buffers das filas

    t_diagnostic.cancel()
    t_router.cancel()
    t_w_ddos.cancel()
    t_w_exploit.cancel()
    t_w_scan.cancel()

    print("\n[MULTI-AGENT SYSTEM] Múltiplos trabalhadores concluídos com sucesso!")
    print(f"IPs isolados no Core Rust: {engine.quarantine_manager.get_isolated_ips()}")


if __name__ == "__main__":
    asyncio.run(main())