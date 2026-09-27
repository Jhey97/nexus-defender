import asyncio
from services.detector import processar_fluxo_trafego
from services.diagnostic import processar_diagnosticos
from services.defense import AutonomousDefenseEngine


async def main():
    fila_bruta = asyncio.Queue()
    fila_diagnosticos = asyncio.Queue()

    engine_defesa = AutonomousDefenseEngine()

    # Executa os 3 microserviços em pipeline assíncrono
    task_detector = asyncio.create_task(processar_fluxo_trafego(fila_bruta))
    task_diagnostic = asyncio.create_task(processar_diagnosticos(fila_bruta, fila_diagnosticos))
    task_defense = asyncio.create_task(engine_defesa.processar_defesa(fila_diagnosticos))

    # Deixa o sistema rodar por 8 segundos
    await asyncio.sleep(8)

    task_detector.cancel()
    task_diagnostic.cancel()
    task_defense.cancel()

    print("\n[SISTEMA FINALIZADO] Teste End-to-End concluído com sucesso!")


if __name__ == "__main__":
    asyncio.run(main())