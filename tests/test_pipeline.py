import asyncio
from services.detector import processar_fluxo_trafego
from services.diagnostic import processar_diagnosticos


async def main():
    fila_bruta = asyncio.Queue()
    fila_diagnosticos = asyncio.Queue()

    # Inicia os dois microserviços trabalhando em pipeline
    task_detector = asyncio.create_task(processar_fluxo_trafego(fila_bruta))
    task_diagnostic = asyncio.create_task(processar_diagnosticos(fila_bruta, fila_diagnosticos))

    # Deixa o fluxo rodar por 6 segundos
    await asyncio.sleep(6)

    task_detector.cancel()
    task_diagnostic.cancel()

    print(f"\n[PIPELINE FINALIZADO] Total de diagnósticos gerados: {fila_diagnosticos.qsize()}")
    while not fila_diagnosticos.empty():
        diag = await fila_diagnosticos.get()
        print(f" -> Diagnóstico: IP={diag.ip_origem} | Risco={diag.nivel_risco.name} | JSON:\n{diag.to_json()}\n")


if __name__ == "__main__":
    asyncio.run(main())