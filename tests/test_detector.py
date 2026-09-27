import asyncio
from services.detector import processar_fluxo_trafego


async def main():
    fila_eventos = asyncio.Queue()

    # Roda o detector em background por 5 segundos
    task = asyncio.create_task(processar_fluxo_trafego(fila_eventos))
    
    await asyncio.sleep(5)
    task.cancel()

    print(f"\n[TESTE DETECTOR] Total de anomalias capturadas na fila: {fila_eventos.qsize()}")
    while not fila_eventos.empty():
        evt = await fila_eventos.get()
        print(f" -> Evento processado: IP={evt.ip_origem}, Entropia={evt.entropia_payload:.2f}")


if __name__ == "__main__":
    asyncio.run(main())