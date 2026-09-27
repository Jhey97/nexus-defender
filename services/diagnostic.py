import asyncio
from common.events import EventoAnomaliaBruta, DiagnosticoAmeaca, NivelAmeaca


def avaliar_grau_ameaca(evento: EventoAnomaliaBruta) -> tuple[NivelAmeaca, str, float]:
    entropia = evento.entropia_payload
    rps = evento.requisicoes_por_segundo

    if entropia >= 7.5 and rps >= 100:
        return NivelAmeaca.AMEACA_CRITICA, "Exploit/RCE Payload Injection", 0.95
    elif entropia >= 7.0:
        return NivelAmeaca.ATAQUE_ATIVO, "Suspicious Encrypted Payload", 0.82
    elif rps >= 80:
        return NivelAmeaca.ANOMALIA_APLICACAO, "High Rate Anomaly (Layer 7)", 0.75
    elif rps >= 50:
        return NivelAmeaca.RECONHECIMENTO, "Reconnaissance / Port Scan", 0.60
    else:
        return NivelAmeaca.INOFENSIVO, "Benign Traffic", 0.20


async def processar_diagnosticos(queue_in: asyncio.Queue, queue_out: asyncio.Queue):
    print("[DIAGNOSTIC] Serviço de Diagnóstico e Classificação iniciado...")

    while True:
        try:
            evento: EventoAnomaliaBruta = await queue_in.get()

            nivel_risco, tipo_ataque, score = avaliar_grau_ameaca(evento)

            diagnostico = DiagnosticoAmeaca(
                event_id=evento.event_id,
                ip_origem=evento.ip_origem,
                nivel_risco=nivel_risco,
                tipo_ataque=tipo_ataque,
                score_confianca=score,
                detalhes_tecnicos={
                    "entropia_detectada": evento.entropia_payload,
                    "rps_medido": evento.requisicoes_por_segundo,
                    "payload_sample": evento.payload_sample,
                }
            )

            print(
                f"[DIAGNOSTIC -> CLASSIFICADO] IP: {diagnostico.ip_origem} | "
                f"Nível: {diagnostico.nivel_risco.name} | Score: {diagnostico.score_confianca}"
            )

            await queue_out.put(diagnostico)
            queue_in.task_done()
            await asyncio.sleep(0.01)
        except Exception as e:
            print(f"[ERRO DIAGNOSTIC] Falha no processamento: {e}")
            queue_in.task_done()