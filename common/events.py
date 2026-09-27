from enum import Enum
from typing import Dict, Any
from pydantic import BaseModel, Field


class NivelAmeaca(int, Enum):
    INOFENSIVO = 1
    RECONHECIMENTO = 2
    ANOMALIA_APLICACAO = 3
    ATAQUE_ATIVO = 4
    AMEACA_CRITICA = 5


class AcaoDefensiva(int, Enum):
    PERMITIR = 0
    MONITORAR = 1
    TARPIT = 2
    QUARENTENA_SANDBOX = 3
    BLOQUEAR_DROP = 4


class EventoAnomaliaBruta(BaseModel):
    event_id: str
    ip_origem: str
    timestamp: float
    entropia_payload: float
    requisicoes_por_segundo: int
    payload_sample: str


class DiagnosticoAmeaca(BaseModel):
    event_id: str
    ip_origem: str
    nivel_risco: NivelAmeaca
    tipo_ataque: str
    score_confianca: float
    detalhes_tecnicos: Dict[str, Any] = Field(default_factory=dict)