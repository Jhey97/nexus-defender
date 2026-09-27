import asyncio
import numpy as np
import core_rust
from common.events import DiagnosticoAmeaca, AcaoDefensiva, NivelAmeaca


class QLearningDefenseAgent:
    """
    Agente de Aprendizado por Reforço para Tomada de Decisão Defensiva.
    
    Espaço de Estados: (NivelAmeaca [1..5], ImportanciaAtivo [0: Normal, 1: Crítico])
    Espaço de Ações: AcaoDefensiva [PERMITIR, MONITORAR, TARPIT, QUARENTENA_SANDBOX, BLOQUEAR_DROP]
    """
    def __init__(self, alpha=0.1, gamma=0.9, epsilon=0.1):
        self.alpha = alpha  # Taxa de aprendizado
        self.gamma = gamma  # Fator de desconto
        self.epsilon = epsilon  # Exploração vs. Exploitation
        
        # Q-Table: Dimensão [5 Níveis de Ameaça x 2 Tipos de Ativo, 5 Ações]
        self.q_table = np.zeros((5, 2, 5))
        self._inicializar_politica_base()

    def _inicializar_politica_base(self):
        """Preenche a Q-Table inicial com heurísticas para acelerar a convergência."""
        # Nível 1: Prioriza PERMITIR (0)
        self.q_table[0, :, 0] = 5.0
        # Nível 2: Prioriza MONITORAR (1)
        self.q_table[1, :, 1] = 5.0
        # Nível 3: Prioriza TARPIT (2)
        self.q_table[2, :, 2] = 5.0
        # Nível 4: Prioriza QUARENTENA_SANDBOX (3)
        self.q_table[3, :, 3] = 6.0
        # Nível 5: Prioriza BLOQUEAR_DROP (4)
        self.q_table[4, :, 4] = 8.0

    def escolher_acao(self, nivel_risco: NivelAmeaca, ativo_critico: bool = False) -> AcaoDefensiva:
        state_nivel = nivel_risco.value - 1
        state_ativo = 1 if ativo_critico else 0

        # Política Epsilon-Greedy
        if np.random.rand() < self.epsilon:
            acao_idx = np.random.choice(5)
        else:
            acao_idx = np.argmax(self.q_table[state_nivel, state_ativo])

        return AcaoDefensiva(acao_idx)


class AutonomousDefenseEngine:
    def __init__(self):
        self.agent = QLearningDefenseAgent()
        self.quarantine_manager = core_rust.QuarantineManager()

    async def processar_defesa(self, queue_in: asyncio.Queue):
        print("[DEFENSE ENGINE] Motor de Defesa Autônoma com Q-Learning iniciado...")

        while True:
            diagnostico: DiagnosticoAmeaca = await queue_in.get()

            # Decide a ação com base no diagnóstico do Microserviço 2
            acao = self.agent.escolher_acao(diagnostico.nivel_risco, ativo_critico=False)

            # Executa a ação no Core em Rust
            if acao in (AcaoDefensiva.TARPIT, AcaoDefensiva.QUARENTENA_SANDBOX):
                self.quarantine_manager.isolate_ip(diagnostico.ip_origem)
                status_rust = "ISOLADO NA QUARENTENA/TARPIT (RUST)"
            elif acao == AcaoDefensiva.BLOQUEAR_DROP:
                self.quarantine_manager.isolate_ip(diagnostico.ip_origem)
                status_rust = "BLOQUEIO DEFINITIVO / DROP (RUST)"
            else:
                status_rust = "TRÁFEGO PERMITIDO / MONITORADO"

            print(
                f"[DEFENSE -> AÇÃO TOMADA] IP: {diagnostico.ip_origem} | "
                f"Nível: {diagnostico.nivel_risco.name} | "
                f"Ação do Agente: {acao.name} | "
                f"Status Rust: {status_rust}"
            )

            print(f" -> IPs atualmente na Quarentena Rust: {self.quarantine_manager.get_isolated_ips()}")
            queue_in.task_done()