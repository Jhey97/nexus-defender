import asyncio
import numpy as np
import core_rust
from common.events import DiagnosticoAmeaca, AcaoDefensiva


class BaseQAgent:
    """Classe base para os Agentes de Aprendizado por Reforço Tabular (Q-Learning)."""

    def __init__(self, name: str, alpha=0.1, gamma=0.9, epsilon=0.10):
        self.name = name
        self.alpha = alpha      # Taxa de aprendizado
        self.gamma = gamma      # Fator de desconto
        self.epsilon = epsilon  # Taxa de exploração (epsilon-greedy)

        # Estados: Nível Risco (1-5) x Ativo Crítico (0-1) = Shape (5, 2)
        # Ações: 5 Ações possíveis (0: PERMITIR, 1: MONITORAR, 2: TARPIT, 3: QUARENTENA, 4: BLOQUEAR)
        self.q_table = np.zeros((5, 2, 5))

    def escolher_acao(self, nivel_risco_val: int, ativo_critico: bool) -> AcaoDefensiva:
        state_idx = max(0, min(nivel_risco_val - 1, 4))
        crit_idx = 1 if ativo_critico else 0

        # Epsilon-Greedy: Exploração vs Exploitation
        if np.random.rand() < self.epsilon:
            return AcaoDefensiva(np.random.choice(5))
        
        melhor_acao_idx = int(np.argmax(self.q_table[state_idx, crit_idx]))
        return AcaoDefensiva(melhor_acao_idx)

    def atualizar_q(
        self,
        nivel_risco_val: int,
        ativo_critico: bool,
        acao: AcaoDefensiva,
        recompensa: float,
        proximo_nivel_val: int
    ):
        state_idx = max(0, min(nivel_risco_val - 1, 4))
        crit_idx = 1 if ativo_critico else 0
        next_state_idx = max(0, min(proximo_nivel_val - 1, 4))

        action_idx = acao.value
        
        q_atual = self.q_table[state_idx, crit_idx, action_idx]
        max_q_futuro = np.max(self.q_table[next_state_idx, crit_idx])

        # Equação de Bellman
        novo_q = q_atual + self.alpha * (recompensa + self.gamma * max_q_futuro - q_atual)
        self.q_table[state_idx, crit_idx, action_idx] = novo_q


class AgentDDoS(BaseQAgent):
    """
    Agente focado em mitigação de volumetria (Layer 7 / Rate Limit / Tarpit).
    Recompensa: Preservar latência e evitar drop desnecessário de tráfego legítimo.
    """

    def __init__(self):
        super().__init__("Q-Agent-DDoS")
        # Inicialização com viés a priori para controle de vazão
        self.q_table[2:, :, AcaoDefensiva.TARPIT.value] = 5.0
        self.q_table[3:, :, AcaoDefensiva.BLOQUEAR_DROP.value] = 8.0

    def calcular_recompensa(self, acao: AcaoDefensiva, nivel_risco: int) -> float:
        if nivel_risco >= 4:
            if acao == AcaoDefensiva.BLOQUEAR_DROP:
                return 10.0  # Protege o servidor de cair por sobrecarga
            elif acao == AcaoDefensiva.TARPIT:
                return 6.0   # Segura vazão, mas consome conexões do pool
            elif acao == AcaoDefensiva.PERMITIR:
                return -15.0 # Severa penalidade por indisponibilidade (DDoS bem sucedido)
        else:
            if acao == AcaoDefensiva.BLOQUEAR_DROP:
                return -8.0  # Falso positivo penalizado (bloqueou cliente legítimo)
            elif acao in (AcaoDefensiva.PERMITIR, AcaoDefensiva.MONITORAR):
                return 5.0
        return 0.0


class AgentExploit(BaseQAgent):
    """
    Agente focado em RCE, Payload Injection e Vulnerabilidades.
    Recompensa: Penaliza severamente Falsos Negativos (deixar exploit passar).
    """

    def __init__(self):
        super().__init__("Q-Agent-Exploit")
        # Viés inicial forte para Quarentena Sandbox e Bloqueio
        self.q_table[1:, :, AcaoDefensiva.QUARENTENA_SANDBOX.value] = 7.0
        self.q_table[3:, :, AcaoDefensiva.BLOQUEAR_DROP.value] = 10.0

    def calcular_recompensa(self, acao: AcaoDefensiva, nivel_risco: int) -> float:
        if nivel_risco >= 3:
            if acao == AcaoDefensiva.QUARENTENA_SANDBOX:
                return 12.0  # Isola ameaça sem perder evidência forense
            elif acao == AcaoDefensiva.BLOQUEAR_DROP:
                return 9.0
            elif acao == AcaoDefensiva.PERMITIR:
                return -25.0 # Catastrófico: RCE/Exploit executado com sucesso
        else:
            if acao == AcaoDefensiva.QUARENTENA_SANDBOX:
                return 2.0   # Custo baixo de envio para sandbox mesmo se inofensivo
        return 1.0


class AgentScan(BaseQAgent):
    """
    Agente focado em Reconhecimento, Port Scan e Mapeamento de Rede.
    Recompensa: Enganar o atacante (Decoy/Honeypot) para coletar inteligência.
    """

    def __init__(self):
        super().__init__("Q-Agent-Scan")
        # Viés para Tarpit/Honeypot
        self.q_table[:3, :, AcaoDefensiva.MONITORAR.value] = 4.0
        self.q_table[2:, :, AcaoDefensiva.TARPIT.value] = 8.0

    def calcular_recompensa(self, acao: AcaoDefensiva, nivel_risco: int) -> float:
        if acao == AcaoDefensiva.TARPIT:
            return 10.0  # Engana o scanner retendo pacotes no Core Rust (Decoy Delay)
        elif acao == AcaoDefensiva.MONITORAR:
            return 6.0   # Mapeia fingerprints sem alertar o atacante
        elif acao == AcaoDefensiva.BLOQUEAR_DROP:
            return 1.0   # Funciona, mas revela ao atacante a presença de Firewall
        return -2.0


class RouterAndMultiAgentEngine:
    def __init__(self, quarantine_manager=None):
        self.quarantine_manager = quarantine_manager or core_rust.QuarantineManager()
        self.agent_ddos = AgentDDoS()
        self.agent_exploit = AgentExploit()
        self.agent_scan = AgentScan()

        self.queue_ddos = asyncio.Queue()
        self.queue_exploit = asyncio.Queue()
        self.queue_scan = asyncio.Queue()

    async def event_router(self, queue_in: asyncio.Queue):
        print("[ROUTER] Roteador Assíncrono de Ameaças iniciado...")
        while True:
            diag: DiagnosticoAmeaca = await queue_in.get()
            
            entropia = diag.detalhes_tecnicos.get("entropia_detectada", 0.0)
            rps = diag.detalhes_tecnicos.get("rps_medido", 0)

            # Roteamento por característica técnica
            if entropia >= 7.0:
                await self.queue_exploit.put(diag)
            elif rps >= 80:
                await self.queue_ddos.put(diag)
            else:
                await self.queue_scan.put(diag)

            queue_in.task_done()
            await asyncio.sleep(0.01)

    async def worker_ddos(self):
        while True:
            diag = await self.queue_ddos.get()
            nivel_val = diag.nivel_risco.value if hasattr(diag.nivel_risco, 'value') else int(diag.nivel_risco)
            
            acao = self.agent_ddos.escolher_acao(nivel_val, False)
            recompensa = self.agent_ddos.calcular_recompensa(acao, nivel_val)
            self.agent_ddos.atualizar_q(nivel_val, False, acao, recompensa, nivel_val)

            if acao in (AcaoDefensiva.TARPIT, AcaoDefensiva.QUARENTENA_SANDBOX, AcaoDefensiva.BLOQUEAR_DROP):
                self.quarantine_manager.isolate_ip(diag.ip_origem)

            print(
                f"[WORKER DDoS -> AÇÃO] IP: {diag.ip_origem} | "
                f"Ação: {acao.name} | Reward: {recompensa:+.1f}"
            )
            self.queue_ddos.task_done()
            await asyncio.sleep(0.01)

    async def worker_exploit(self):
        while True:
            diag = await self.queue_exploit.get()
            nivel_val = diag.nivel_risco.value if hasattr(diag.nivel_risco, 'value') else int(diag.nivel_risco)

            acao = self.agent_exploit.escolher_acao(nivel_val, True)
            recompensa = self.agent_exploit.calcular_recompensa(acao, nivel_val)
            self.agent_exploit.atualizar_q(nivel_val, True, acao, recompensa, nivel_val)

            if acao in (AcaoDefensiva.TARPIT, AcaoDefensiva.QUARENTENA_SANDBOX, AcaoDefensiva.BLOQUEAR_DROP):
                self.quarantine_manager.isolate_ip(diag.ip_origem)

            print(
                f"[WORKER EXPLOIT -> AÇÃO] IP: {diag.ip_origem} | "
                f"Ação: {acao.name} | Reward: {recompensa:+.1f}"
            )
            self.queue_exploit.task_done()
            await asyncio.sleep(0.01)

    async def worker_scan(self):
        while True:
            diag = await self.queue_scan.get()
            nivel_val = diag.nivel_risco.value if hasattr(diag.nivel_risco, 'value') else int(diag.nivel_risco)

            acao = self.agent_scan.escolher_acao(nivel_val, False)
            recompensa = self.agent_scan.calcular_recompensa(acao, nivel_val)
            self.agent_scan.atualizar_q(nivel_val, False, acao, recompensa, nivel_val)

            if acao in (AcaoDefensiva.TARPIT, AcaoDefensiva.QUARENTENA_SANDBOX, AcaoDefensiva.BLOQUEAR_DROP):
                self.quarantine_manager.isolate_ip(diag.ip_origem)

            print(
                f"[WORKER SCAN -> AÇÃO] IP: {diag.ip_origem} | "
                f"Ação: {acao.name} | Reward: {recompensa:+.1f}"
            )
            self.queue_scan.task_done()
            await asyncio.sleep(0.01)