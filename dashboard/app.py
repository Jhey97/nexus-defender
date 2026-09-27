import asyncio
import time
import pandas as pd
import streamlit as st
from services.detector import processar_fluxo_trafego
from services.diagnostic import processar_diagnosticos
from services.defense import AutonomousDefenseEngine

st.set_page_config(
    page_title="Nexus-Defender | SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Nexus-Defender — Autonomous Threat Detection & Mitigation")
st.caption("Engine Híbrida Python + Rust com Aprendizado por Reforço (Q-Learning)")

# Métricas Top-Level
col1, col2, col3, col4 = st.columns(4)
metric_eventos = col1.metric("Anomalias Detectadas", "0")
metric_quarentena = col2.metric("IPs Isolados (Rust)", "0")
metric_entropia = col3.metric("Média de Entropia", "0.0")
metric_status = col4.metric("Status do Sistema", "ONLINE", delta_color="normal")

st.divider()

# Colunas para Gráficos e Tabela de Logs
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("📊 Fluxo de Eventos e Diagnósticos")
    table_placeholder = st.empty()

with col_right:
    st.subheader("🚫 IPs Isolados no Core em Rust")
    quarantine_placeholder = st.empty()


async def rodar_simulacao_dashboard():
    fila_bruta = asyncio.Queue()
    fila_diagnosticos = asyncio.Queue()
    engine_defesa = AutonomousDefenseEngine()

    # Inicia os serviços em background
    asyncio.create_task(processar_fluxo_trafego(fila_bruta))
    asyncio.create_task(processar_diagnosticos(fila_bruta, fila_diagnosticos))

    historico_eventos = []

    while True:
        # Consome eventos se houver no buffer
        while not fila_diagnosticos.empty():
            diag = await fila_diagnosticos.get()
            
            # Aplica a mitigação no Q-Learning + Rust
            engine_defesa.agent.escolher_acao(diag.nivel_risco)
            engine_defesa.quarantine_manager.isolate_ip(diag.ip_origem)

            historico_eventos.append({
                "Timestamp": pd.to_datetime(diag.criado_em).strftime("%H:%M:%S"),
                "IP Origem": diag.ip_origem,
                "Nível Risco": diag.nivel_risco.name,
                "Tipo Ataque": diag.tipo_ataque,
                "Entropia": round(diag.detalhes_tecnicos["entropia_detectada"], 2),
                "RPS": diag.detalhes_tecnicos["rps_medido"]
            })

        # Atualiza a interface
        if historico_eventos:
            df = pd.DataFrame(historico_eventos).tail(10)
            table_placeholder.dataframe(df, use_container_width=True)

            ips_isolados = engine_defesa.quarantine_manager.get_isolated_ips()
            quarantine_placeholder.write(ips_isolados)

            metric_eventos.metric("Anomalias Detectadas", len(historico_eventos))
            metric_quarentena.metric("IPs Isolados (Rust)", len(ips_isolados))
            metric_entropia.metric("Média de Entropia", f"{df['Entropia'].mean():.2f}")

        await asyncio.sleep(1)


# Botão para disparar o motor no Streamlit
if st.sidebar.button("▶️ Iniciar Monitoramento em Tempo Real", type="primary"):
    asyncio.run(rodar_simulacao_dashboard())