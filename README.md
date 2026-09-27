# 🛡️ Nexus-Defender // Autonomous Cyber Threat Mitigation & Event Pipeline

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/Rust-Edition%202024-orange?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**Nexus-Defender** é um sistema autônomo de alta performance de segurança cibernética (SIEM/SOAR) de arquitetura híbrida. Ele combina a velocidade e isolamento de memória de **Rust (via FFI/PyO3)** com a flexibilidade de processamento assíncrono e aprendizado de máquina em **Python**. 

O sistema utiliza Agentes de Aprendizado por Reforço baseados em Q-Learning e análises algébricas de grafos para rastrear movimentos laterais e mitigar ameaças ativas em tempo real ($\le 50\,\mu s$).

---

## 🏗️ Arquitetura do Sistema

┌──────────────────────────────────────────────────────────────────────────┐
│                        NEXUS-DEFENDER ENGINE                             │
│                                                                          │
│   [Simulador de Tráfego] ---> [Detector de Anomalias]                    │
│                                     |                                    │
│                                     v                                    │
│                         [Serviço de Diagnóstico]                         │
│                                     |                                    │
│                                     v                                    │
│                  [Router de Ameaças & Multi-Agent RL]                    │
│                       /             |             \                      │
│              [Worker DDoS]   [Worker Exploit]   [Worker Scan]            │
│                                     |                                    │
│                                     v                                    │
│                   [Core Rust FFI: Quarantine/Tarpit]                     │
└──────────────────────────────────────────────────────────────────────────┘
---

## ⚙️ Funcionalidades Principais

- **Pipeline Reativo Assíncrono:** Filas assíncronas dedicadas (`asyncio`) garantem zero perda de eventos sob alto volume de requisições por segundo (RPS).
- **Multi-Agent Q-Learning:** Agentes otimizam políticas de resposta (`MONITORAR`, `TARPIT`, `BLOQUEAR_DROP`, `QUARENTENA_SANDBOX`) com base em recompensas dinâmicas por severidade de ataque.
- **Análise Topológica & Markoviana:** Uso de Álgebra Linear e busca em profundidade para risco de movimento lateral e cálculo de *Threat PageRank*.
- **Core de Alta Performance em Rust:** Módulo dinâmico acoplado via FFI (`PyO3`) responsável pelo gerenciamento estrito e isolamento de IPs maliciosos em quarentena/tarpit em $\le 50\,\mu s$.
- **Dashboard Real-Time:** Servidor de streaming integrado com FastAPI e WebSockets para visualização de métricas e logs operacionais.

---

## 🚀 Como Executar o Projeto

### Pré-requisitos
- Python 3.10+ instalado.
- Ferramentas de compilação do Rust (`cargo` / `rustc`) e Maturin.

### 1. Compilar o Core Rust
```powershell
maturin develop --release

2. Instalar as Dependências
PowerShell
pip install -r requirements.txt
3. Iniciar o Backend FastAPI (Terminal 1)
PowerShell
python -m uvicorn api:app --reload --port 8000
4. Iniciar o Painel HUD Streamlit (Terminal 2)
PowerShell
python -m streamlit run dashboard.py
✒️ Autor
Desenvolvido por José Henrique Cordeiro Vieira.

📄 Licença
Distribuído sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.