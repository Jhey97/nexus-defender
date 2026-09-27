# 🛡️ Nexus-Defender: Autonomous Cyber Threat Mitigation & Event Pipeline

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/Rust-Edition%202024-orange?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**Nexus-Defender** é um sistema autônomo de alta performance de segurança cibernética (SIEM/SOAR) de arquitetura híbrida. Ele combina a velocidade e isolamento de memória de **Rust (via FFI/PyO3)** com a flexibilidade de processamento assíncrono e aprendizado de máquina em **Python**. 

O sistema utiliza Agentes de Aprendizado por Reforço baseados em Q-Learning e análises algébricas de grafos/cadeias de Markov para rastrear movimentos laterais e mitigar ameaças ativas em tempo real.

---

## 🏗️ Arquitetura do Sistema
+--------------------------------------------------------------------------+
|                       NEXUS-DEFENDER ENGINE                              |
|                                                                          |
|  [Simulador de Tráfego] ---> [Detector de Anomalias]                     |
|                                    |                                     |
|                                    v                                     |
|                        [Serviço de Diagnóstico]                          |
|                                    |                                     |
|                                    v                                     |
|                   [Router de Ameaças & Multi-Agent RL]                   |
|                        /           |           \                         |
|           [Worker DDoS]  [Worker Exploit]  [Worker Scan]                 |


---

## ⚙️ Funcionalidades Principais

* **Pipeline Reativo Assíncrono:** Filas assíncronas dedicadas (`asyncio`) garantem zero perda de eventos sob alto volume de requisições por segundo (RPS).
* **Multi-Agent Q-Learning:** Três agentes independentes otimizam políticas de resposta (`MONITORAR`, `TARPIT`, `BLOQUEAR_DROP`, `QUARENTENA_SANDBOX`) com base em recompensas dinâmicas por severidade de ataque.
* **Análise Topológica & Markoviana:** Uso de Álgebra Linear, busca em profundidade com memoização (DFS) para risco de movimento lateral ($O(V + E)$) e *Power Iteration* para cálculo convergente de *Threat PageRank*.
* **Core de Alta Performance em Rust:** Módulo dinâmico acoplado via FFI (`PyO3`) responsável pelo gerenciamento estrito e isolamento de IPs maliciosos em quarentena/tarpit.
* **Dashboard Real-Time:** Servidor de streaming integrado com FastAPI e WebSockets para visualização de métricas (Entropia vs. RPS) e logs operacionais.

---

## 🚀 Como Executar o Projeto

### Pré-requisitos
* Python 3.10+ instalado.
* Ferramentas de compilação do Rust (`cargo` / `rustc`).

### 1. Clonar o Repositório
```bash
git clone [https://github.com/Jhey97/nexus-defender.git](https://github.com/Jhey97/nexus-defender.git)
cd nexus-defender

python -m venv venv
# No Windows (PowerShell):
.\venv\Scripts\Activate
# No Linux/macOS:
# source venv/bin/activate

3. Instalar as Dependências e Compilar o Core RustCertifique-se de ter o ambiente de compilação do Rust configurado para gerar a biblioteca Python nativa (core_rust).4. Iniciar a AplicaçãoBashpython main.py
✒️ AutorJosé Henrique Cordeiro VieiraDesenvolvido por José Henrique Cordeiro Vieira.

📄 Licença
Distribuído sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.
|                        \           |           /                         |
|                                    v                                     |
|                   [Core Rust FFI: Quarantine/Tarpit]                     |
+--------------------------------------------------------------------------+
