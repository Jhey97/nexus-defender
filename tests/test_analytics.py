import numpy as np
from analytics.graph_markov import AttackGraphAnalytics


def test_analytics():
    # Topologia: 5 Nós (0: Edge Router, 1: Web App, 2: API Gateway, 3: DB Master, 4: Active Directory)
    adj_matrix = np.array([
        [0, 1, 1, 0, 0],  # Edge Router -> Web App, API
        [0, 0, 1, 1, 0],  # Web App -> API, DB
        [0, 0, 0, 1, 1],  # API -> DB, AD
        [0, 0, 0, 0, 0],  # DB Master (Nó folha)
        [0, 0, 0, 1, 0],  # AD -> DB
    ])

    # Riscos isolados base [0.1 a 0.9]
    base_risks = np.array([0.2, 0.5, 0.6, 0.9, 0.95])

    analytics = AttackGraphAnalytics(adj_matrix, base_risks, alpha=0.85)

    # 1. Teste de Risco Acumulado por DFS Recursiva no Edge Router (Nó 0)
    risco_mov_lateral = analytics.calcular_risco_acumulado_dfs(nodo=0, max_depth=4)
    print(f"[DFS RECURSIVA] Risco Acumulado do Movimento Lateral (Origem Node 0): {risco_mov_lateral:.4f}")

    # 2. Teste do PageRank de Ameaça via Power Iteration (Markov)
    v_estacionario, iters = analytics.calcular_pagerank_ameaca()
    print(f"[POWER ITERATION] Autovetor Dominante de Centralidade (Convergência em {iters} iterações):")
    
    nomes_nos = ["Router", "Web App", "API Gateway", "DB Master", "Active Directory"]
    for idx, rank in enumerate(v_estacionario):
        print(f"  - {nomes_nos[idx]}: Centralidade de Ameaça = {rank:.4f}")


if __name__ == "__main__":
    test_analytics()