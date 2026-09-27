import numpy as np
from typing import Dict, List, Set, Tuple


class AttackGraphAnalytics:
    def __init__(self, adj_matrix: np.ndarray, base_risks: np.ndarray, alpha: float = 0.85):
        """
        :param adj_matrix: Matriz de adjacência da rede (N x N)
        :param base_risks: Vetor de riscos base iniciais de cada nó
        :param alpha: Fator de amortecimento / desconto para propagação
        """
        self.A = np.array(adj_matrix, dtype=float)
        self.base_risks = np.array(base_risks, dtype=float)
        self.alpha = alpha
        self.num_nodes = self.A.shape[0]

    # -------------------------------------------------------------------------
    # A. Análise Recursiva de Grafos de Ataque (DFS com Memória)
    # -------------------------------------------------------------------------
    def calcular_risco_acumulado_dfs(
        self, 
        nodo: int, 
        max_depth: int = 5, 
        visited: Set[int] = None, 
        memo: Dict[Tuple[int, int], float] = None
    ) -> float:
        """
        Calcula o Risco Acumulado Recursivo:
        R(nodo) = RiscoBase(nodo) + gamma * sum(R(vizinho))
        Aplica memoização (nodo, profundidade) para otimização de tempo O(V + E).
        """
        if visited is None:
            visited = set()
        if memo is None:
            memo = {}

        # Caso base: profundidade máxima atingida ou ciclo detectado
        if max_depth == 0 or nodo in visited:
            return float(self.base_risks[nodo])

        # Verificação na memória de memoização
        state_key = (nodo, max_depth)
        if state_key in memo:
            return memo[state_key]

        visited.add(nodo)
        vizinhos = np.where(self.A[nodo] > 0)[0]
        
        soma_risco_vizinhos = 0.0
        for vizinho in vizinhos:
            if vizinho not in visited:
                soma_risco_vizinhos += self.calcular_risco_acumulado_dfs(
                    vizinho, max_depth - 1, visited.copy(), memo
                )

        risco_acumulado = self.base_risks[nodo] + (self.alpha * soma_risco_vizinhos)
        memo[state_key] = risco_acumulado
        return risco_acumulado

    # -------------------------------------------------------------------------
    # B. Power Iteration para Autovalor Dominante e Markov Threat PageRank
    # -------------------------------------------------------------------------
    def construir_matriz_estocastica(self) -> np.ndarray:
        """
        Converte a matriz de adjacência A em uma Matriz Estocástica P,
        onde a soma de cada linha é igual a 1 (normalização por grau de saída).
        """
        out_degrees = self.A.sum(axis=1)
        out_degrees[out_degrees == 0] = 1.0  # Evita divisão por zero em nós folha
        
        P = self.A / out_degrees[:, np.newaxis]
        
        # Teleporte estocástico (Google PageRank / Markov Random Walk)
        E = np.ones((self.num_nodes, self.num_nodes)) / self.num_nodes
        P_markov = self.alpha * P + (1 - self.alpha) * E
        return P_markov

    def calcular_pagerank_ameaca(self, tol: float = 1e-6, max_iter: int = 200) -> Tuple[np.ndarray, int]:
        """
        Calcula o autovetor estacionário (v * P = v) via Power Iteration:
        v^(t+1) = v^(t) * P
        Retorna o vetor de centralidade do nó (autovetor com lambda_1 = 1) e nº de iterações.
        """
        P = self.construir_matriz_estocastica()
        # Vetor de estado inicial uniforme
        v = np.ones(self.num_nodes) / self.num_nodes

        iterations = 0
        for i in range(max_iter):
            iterations += 1
            v_next = np.dot(v, P)
            
            # Normalização L1
            v_next = v_next / np.linalg.norm(v_next, ord=1)
            
            # Checagem de convergência
            if np.linalg.norm(v_next - v, ord=1) < tol:
                v = v_next
                break
            v = v_next

        return v, iterations