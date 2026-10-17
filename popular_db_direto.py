import sqlite3
import datetime

db_name = "nexus_audit.db"
print(f"[*] A ligar à base de dados {db_name}...")

try:
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    # Cria a tabela de incidentes caso não exista
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            tenant_id TEXT,
            ip TEXT,
            threat_level TEXT,
            action TEXT,
            rps REAL,
            entropy REAL,
            is_quarantined INTEGER,
            payload_hex TEXT
        )
    ''')
    
    # Dados simulados de incidentes forenses detalhados
    novos_incidentes = [
        (datetime.datetime.now().isoformat(), "Global-Enterprise", "192.168.1.105", "HIGH", "QUARANTINE", 450.2, 7.89, 1, "48 65 6c 6c 6f 20 58 44 52 20 41 6c 65 72 74"),
        (datetime.datetime.now().isoformat(), "Alpha-Fintech", "10.0.4.15", "CRITICAL", "BLOCK", 1200.5, 9.12, 1, "53 51 4c 69 20 49 6e 6a 65 63 74 69 6f 6e 20 44 65 74 65 63 74 65 64"),
        (datetime.datetime.now().isoformat(), "Global-Enterprise", "172.16.0.22", "MEDIUM", "MONITOR", 85.0, 5.41, 0, "52 65 63 6f 6e 20 53 63 61 6e 20 41 63 74 90 55")
    ]
    
    cursor.executemany('''
        INSERT INTO incidents (timestamp, tenant_id, ip, threat_level, action, rps, entropy, is_quarantined, payload_hex)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', novos_incidentes)
    
    conn.commit()
    conn.close()
    print("[*] Incidentes forenses injetados com sucesso na base de dados SQLite!")
except Exception as e:
    print(f"[!] Erro ao atualizar a base de dados: {e}")

print("\n✨ Feito! Feche e reabra o executável ou mude de aba no Nexus-Defender para ver os dados no board!")
