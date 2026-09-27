import core_rust

# 1. Testando cálculo de entropia ultra-rápido em Rust
payload_limpo = b"GET /home HTTP/1.1\r\nHost: myapp.com\r\n"
payload_alta_entropia = bytes([i % 256 for i in range(500)]) # Simulando shellcode/malware

entropia_1 = core_rust.calculate_entropy(payload_limpo)
entropia_2 = core_rust.calculate_entropy(payload_alta_entropia)

print(f"[RUST CORE] Entropia Payload Limpo: {entropia_1:.4f}")
print(f"[RUST CORE] Entropia Payload Suspeito: {entropia_2:.4f}")

# 2. Testando Gerenciador de Quarentena
qm = core_rust.QuarantineManager()
qm.isolate_ip("192.168.1.105")

print(f"\n[RUST CORE] IP '192.168.1.105' isolado? {qm.is_quarantined('192.168.1.105')}")
print(f"[RUST CORE] IP '10.0.0.1' isolado? {qm.is_quarantined('10.0.0.1')}")
print(f"[RUST CORE] Lista de IPs Isolados: {qm.get_isolated_ips()}")