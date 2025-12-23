#!/usr/bin/env python3
# ============================================
# SCRIPT: generate_logs.py
# RESPONSABILIDADE: Gerar um arquivo de log de autenticação (auth.log) simulado e realista
# ============================================

import random
import time
from datetime import datetime, timedelta

def generate_auth_log(filename="auth.log", num_entries=200):

    """
    Gera um arquivo de log de autenticação SSH simulando tráfego normal e ataques.

    Args:
        filename (str): Nome do arquivo de log a ser criado.
        num_entries (int): Número total de entradas de log a gerar.

    Lógica:
        1. Define IPs e usuários para cenários normais e maliciosos.
        2. Para cada entrada, decide aleatoriamente o tipo de evento.
        3. Formata a linha de log no padrão syslog.
        4. Insere um padrão de ataque de força bruta claro para um IP específico.
    """

    # IPs e usuarios para simular trafego diversificado 
    normal_ips = ["192.168.1.10", "192.268.1.55", "10.0.0.101", "172.16.254.3"]
    malicious_ip = "45.83.19.77" # IP do atacante simulado
    users = ["admin", "root", "user1", "ubuntu", "ssh-user", "devops"]
    protocols = ["ssh2", "ssh1"]

    # Cabeçalho do arquivo
    log_header = f"# Arquivo de log de autenticação simulado - Gerado em {datetime.now()}\n"
    log_header += "# Formato: dta Hora Serviço[PID]: Mensagem\n\n"

    log_entries = [log_header]
    base_time = datetime.now() - timedelta(hours=1) # Logs da ultima hora

    for i in range(num_entries):
        # A cada ~15 entradas, força a geraçao de uma falha do IP malicioso oara cirar o padrão de ataque
        if i % 15 == 5:
            ip = malicious_ip
            user = "admin"
            status = "Failed"
        else:
            ip = random.choice(normal_ips)
            user = random.choice(users)
            # A maioria dos logins de IPs normais é bem-sucedida, mas com algumas falhas esporádicas
            status = random.choices(["Accepted", "Failed"], weights=[85, 15]) [0]

        # Incrementa o tempo para cada entrada
        entry_time = base_time + timedelta(seconds=random.randint(1, 30))
        timestamp = entry_time.strftime("%b %d %H:%M:%S")
        pid = random.randint(1000, 9999)
        port = random.randint(50000, 60000)
        protocol = random.choice(protocols)

    # Formata a linha de log no padrão syslog do SSH
    if status == "Failed":
        log_line = f"{timestamp} server sshd [{pid}]: Failed for {user} from {ip} port {port} {protocol}\n"
    else:
        log_line = f"{timestamp} server sshd [{pid}]: Accepted password for {user} from {ip} port {port} {protocol}\n"

        log_entries.append(log_line)


    # Escreve todas as entradas no arquivo 
    with open(f"../logs/{filename}", "w") as f:
        f.writelines(log_entries)

    print(f"[+] Arquivo de log '{filename}' gerado com sucesso em 'logs/' com {num_entries} entradas.")
    print(f"[+] Padrão de força bruta simulado para o IP: {malicious_ip} -> 'admin'")

if __name__ == "__main__":
    generate_auth_log