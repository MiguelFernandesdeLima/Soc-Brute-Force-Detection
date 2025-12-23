#!/usr/bin/env python3
# ============================================
# SCRIPT: detect_bruteforce.py
# RESPONSABILIDADE: Analisar logs de autenticação, detectar padrões de força bruta e gerar alertas.
# NIVEL: SOC-L1/L2 (Análise, correlação, automação básica, tomada de decisão)
# ============================================

import re
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import subprocess
import sys
import os

# --------------------------------------------
# CONFIGURAÇÕES GLOBAIS (Fácil ajuste para o analista)
# --------------------------------------------
THRESHOLD_FAILED_ATTEMPTS = 10  # Número de falhas para gerar alerta
TIME_WINDOW_MINUTES = 5         # Janela de tempo para análise (minutos)
CRITICAL_USERS = {"admin", "root"}  # Usuários que elevam a criticidade

def parse_auth_log(log_file_path):
    """
    Lê e analisa o arquivo de log de autenticação.

    Args:
        log_file_path (str): Caminho para o arquivo de log.

    Returns:
        list: Lista de dicionários, cada um representando uma tentativa de login falha.
              Formato: {'timestamp': datetime, 'user': str, 'ip': str, 'raw_line': str}

    Lógica:
        1. Abre o arquivo linha a linha.
        2. Usa expressão regular (regex) para extrair dados apenas de eventos 'Failed password'.
        3. Converte o timestamp para um objeto datetime para análise temporal.
    """
    failed_attempts = []
    # Regex para capturar timestamp, usuário e IP de linhas de falha
    # Exemplo: "Dec 23 10:15:22 server sshd[1234]: Failed password for admin from 45.83.19.77 port 55214 ssh2"
    pattern = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?Failed password for (?P<user>\w+).*?from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    current_year = datetime.now().year  # Assume logs do ano atual

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                # Ignora linhas de comentário ou vazias
                if line.startswith('#') or not line.strip():
                    continue

                match = pattern.search(line)
                if match:
                    # Constrói uma string de data completa e converte para objeto datetime
                    date_str = f"{match.group('month')} {match.group('day')} {current_year} {match.group('time')}"
                    try:
                        timestamp = datetime.strptime(date_str, "%b %d %Y %H:%M:%S")
                    except ValueError:
                        # Se falhar (ex: 29 de fev em ano não bissexto), usa a data atual
                        timestamp = datetime.now()

                    failed_attempts.append({
                        'timestamp': timestamp,
                        'user': match.group('user'),
                        'ip': match.group('ip'),
                        'raw_line': line.strip()
                    })
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de log não encontrado: {log_file_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] {len(failed_attempts)} tentativas de login falhas analisadas.")
    return failed_attempts

def detect_bruteforce_attempts(failed_attempts, time_window_minutes, threshold):
    """
    Agrupa as falhas por IP e identifica potenciais ataques dentro de uma janela de tempo.

    Args:
        failed_attempts (list): Lista de dicionários com tentativas falhas.
        time_window_minutes (int): Janela de tempo para agrupar eventos.
        threshold (int): Limite de falhas para considerar como ataque.

    Returns:
        dict: Dicionário onde a chave é o IP e o valor é um dict com detalhes do alerta.

    Lógica:
        1. Ordena as tentativas por tempo.
        2. Para cada IP, agrupa tentativas que estão próximas no tempo (janela deslizante).
        3. Se o número de tentativas em uma janela exceder o limite, gera um alerta.
    """
    # Ordena as tentativas por timestamp
    sorted_attempts = sorted(failed_attempts, key=lambda x: x['timestamp'])
    ip_alerts = {}

    for attempt in sorted_attempts:
        ip = attempt['ip']
        current_time = attempt['timestamp']

        # Inicializa a lista de alertas para este IP se for a primeira vez
        if ip not in ip_alerts:
            ip_alerts[ip] = {
                'attempts': [],
                'users': set(),
                'first_seen': current_time,
                'last_seen': current_time
            }

        # Adiciona a tentativa atual à lista do IP
        ip_alerts[ip]['attempts'].append(attempt)
        ip_alerts[ip]['users'].add(attempt['user'])
        ip_alerts[ip]['last_seen'] = current_time

        # Define o limite de tempo para a janela
        time_limit = current_time - timedelta(minutes=time_window_minutes)

        # Remove tentativas que estão fora da janela de tempo atual
        ip_alerts[ip]['attempts'] = [a for a in ip_alerts[ip]['attempts'] if a['timestamp'] > time_limit]

    # Analisa cada IP para verificar se atingiu o limite de falhas
    final_alerts = {}
    for ip, data in ip_alerts.items():
        recent_attempts = data['attempts']
        if len(recent_attempts) >= threshold:
            # Coleta os usuários visados e o período do ataque
            target_users = list(data['users'])
            first_seen = min(a['timestamp'] for a in recent_attempts)
            last_seen = max(a['timestamp'] for a in recent_attempts)
            duration = last_seen - first_seen

            # Determina a criticidade com base nos usuários visados
            is_critical = any(user in CRITICAL_USERS for user in target_users)
            severity = "CRÍTICO" if is_critical else "ALTO"

            final_alerts[ip] = {
                'ip': ip,
                'attempt_count': len(recent_attempts),
                'target_users': target_users,
                'first_attempt': first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                'last_attempt': last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                'duration_seconds': duration.total_seconds(),
                'severity': severity,
                'sample_log': recent_attempts[0]['raw_line']  # Pega uma linha de log exemplo
            }
            print(f"[!] ALERTA: IP {ip} -> {len(recent_attempts)} falhas em <= {time_window_minutes} min. Severidade: {severity}")

    return final_alerts

def enrich_with_threat_intelligence(alert):
    """
    Simula uma consulta a uma API de Threat Intelligence como o AbuseIPDB.

    Args:
        alert (dict): Dicionário contendo os dados do alerta de um IP.

    Returns:
        dict: O mesmo dicionário enriquecido com informações de reputação.

    Lógica SOC L1:
        1. Em um ambiente real, aqui seria feita uma chamada de API REST.
        2. Para fins didáticos, simula uma consulta com base no prefixo do IP.
        3. Mostra como integrar inteligência externa na triagem.
    """
    ip = alert['ip']
    # Simulação simples: IPs começando com "45.83." são considerados maliciosos conhecidos
    if ip.startswith("45.83."):
        alert['ti_abuse_score'] = 95  # Score de 0-100
        alert['ti_category'] = "Brute Force, SSH Attacks"
        alert['ti_reported_times'] = 150
        alert['ti_veredict'] = "MALICIOSO CONHECIDO"
    else:
        alert['ti_abuse_score'] = 5
        alert['ti_category'] = "Nenhuma ameaça conhecida"
        alert['ti_reported_times'] = 0
        alert['ti_veredict'] = "Limpo / Não listado"

    print(f"   [+] Threat Intel para {ip}: Score {alert['ti_abuse_score']}/100 - {alert['ti_veredict']}")
    return alert

def generate_incident_report(alerts, report_filename):
    """
    Gera um relatório de incidente no formato Markdown, pronto para o time SOC.

    Args:
        alerts (dict): Dicionário com todos os alertas identificados.
        report_filename (str): Caminho para salvar o relatório.

    Lógica:
        Segue o formato estruturado de relatório de incidente (Summary, Detection, etc.),
        exatamente como solicitado.
    """
    if not alerts:
        report_content = "# Relatório de Análise - SOC\n\nNenhum alerta de força bruta detectado no período analisado.\n"
    else:
        report_content = f"# Relatório de Incidente SOC - Detecção de Força Bruta\n"
        report_content += f"**Data da Geração:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_content += f"**Total de Alertas:** {len(alerts)}\n\n"

        for ip, details in alerts.items():
            report_content += f"## Alerta: {ip}\n"
            report_content += f"### 1. Summary\n"
            report_content += f"- **IP Origem:** {details['ip']}\n"
            report_content += f"- **Severidade:** **{details['severity']}**\n"
            report_content += f"- **Tentativas Falhas:** {details['attempt_count']}\n"
            report_content += f"- **Usuários Visados:** {', '.join(details['target_users'])}\n"
            report_content += f"- **Período do Ataque:** {details['first_attempt']} até {details['last_attempt']}\n"
            report_content += f"- **Duração:** {details['duration_seconds']:.0f} segundos\n\n"

            report_content += f"### 2. Detection\n"
            report_content += f"- **Método de Detecção:** Análise de log `auth.log` para padrões de falha consecutiva.\n"
            report_content += f"- **Limite (Threshold):** {THRESHOLD_FAILED_ATTEMPTS} falhas em {TIME_WINDOW_MINUTES} minutos.\n"
            report_content += f"- **Linha de Log de Exemplo:** `{details['sample_log']}`\n\n"

            report_content += f"### 3. Investigation & Threat Intelligence\n"
            report_content += f"- **Abuse Score (Simulado):** {details.get('ti_abuse_score', 'N/A')}/100\n"
            report_content += f"- **Categoria:** {details.get('ti_category', 'N/A')}\n"
            report_content += f"- **Veredito TI:** {details.get('ti_veredict', 'N/A')}\n\n"

            report_content += f"### 4. Response & Escalation Decision\n"
            if details['severity'] == "CRÍTICO" or details.get('ti_abuse_score', 0) > 80:
                decision = "**ESCALAR IMEDIATAMENTE para SOC Nível 2.**\n- Motivo: Ataque contra usuário privilegiado e/ou IP com alta reputação maliciosa.\n- Ação Imediata Sugerida: Bloqueio temporário do IP no firewall (iptables/NSG)."
            else:
                decision = "**MANTER EM MONITORAMENTO (Nível 1).**\n- Motivo: Ataque de baixa sofisticação contra usuário não-privilegiado. Pode ser teste automatizado.\n- Ação Sugerida: Adicionar à watchlist e verificar se há novas tentativas nas próximas horas."
            report_content += f"{decision}\n\n"
            report_content += "---\n\n"

    # Salva o relatório no diretório 'reports/'
    report_path = f"../reports/{report_filename}"
    with open(report_path, 'w') as f:
        f.write(report_content)
    print(f"[+] Relatório de incidente gerado: {report_path}")

def main():
    """Função principal que orquestra todo o fluxo de análise SOC L1."""
    print("\n" + "="*70)
    print("SOC BRUTE FORCE DETECTION - SCRIPT DE TRIAGEM NÍVEL 1")
    print("="*70)

    # 1. Define o caminho do arquivo de log
    log_file = "../logs/auth.log"

    # 2. Parse do Log (Fase de Coleta e Filtro)
    print(f"\n[FASE 1] Analisando arquivo de log: {log_file}")
    failed_attempts = parse_auth_log(log_file)

    if not failed_attempts:
        print("[-] Nenhuma tentativa falha encontrada. Análise encerrada.")
        sys.exit(0)

    # 3. Detecção de Padrões (Fase de Correlação)
    print(f"\n[FASE 2] Detectando padrões de força bruta...")
    print(f"        (Threshold: {THRESHOLD_FAILED_ATTEMPTS} falhas em {TIME_WINDOW_MINUTES} minutos)")
    alerts = detect_bruteforce_attempts(failed_attempts, TIME_WINDOW_MINUTES, THRESHOLD_FAILED_ATTEMPTS)

    if not alerts:
        print("[-] Nenhum IP atingiu o threshold para alerta.")
        # Gera um relatório mesmo sem alertas, documentando a análise
        generate_incident_report({}, f"incident_report_{datetime.now().strftime('%Y-%m-%d_T%H-%M-%S')}.md")
        sys.exit(0)

    # 4. Enriquecimento com Threat Intelligence (Fase de Investigação)
    print(f"\n[FASE 3] Enriquecendo alertas com Threat Intelligence (simulado)...")
    enriched_alerts = {}
    for ip, alert in alerts.items():
        enriched_alerts[ip] = enrich_with_threat_intelligence(alert)

    # 5. Geração do Relatório (Fase de Documentação e Decisão)
    print(f"\n[FASE 4] Gerando relatório de incidente...")
    report_filename = f"incident_report_{datetime.now().strftime('%Y-%m-%d_T%H-%M-%S')}.md"
    generate_incident_report(enriched_alerts, report_filename)

    print("\n" + "="*70)
    print("ANÁLISE CONCLUÍDA. Verifique o diretório 'reports/' para o relatório final.")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()