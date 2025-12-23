# Relatório de Incidente SOC - Detecção de Força Bruta
**Data da Geração:** 2025-12-23 10:30:00
**Total de Alertas:** 1

## Alerta: 45.83.19.77
### 1. Summary
- **IP Origem:** 45.83.19.77
- **Severidade:** **CRÍTICO**
- **Tentativas Falhas:** 12
- **Usuários Visados:** admin
- **Período do Ataque:** 2025-12-23 09:45:11 até 2025-12-23 09:48:33
- **Duração:** 202 segundos

### 2. Detection
- **Método de Detecção:** Análise de log `auth.log` para padrões de falha consecutiva.
- **Limite (Threshold):** 10 falhas em 5 minutos.
- **Linha de Log de Exemplo:** `Dec 23 09:45:11 server sshd[5678]: Failed password for admin from 45.83.19.77 port 55214 ssh2`

### 3. Investigation & Threat Intelligence
- **Abuse Score (Simulado):** 95/100
- **Categoria:** Brute Force, SSH Attacks
- **Veredito TI:** MALICIOSO CONHECIDO

### 4. Response & Escalation Decision
**ESCALAR IMEDIATAMENTE para SOC Nível 2.**
- Motivo: Ataque contra usuário privilegiado e/ou IP com alta reputação maliciosa.
- Ação Imediata Sugerida: Bloqueio temporário do IP no firewall (iptables/NSG).
---