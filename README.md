# SOC Brute Force Detection - Projeto de Automação e Análise Nível 1

Este projeto simula o fluxo de trabalho real de um **SOC Analyst L1**, desde a detecção de um possível ataque de força bruta em logs SSH até a geração de um relatório de incidente enriquecido com Threat Intelligence.

## 🎯 Objetivo

Automatizar a triagem inicial de alertas de segurança, demonstrando as habilidades essenciais de um analista júnior: análise de logs, correlação, enriquecimento de dados e documentação.

## 🛠️ Habilidades Demonstradas

- **SIEM Mindset**: Busca, filtro e correlação de eventos em logs brutos.
- **Regex Aplicada**: Extração de informações estruturadas (IP, usuário) de logs de texto.
- **Análise de Comportamento**: Identificação de padrões de força bruta (múltiplas falhas em janela de tempo).
- **Threat Intelligence**: Enriquecimento de alertas com dados de reputação de IP (simulado).
- **Triagem de Alertas**: Classificação de Severidade (Crítico/Alto) e decisão de escalonamento.
- **Documentação SOC**: Geração automática de relatório de incidente no formato estruturado.
- **Automação com Python**: Script modular, comentado e pronto para produção.

## 📁 Estrutura do Projeto
... (igual à apresentada no início)

## 🚀 Como Executar

1.  **Clone o repositório:**
    ```bash
    git clone https://github.com/MiguelFernandesdeLima/soc-bruteforce-detection.git
    cd soc-bruteforce-detection
    ```

2.  **Execute o gerador de logs (opcional, se não tiver um `auth.log` real):**
    ```bash
    cd scripts
    python3 generate_logs.py
    ```
    *Isso criará um arquivo `logs/auth.log` com dados simulados, incluindo um padrão de ataque.*

3.  **Execute o detector de força bruta:**
    ```bash
    python3 detect_bruteforce.py
    ```
    *O script analisará o log, imprimirá alertas no terminal e gerará um relatório em `reports/`.*

## 🔍 O que o Script Faz (Fluxo SOC)

1.  **Parsing do Log:** Lê `auth.log`, aplica regex para filtrar apenas eventos "Failed password".
2.  **Correlação:** Agrupa falhas por IP em uma janela de tempo configurável (ex: 5 min).
3.  **Detecção:** Gera um alerta se um IP exceder um limite de tentativas (ex: 10).
4.  **Enriquecimento:** Consulta (simula) uma base de Threat Intelligence para obter reputação do IP.
5.  **Triagem:** Classifica a criticidade com base no usuário visado (admin/root = CRÍTICO) e no score de TI.
6.  **Relatório:** Gera um documento em Markdown com Summary, Detection, Investigation e a **Escalation Decision** (se mantém no L1 ou sobe para o L2).


**Nota para Recrutadores:** Este projeto foi desenvolvido para demonstrar um entendimento prático e metodológico das tarefas de um SOC Nível 1, incluindo a tomada de decisão documentada sobre a escalação de incidentes, uma habilidade crucial no dia a dia.