# Ethical Hacking Scanner CLI

### Ferramenta de Hacking Ético para Escanear Vulnerabilidades em Websites

Esta ferramenta de linha de comando (CLI) realiza uma análise automatizada de websites em busca de vulnerabilidades de segurança, gerando relatórios detalhados. As vulnerabilidades são classificadas de acordo com sua gravidade, com base em referências como o **CVE (Common Vulnerabilities and Exposures)**.

## Funcionalidades

- **SQL Injection**: Testa se o site é vulnerável a injeções SQL.
- **Cross-Site Scripting (XSS)**: Verifica se há vulnerabilidades de XSS.
- **Cabeçalhos inseguros**: Verifica a ausência de cabeçalhos de segurança como `Content-Security-Policy`, `X-Frame-Options` e outros.
- **SSL/TLS inválido**: Verifica a validade do certificado SSL/TLS.
- **Portas abertas**: Escaneia portas abertas no servidor (1-1024).
- **Arquivos e diretórios expostos**: Verifica se arquivos sensíveis, como `.env` ou diretórios como `.git`, estão acessíveis publicamente.
- **Força bruta de login**: Realiza tentativas de login com uma wordlist.
- **Descoberta de subdomínios**: Tenta encontrar subdomínios de um domínio específico.
- **Open Redirect**: Verifica se há redirecionamentos inseguros que possam ser explorados.
- **Relatório detalhado**: Gera um relatório em `report.txt`, incluindo a gravidade da vulnerabilidade (baixa, média, alta, crítica).
- **Timeout ajustável**: Limite de tempo para cada requisição HTTP.
- **Escolha de vulnerabilidades**: Escaneie vulnerabilidades específicas (ex: apenas SQL Injection).

## Instalação
git clone https://github.com/AngeloHale/hacker-scanner.git
### Requisitos

- **Python 3.9**
- Bibliotecas listadas em `requirements.txt`

### Instalação das dependências

Execute o comando abaixo para instalar as dependências necessárias:
```pip3 install -r requirements.txt
```

## Como usar

### Escaneamento básico

Para escanear um website e verificar todas as vulnerabilidades, execute o seguinte comando no terminal:

python3 scanner.py https://exemplo.com
```

### Escanear vulnerabilidades específicas

Se você quiser escanear apenas certas vulnerabilidades (por exemplo, SQL Injection e XSS), use as flags apropriadas:

python3 scanner.py https://exemplo.com --scan sql_injection xss
```

### Verificar força bruta

Para realizar ataques de força bruta em um formulário de login, forneça a URL de login, o nome de usuário e a wordlist:

python3 scanner.py https://exemplo.com --brute-force https://exemplo.com/login admin wordlist.txt
```

### Verificar subdomínios

Para escanear subdomínios, forneça um arquivo de texto com a lista de subdomínios:

python3 scanner.py https://exemplo.com --subdomains subdomains.txt
```

### Timeout personalizado

Se o website demorar para responder, você pode definir um timeout (em segundos):

python3 scanner.py https://exemplo.com --timeout 10
```

### Exemplo de uso completo

```python3 scanner.py https://exemplo.com --scan sql_injection xss --brute-force https://exemplo.com/login admin wordlist.txt --subdomains subdomains.txt --timeout 10
```

## Relatório gerado

O relatório `report.txt` incluirá:

1. **Vulnerabilidades encontradas**
2. **Classificação da gravidade** (baseada no CVE):
   - **Baixa**
   - **Média**
   - **Alta**
   - **Crítica**
3. **Recomendações de mitigação**

---

## Segurança e Ética

**IMPORTANTE**: Use esta ferramenta apenas em websites que você tenha autorização para testar. Testes sem permissão podem ser ilegais. Sempre pratique hacking ético.

### Contribuições

Se você deseja contribuir com o projeto, sinta-se à vontade para abrir um Pull Request ou sugerir melhorias!

---
