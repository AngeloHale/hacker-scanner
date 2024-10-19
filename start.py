import requests
from bs4 import BeautifulSoup
import socket
import ssl
import argparse

class EthicalHackerTool:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    # Função para verificar se o site tem SQL Injection
    def check_sql_injection(self):
        test_url = self.target_url + "'"
        response = self.session.get(test_url)
        error_msgs = ["you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows", "pg_query", "sql syntax"]
        for error in error_msgs:
            if error.lower() in response.text.lower():
                print("[!] Possível vulnerabilidade de SQL Injection encontrada!")
                return True
        print("[+] Sem vulnerabilidade de SQL Injection.")
        return False

    # Função para verificar vulnerabilidades de XSS
    def check_xss(self):
        payload = "<script>alert('xss');</script>"
        response = self.session.get(self.target_url)
        if payload in response.text:
            print("[!] Vulnerabilidade XSS encontrada!")
            return True
        print("[+] Sem vulnerabilidade XSS.")
        return False

    # Função para verificar cabeçalhos de segurança
    def check_insecure_headers(self):
        response = self.session.get(self.target_url)
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]
        missing_headers = []
        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)
        if missing_headers:
            print(f"[!] Cabeçalhos de segurança ausentes: {', '.join(missing_headers)}")
        else:
            print("[+] Todos os cabeçalhos de segurança estão presentes.")
        return missing_headers

    # Função para verificar SSL/TLS
    def check_ssl_tls(self):
        try:
            hostname = self.target_url.replace('https://', '').replace('http://', '').split('/')[0]
            port = 443
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    print(f"[+] Certificado SSL/TLS válido para {hostname}")
                    return cert
        except ssl.SSLError as e:
            print(f"[!] Problema com o certificado SSL/TLS: {e}")
            return None

    # Função para escanear portas abertas
    def check_open_ports(self):
        hostname = self.target_url.replace('https://', '').replace('http://', '').split('/')[0]
        open_ports = []
        for port in range(1, 1025):  # Escaneia portas comuns (1-1024)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        if open_ports:
            print(f"[!] Portas abertas encontradas: {open_ports}")
        else:
            print("[+] Nenhuma porta aberta encontrada.")
        return open_ports

    # Verificação de arquivos e diretórios expostos
    def check_exposed_files(self):
        sensitive_files = [".git/", ".env", "backup.zip", "config.php", "admin/"]
        exposed_files = []
        for file in sensitive_files:
            url = self.target_url + file
            response = self.session.get(url)
            if response.status_code == 200:
                exposed_files.append(file)
        if exposed_files:
            print(f"[!] Arquivos/Diretórios expostos encontrados: {exposed_files}")
        else:
            print("[+] Nenhum arquivo ou diretório sensível exposto encontrado.")
        return exposed_files

    # Verificação básica de autenticação
    def check_brute_force(self, login_url, username, wordlist):
        for password in wordlist:
            response = self.session.post(login_url, data={'username': username, 'password': password})
            if "login failed" not in response.text.lower():
                print(f"[!] Senha válida encontrada: {password}")
                return password
        print("[+] Nenhuma senha válida encontrada com a wordlist fornecida.")
        return None

    # Verificação de subdomínios (básica)
    def check_subdomains(self, subdomains):
        discovered_subdomains = []
        base_domain = self.target_url.replace('https://', '').replace('http://', '').split('/')[0]
        for sub in subdomains:
            url = f"http://{sub}.{base_domain}"
            try:
                response = self.session.get(url)
                if response.status_code == 200:
                    discovered_subdomains.append(url)
            except requests.ConnectionError:
                pass
        if discovered_subdomains:
            print(f"[!] Subdomínios encontrados: {discovered_subdomains}")
        else:
            print("[+] Nenhum subdomínio encontrado.")
        return discovered_subdomains

    # Geração de relatórios detalhados
    def generate_report(self, vulnerabilities):
        report = "Relatório de Vulnerabilidades:\n"
        for vuln, details in vulnerabilities.items():
            report += f"- {vuln}: {details}\n"
        with open("report.txt", "w") as f:
            f.write(report)
        print("[+] Relatório gerado: report.txt")

    # Função para realizar uma varredura completa
    def scan(self):
        vulnerabilities = {}
        print(f"--- Iniciando varredura em {self.target_url} ---")
        
        if self.check_sql_injection():
            vulnerabilities["SQL Injection"] = "Possível vulnerabilidade detectada."
        
        if self.check_xss():
            vulnerabilities["XSS"] = "Possível vulnerabilidade de XSS detectada."
        
        missing_headers = self.check_insecure_headers()
        if missing_headers:
            vulnerabilities["Insecure Headers"] = f"Cabeçalhos ausentes: {', '.join(missing_headers)}"
        
        if not self.check_ssl_tls():
            vulnerabilities["SSL/TLS"] = "Problema no certificado SSL/TLS."
        
        open_ports = self.check_open_ports()
        if open_ports:
            vulnerabilities["Open Ports"] = f"Portas abertas encontradas: {open_ports}"

        exposed_files = self.check_exposed_files()
        if exposed_files:
            vulnerabilities["Exposed Files"] = f"Arquivos/diretórios sensíveis expostos: {exposed_files}"

        self.generate_report(vulnerabilities)
        print("--- Varredura concluída ---")


# Função principal para o CLI
def main():
    parser = argparse.ArgumentParser(description="Ferramenta de Hacking Ético para escanear vulnerabilidades em websites")
    
    # Argumentos da linha de comando
    parser.add_argument("url", help="URL do website alvo")
    parser.add_argument("--brute-force", nargs=3, metavar=("login_url", "username", "wordlist"), help="Executa ataque de força bruta no site")
    parser.add_argument("--subdomains", metavar="subdomains_file", help="Arquivo de texto contendo uma lista de subdomínios a serem testados")
    
    args = parser.parse_args()
    
    # Instancia a ferramenta com a URL fornecida
    scanner = EthicalHackerTool(args.url)

    # Executa a varredura básica
    scanner.scan()

    # Força bruta, se solicitada
    if args.brute_force:
        login_url, username, wordlist_file = args.brute_force
        with open(wordlist_file, "r") as file:
            wordlist = [line.strip() for line in file]
        scanner.check_brute_force(login_url, username, wordlist)

    # Teste de subdomínios, se solicitado
    if args.subdomains:
        with open(args.subdomains, "r") as file:
            subdomains = [line.strip() for line in file]
        scanner.check_subdomains(subdomains)

if __name__ == "__main__":
    main()
