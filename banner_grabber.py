#!/usr/bin/env python3
import argparse
import socket
import sys

# --- 1. Função Auxiliar de Formatação (Necessária para -p) ---

def formata_lista_int(arg):
    """
    Converte string '80,443,22' em lista de inteiros [80, 443, 22].
    """
    if not arg:
        return []
    try:
        return [int(item.strip()) for item in arg.split(',') if item.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError("Portas devem ser números inteiros separados por vírgula.")

# --- 2. Dicionário de Protocolos Conhecidos ---

PROTOCOLOS_CONHECIDOS = {
    21:   ("FTP",       b"HELP\r\n"),
    22:   ("SSH",       b""),  # Banner automático ao conectar
    23:   ("Telnet",    b"\r\n"),
    25:   ("SMTP",      b"EHLO localhost\r\n"),
    53:   ("DNS",       b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"),
    80:   ("HTTP",      b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    110:  ("POP3",      b"USER root\r\n"),
    143:  ("IMAP",      b"1 CAPABILITY\r\n"),
    443:  ("HTTPS",     b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    993:  ("IMAPS",     b"1 CAPABILITY\r\n"),
    995:  ("POP3S",     b"USER root\r\n"),
    3306: ("MySQL",     b""),  # Banner automático
    5432: ("PostgreSQL",b""),  # Banner automático
    8080: ("HTTP-Alt",  b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    3389: ("RDP",       b""),  # Banner automático
}

def detectar_protocolo(port, host):
    """Retorna (nome_protocolo, comando_para_enviar)"""
    if port in PROTOCOLOS_CONHECIDOS:
        nome, cmd_template = PROTOCOLOS_CONHECIDOS[port]
        if b"{host}" in cmd_template:
            cmd = cmd_template.replace(b"{host}", host.encode())
        else:
            cmd = cmd_template
        return nome, cmd
    else:
        # Fallback: tenta como HTTP
        return "Desconhecido", b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".replace(b"{host}", host.encode())

# --- 3. Função de Parsing de Argumentos ---

def processar_argumentos_terminal():
    parser = argparse.ArgumentParser(
        description='Banner Grabber Avançado com detecção de protocolo.',
        epilog='Use apenas em sistemas autorizados. Ideal para pentest educacional.'
    )

    parser.add_argument('host_ip', type=str, help='IP ou hostname alvo (ex: 192.168.1.1)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo detalhado: mostra banner completo')
    parser.add_argument('-p', '--ports', type=formata_lista_int, default=[80, 443],
                        help='Portas para escanear (ex: 22,80,443). Padrão: 80,443')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Salvar resultados em arquivo')

    return parser.parse_args()

# --- 4. Função Principal de Varredura ---

def scan_ports(host, ports, verbose, output_file=None):
    TIMEOUT = 2.0
    print(f"\nIniciando varredura em {host} ({len(ports)} portas)...\n")

    resultados = []
    abertas = 0

    for port in sorted(ports):
        protocolo, comando = detectar_protocolo(port, host)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)

        status = "FECHADA"
        banner = ""
        linha_resumo = ""

        try:
            s.connect((host, port))
            status = "ABERTA"
            abertas += 1

            # Alguns serviços enviam banner automaticamente
            if protocolo in ["SSH", "MySQL", "PostgreSQL", "RDP"]:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                s.sendall(comando)
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()

            primeira_linha = banner.splitlines()[0][:70] if banner else "(vazio)"
            linha_resumo = f"Porta {port:5} | {protocolo:12} | ABERTA  | {primeira_linha}"

            if verbose:
                print(f"[+] Porta {port} ABERTA - {protocolo}")
                print(f"    [BANNER]:\n{banner}\n" + "-"*50)
            else:
                print(linha_resumo)

            resultados.append(linha_resumo + f"\n    Banner completo: {banner}")

        except socket.timeout:
            status = "FILTRADA"
            if verbose:
                print(f"[-] Porta {port:5} | {protocolo:12} | FILTRADA (timeout)")

        except ConnectionRefusedError:
            status = "FECHADA"
            if verbose:
                print(f"[-] Porta {port:5} | {protocolo:12} | FECHADA")

        except Exception as e:
            status = "ERRO"
            if verbose:
                print(f"[!] Porta {port:5} | {protocolo:12} | ERRO: {e}")

        finally:
            s.close()

    # --- Salvar em arquivo ---
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"Banner Grabber - Resultados para {host}\n")
                f.write(f"Data: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Portas escaneadas: {len(ports)} | Portas abertas: {abertas}\n")
                f.write("="*80 + "\n\n")
                for r in resultados:
                    f.write(r + "\n\n")
            print(f"\nResultados salvos em: {output_file}")
        except Exception as e:
            print(f"\nErro ao salvar arquivo: {e}")

    print(f"\nVarredura concluída. {abertas} porta(s) aberta(s).")

# --- 5. Bloco Principal ---

def main():
    args = processar_argumentos_terminal()
    host = args.host_ip
    ports = args.ports
    verbose = args.verbose
    output = args.output

    if not ports:
        print("Nenhuma porta especificada. Usando padrão: 80,443")
        ports = [80, 443]

    try:
        socket.inet_aton(host)  # Valida IP
    except socket.error:
        try:
            socket.gethostbyname(host)  # Valida hostname
        except socket.gaierror:
            print("Erro: Host inválido ou não resolvível.")
            sys.exit(1)

    scan_ports(host, ports, verbose, output)

if __name__ == "__main__":
    main()