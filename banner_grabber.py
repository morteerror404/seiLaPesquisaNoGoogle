import argparse
import socket
import sys

# --- 1. Função Auxiliar de Formatação (Necessária para -p) ---

def formata_lista_int(arg):
    """
    Função type customizada: Converte uma string 'p1,p2,p3' em uma lista de INTEIROS [p1, p2, p3].
    """
    if not arg:
        # Se o argumento não for fornecido e não houver um 'default', retorna lista vazia.
        return []
    try:
        # Remove espaços e converte para inteiro
        return [int(item.strip()) for item in arg.split(',')]
    except ValueError:
        # ArgumentTypeError é o padrão para erros de tipo no argparse
        raise argparse.ArgumentTypeError("Portas devem ser números inteiros separados por vírgula.")

# --- 2. Função de Parsing de Argumentos ---

def processar_argumentos_terminal():
    """
    Configura e analisa os argumentos de linha de comando.
    """
    parser = argparse.ArgumentParser(
        description='Ferramenta de varredura de portas com modo detalhado.',
        # Eu ajustei o 'epilog' para algo mais neutro e focado em aprendizado.
        epilog='Use a ferramenta para propósitos educacionais e em sistemas autorizados.'
    )

    # Argumento Posicional (Host/IP - Obrigatório)
    # Nota: Mudei de '-path' para um argumento posicional simples, que é o padrão para o IP.
    parser.add_argument(
        'host_ip',
        type=str,
        help='O endereço IP ou hostname alvo (Ex: 192.168.1.1).'
    )

    # Argumento -v / --verbose (Flag)
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Ativa o modo detalhado. Mostra o status e o banner de CADA porta.'
    )

    # Argumento -p / --ports (Lista)
    parser.add_argument(
        '-p', '--ports',
        type=formata_lista_int, # Usa a função customizada
        default=[80, 443],      # Portas padrão se a flag for omitida
        help='Lista de portas a serem verificadas, separadas por vírgula (Ex: 22,80,443). Padrão: 80,443.'
    )

    # Argumento -u / --user (Usuário)
    parser.add_argument(
        '-u', '--user',
        type=str,
        default='root',
        help='Especifica usuário para tentativa de conexão. (Ex. ssh root@192.168.1.1).'
        )

    # Argumento -passwd / --password
    parser.add_argument(
    '-passwd', '--password',
    type=str,
    default='toor',
    help='Especifica senha para tentativa de conexão.'
    )

    # Argumento -o / --output (Saída para arquivo)
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Especifica o nome do arquivo para salvar a saída.'
    )

    # Analisa e retorna os argumentos
    return parser.parse_args()

# --- 3. Função de Varredura de Portas (Lógica Principal) ---

def scan_ports(host, ports, verbose):
    """
    Executa a varredura de portas e a lógica de captura de banner.
    """
    TIMEOUT = 1.0 # Timeout de 1 segundo para a conexão

    print(f"\nIniciando varredura em {host} ({len(ports)} portas)...")

    # Variável de controle para o modo não-verbose
    first_banner_shown = False

    for port in ports:
        # Cria um novo socket a cada iteração
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)

        try:
            s.connect((host, port))

            # --- Tentar Capturar o Banner ---
            # Envia um HTTP GET simples para provocar a resposta (banner)
            s.sendall(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')

            banner = s.recv(1024).decode(errors='ignore').strip()

            if verbose:
                print(f"[+] Porta {port} ABERTA")
                print(f"    [BANNER]: {banner}\n{'-'*20}")

            elif not first_banner_shown:
                # MODO SIMPLES: Mostra o primeiro banner encontrado e para
                print(f"[+] Porta {port} ABERTA. Banner capturado:")
                print(f"    {banner}\n{'-'*20}")
                first_banner_shown = True # Marca que já foi mostrado

        except socket.timeout:
            if verbose:
                print(f"[-] Porta {port} FILTRADA (Tempo Esgotado)")

        except ConnectionRefusedError:
            if verbose:
                print(f"[-] Porta {port} FECHADA (Conexão Recusada)")

        except Exception as e:
            if verbose:
                print(f"[-] Porta {port} - ERRO: {e}")

        finally:
            s.close()

    print("\nVarredura concluída.")

# --- 4. Bloco Principal de Execução ---

def main():
    # 1. Processa os argumentos primeiro
    args = processar_argumentos_terminal()

    host = args.host_ip
    ports = args.ports
    verbose = args.verbose

    # 2. Executa a varredura
    scan_ports(host, ports, verbose)

main()
