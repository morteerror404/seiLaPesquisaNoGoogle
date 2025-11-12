#!/bin/bash
# Port-Knocking Scanner - Corrigido e Otimizado
# Autor: Daniel Domingues + 0xMorte 
# Uso: ./scanner.sh 192.168.1.10 192.168.1.20

# ===============================================
# CONFIGURAÇÕES
# ===============================================
KNOCK_PORTS=(13 37 30000 3000 1337)
TARGET_PORT=1337
TIMEOUT=3
MAX_JOBS=50
OUTPUT_FILE="hosts.txt"
PAGE_DIR="extracted_pages"

# ===============================================
# CORES
# ===============================================
RED='\033[31;1m'
GREEN='\033[32;1m'
YELLOW='\033[33;1m'
BLUE='\033[34;1m'
WHITE='\033[37;1m'
NC='\033[m'

# ===============================================
# VERIFICA DEPENDÊNCIAS
# ===============================================
check_deps() {
    local deps=("hping3" "nc")
    local prefix=""
    (( $(id -u) != 0 )) && prefix="sudo "

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            echo -e "${RED}[-] ERRO: '$dep' não encontrado.${NC}"
            echo -e "${WHITE}    Instale com:${YELLOW}"
            if command -v apt &>/dev/null; then
                echo "    ${prefix}apt install -y $dep"
            elif command -v dnf &>/dev/null; then
                echo "    ${prefix}dnf install -y $dep"
            elif command -v pacman &>/dev/null; then
                echo "    ${prefix}pacman -S --noconfirm $dep"
            else
                echo "    (Instale manualmente)"
            fi
            exit 1
        fi
    done
}

# ===============================================
# VALIDA IP
# ===============================================
valid_ip() {
    local ip=$1
    local stat=1

    if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        [[ ${BASH_REMATCH[1]} -le 255 && ${BASH_REMATCH[2]} -le 255 &&
           ${BASH_REMATCH[3]} -le 255 && ${BASH_REMATCH[4]} -le 255 ]] && stat=0
    fi
    return $stat
}

# ===============================================
# DIVISÓRIA DINÂMICA
# ===============================================
divisoria() {
    printf "${WHITE}%*s${NC}\n" "$(tput cols)" "" | tr ' ' '='
}

# ===============================================
# PORT KNOCKING + DETECÇÃO
# ===============================================
knock_and_check() {
    local ip=$1
    local rede=$2
    local host=$3

    # Sequência de knock
    for port in "${KNOCK_PORTS[@]}"; do
        timeout $TIMEOUT hping3 -S -p "$port" -c 1 "$ip" &>/dev/null || return 1
    done

    # Verifica se porta 1337 abriu (SYN-ACK)
    if timeout $TIMEOUT hping3 -S -p "$TARGET_PORT" -c 1 "$ip" 2>/dev/null | grep -q "flags=SA"; then
        echo "$host" >> "$OUTPUT_FILE"
        return 0
    fi
    return 1
}

# ===============================================
# EXTRAI PÁGINA WEB
# ===============================================
extract_page() {
    local ip=$1
    local timeout_cmd="timeout 5"

    mkdir -p "$PAGE_DIR"
    local outfile="$PAGE_DIR/${ip//./_}.html"

    echo -e "${GREEN}[+] Extraindo página de $ip...${NC}"
    if printf "GET / HTTP/1.0\r\n\r\n" | $timeout_cmd nc -w 5 "$ip" "$TARGET_PORT" > "$outfile" 2>/dev/null; then
        echo -e "${YELLOW}    Página salva em: $outfile${NC}"
        head -n 20 "$outfile" | sed 's/^/    | /'
    else
        echo -e "${RED}    Falha ao extrair página.${NC}"
    fi
}

# ===============================================
# MAIN
# ===============================================
main() {
    clear
    check_deps
    divisoria

    local cols=$(tput cols)
    local title="SCRIPT PORT-KNOCKING SCANNER"
    printf "${BLUE}%*s${NC}\n" $(( (${#title} + cols) / 2 )) "$title"
    divisoria

    [[ -z "$1" || -z "$2" ]] && {
        echo -e "${RED}[-] Uso: $0 <IP_INICIAL> <IP_FINAL>${NC}"
        echo -e "    Ex: $0 192.168.1.1 192.168.1.254"
        exit 1
    }

    local ip1=$1 ip2=$2
    valid_ip "$ip1" || { echo -e "${RED}[-] IP inicial inválido: $ip1${NC}"; exit 1; }
    valid_ip "$ip2" || { echo -e "${RED}[-] IP final inválido: $ip2${NC}"; exit 1; }

    local rede1=$(echo "$ip1" | cut -d. -f1-3)
    local rede2=$(echo "$ip2" | cut -d. -f1-3)
    [[ "$rede1" != "$rede2" ]] && {
        echo -e "${RED}[-] IPs devem estar na mesma /24${NC}"
        exit 1
    }

    local inicio=$(echo "$ip1" | cut -d. -f4)
    local final=$(echo "$ip2" | cut -d. -f4)
    [[ $inicio -gt $final ]] && { echo -e "${RED}[-] IP inicial > final${NC}"; exit 1; }

    local rede=$rede1
    local total=$((final - inicio + 1))
    local encontrados=0
    local cont=0

    > "$OUTPUT_FILE"

    echo -e "${WHITE}[+] Escaneando $total hosts: $ip1 → $ip2${NC}"
    echo -e "${WHITE}[+] Sequência de knock: ${KNOCK_PORTS[*]}${NC}\n"

    # Controle de jobs paralelos
    for i in $(seq "$inicio" "$final"); do
        ip="${rede}.${i}"
        ((cont++))

        # Aguarda se atingir limite de jobs
        while (( $(jobs -r | wc -l) >= MAX_JOBS )); do
            sleep 0.1
        done

        knock_and_check "$ip" "$rede" "$i" && ((encontrados++)) &
        printf "${GREEN}.${NC}"
    done

    wait
    echo -e "\n"

    divisoria

    if [[ $encontrados -gt 0 ]]; then
        echo -e "${GREEN}[+] $cont hosts verificados. $encontrados com malware!${NC}"
        divisoria
        for host in $(cat "$OUTPUT_FILE"); do
            ip="${rede}.${host}"
            extract_page "$ip"
            divisoria
        done
    else
        echo -e "${RED}[-] $cont hosts verificados. Nenhum comprometido.${NC}"
        divisoria
    fi
}

# Executa
main "$@"