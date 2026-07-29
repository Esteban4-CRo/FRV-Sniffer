#!/bin/bash

# FRV Sniffer - Startup Script
# By EstebanCRO

RS="\e[0m"
Y="\e[93m"
M="\e[95m"
C="\e[96m"

# Función para imprimir el logo estilizado
print_logo() {
    echo -e "${C}    ██████╗██████╗  ██████╗  ██████╗██╗  ██╗"
    echo -e "  ██╔════╝██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝"
    echo -e "  ██║     ██████╔╝██║   ██║██║     █████╔╝ "
    echo -e "  ██║     ██╔══██╗██║   ██║██║     ██╔═██╗ "
    echo -e "  ╚██████╗██║  ██║╚██████╔╝╚██████╗██║  ██╗"
    echo -e "   ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝${RS}"
    echo -e "    ${Y}Sniffer FRV${RS}"
    echo -e "                 ${M}by EstebanCRO${RS}"
    echo ""
}

# Función para mostrar la ayuda del script
show_help() {
    print_logo
    echo "Uso: sudo ./start.sh [opciones]"
    echo ""
    echo "Opciones disponibles:"
    echo "  -i, --interface <nombre>    Especificar interfaz de red (ej: eth0, wlan0)"
    echo "  -c, --count <número>        Cantidad de paquetes a capturar (0 = infinito)"
    echo "  -p, --protocol <protocolo>  Filtrar por protocolo específico: [tcp, udp, icmp, dns, http, https, ftp, ssh, all]"
    echo "  -f, --filter <filtro_bpf>   Filtro BPF adicional (ej: \"host 192.168.1.100\")"
    echo "  -s, --search <texto>        Filtro de búsqueda de texto dentro del paquete"
    echo "  -v, --verbose               Mostrar detalle de capas y hexdump de paquetes (estilo Wireshark)"
    echo "  -q, --quiet                 Modo silencioso (no mostrar traza de paquetes en consola, solo alertas)"
    echo "  -h, --help                  Mostrar esta pantalla de ayuda y salir"
    echo ""
    echo "Ejemplos:"
    echo "  sudo ./start.sh -i eth0 -c 10"
    echo "  sudo ./start.sh -p dns -s \"google\""
    echo "  sudo ./start.sh -i wlan0 -p tcp -c 100 -s \"GET\" -v"
    echo ""
    exit 0
}

# Parsear argumentos
IFACE=""
COUNT=""
PROTO=""
FILTER=""
SEARCH=""
VERBOSE=""
QUIET=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -i|--interface) IFACE="$2"; shift ;;
        -c|--count) COUNT="$2"; shift ;;
        -p|--protocol) PROTO="$2"; shift ;;
        -f|--filter) FILTER="$2"; shift ;;
        -s|--search) SEARCH="$2"; shift ;;
        -v|--verbose) VERBOSE="1" ;;
        -q|--quiet) QUIET="1" ;;
        -h|--help) show_help ;;
        *) echo "Opción desconocida: $1"; show_help ;;
    esac
    shift
done

# Imprimir logo
print_logo

# Ir al directorio del script
cd "$(dirname "$0")"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  WARNING: Root privileges required for packet capture"
    echo "  Execute with: sudo ./start.sh"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    read -p "  Continue anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "✗ Error: Python 3 not installed"
    exit 1
fi

echo "✓ Python detected: $(python3 --version)"

# Check dependencies
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt
fi

echo "✓ Dependencies verified"
echo ""

# Create directories
mkdir -p data logs

# Kill existing instances
pkill -f "api_server.py" 2>/dev/null
pkill -f "sniffer.py" 2>/dev/null

# Start API server
echo "Starting dashboard server..."
cd backend
python3 api_server.py > ../logs/api_server.log 2>&1 &
API_PID=$!
cd ..

sleep 2

echo "✓ Server started (PID: $API_PID)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Dashboard: http://localhost:8000"
echo "  Starting packet capture..."
echo ""
echo "  Press Ctrl+C to stop"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Construir argumentos para el sniffer de python
SNIFFER_ARGS=""
if [ -n "$IFACE" ]; then SNIFFER_ARGS="$SNIFFER_ARGS -i $IFACE"; fi
if [ -n "$COUNT" ]; then SNIFFER_ARGS="$SNIFFER_ARGS -c $COUNT"; fi
if [ -n "$PROTO" ]; then SNIFFER_ARGS="$SNIFFER_ARGS -p $PROTO"; fi
if [ -n "$FILTER" ]; then SNIFFER_ARGS="$SNIFFER_ARGS -f \"$FILTER\""; fi
if [ -n "$SEARCH" ]; then SNIFFER_ARGS="$SNIFFER_ARGS -s \"$SEARCH\""; fi
if [ -n "$VERBOSE" ]; then SNIFFER_ARGS="$SNIFFER_ARGS -v"; fi
if [ -n "$QUIET" ]; then SNIFFER_ARGS="$SNIFFER_ARGS -q"; fi

# Start packet capture
cd backend
eval "python3 sniffer.py $SNIFFER_ARGS"

# Cleanup
echo ""
echo "Stopping services..."
kill $API_PID 2>/dev/null
echo "✓ System stopped"
