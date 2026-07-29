#!/bin/bash

# FRV Sniffer - Dashboard Server Only
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
    echo "Uso: ./start-dashboard.sh [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help                  Mostrar esta pantalla de ayuda y salir"
    echo ""
    exit 0
}

# Parsear argumentos
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) show_help ;;
        *) echo "Opción desconocida: $1"; show_help ;;
    esac
    shift
done

# Imprimir logo
print_logo

cd "$(dirname "$0")"

mkdir -p data logs

if ! command -v python3 &> /dev/null; then
    echo "✗ Error: Python 3 not installed"
    exit 1
fi

# Verificar e instalar Flask y Flask-CORS si no existen
if ! python3 -c "import flask, flask_cors" 2>/dev/null; then
    echo "Instalando dependencias de Flask..."
    pip install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt || pip install flask flask-cors
fi

echo "✓ Starting web server..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Dashboard: http://localhost:8000"
echo "  Note: Run sniffer in another terminal"
echo "        sudo python3 backend/sniffer.py"
echo ""
echo "  Press Ctrl+C to stop"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python3 backend/api_server.py
