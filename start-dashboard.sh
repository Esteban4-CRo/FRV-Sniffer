#!/bin/bash

# FRV Sniffer - Dashboard Server Only
# By EstebanCRO

echo -e "\e[96m╔══════════════════════════════════════════════════════════════╗"
echo -e "║                                                              ║"
echo -e "║                       FRV SNIFFER                            ║"
echo -e "║                    Dashboard Server                          ║"
echo -e "║                     By EstebanCRO                            ║"
echo -e "║                                                              ║"
echo -e "╚══════════════════════════════════════════════════════════════╝\e[0m"
echo ""

cd "$(dirname "$0")"

mkdir -p data logs

if ! command -v python3 &> /dev/null; then
    echo "✗ Error: Python 3 not installed"
    exit 1
fi

if ! python3 -c "import flask" 2>/dev/null; then
    echo "✗ Error: Flask not installed"
    echo "  Run: pip install flask flask-cors"
    exit 1
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
