#!/bin/bash

# FRV Sniffer - Startup Script

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║                       FRV SNIFFER                            ║"
echo "║                   System Initialization                      ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

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

# Start packet capture
cd backend
python3 sniffer.py "$@"

# Cleanup
echo ""
echo "Stopping services..."
kill $API_PID 2>/dev/null
echo "✓ System stopped"
