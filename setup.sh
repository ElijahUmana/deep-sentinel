#!/bin/bash
# DeepSentinel — One-command setup
set -e

echo "=== DeepSentinel Setup ==="
echo ""

# Python environment
if [ ! -d "venv" ]; then
    echo "[1/4] Creating Python virtual environment..."
    python3 -m venv venv
else
    echo "[1/4] Virtual environment exists"
fi

source venv/bin/activate

# Dependencies
echo "[2/4] Installing Python dependencies..."
pip install -q -r requirements.txt

# Ghost CLI
if ! command -v ghost &> /dev/null; then
    echo "[3/4] Installing Ghost CLI..."
    curl -fsSL https://install.ghost.build | sh
else
    echo "[3/4] Ghost CLI already installed"
fi

# Environment file
if [ ! -f ".env" ]; then
    echo "[4/4] Creating .env from template..."
    cp .env.example .env
    echo "  Edit .env with your API keys before running."
else
    echo "[4/4] .env file exists"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Add API keys to .env"
echo "  2. Run: source venv/bin/activate"
echo "  3. Run: python -m src.main ElijahUmana demo-vulnerable-app 1"
echo "  4. Or autonomous mode: python -m src.main --autonomous ElijahUmana demo-vulnerable-app"
