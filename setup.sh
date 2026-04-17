#!/bin/bash
# CanaryNet — Quick Setup Script
# Run this once on a fresh clone to get everything ready.
set -e

echo ""
echo "╔══════════════════════════════════════╗"
echo "║         CanaryNet Setup              ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. Python version check
python3 --version || { echo "[ERROR] Python 3 required"; exit 1; }

# 2. Create virtual environment
if [ ! -d ".venv" ]; then
    echo "[1/5] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/5] Virtual environment already exists, skipping."
fi

# 3. Activate venv
source .venv/bin/activate

# 4. Install dependencies
echo "[2/5] Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "      Done."

# 5. Copy .env if not present
if [ ! -f ".env" ]; then
    echo "[3/5] Creating .env from template..."
    cp .env.example .env
    echo "      .env created — edit it before running!"
else
    echo "[3/5] .env already exists, skipping."
fi

# 6. Init database
echo "[4/5] Initialising database..."
python main.py db init

# 7. Done
echo "[5/5] Setup complete!"
echo ""
echo "  Next steps:"
echo "  1. Edit .env with your real values"
echo "  2. source .venv/bin/activate"
echo "  3. python main.py serve"
echo ""
