#!/usr/bin/env bash
# =============================================================
# Cookie Impact Analyzer – Setup Script
# =============================================================
# Installs browsermob-proxy (requires Java 8+) and all
# Python dependencies into the active virtual environment.
# =============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BMP_VERSION="2.1.4"
BMP_DIR="browsermob-proxy"
BMP_ZIP="browsermob-proxy-${BMP_VERSION}-bin.zip"
BMP_URL="https://github.com/lightbody/browsermob-proxy/releases/download/browsermob-proxy-${BMP_VERSION}/${BMP_ZIP}"

echo "=============================================="
echo "  Cookie Impact Analyzer – Setup"
echo "=============================================="

# ── 1. Check Java ─────────────────────────────────────────────
echo ""
echo "[1/3] Checking Java..."
if ! command -v java &>/dev/null; then
    echo "  [ERROR] Java not found. Install OpenJDK 11+ first:"
    echo "    sudo apt install openjdk-11-jre   # Debian/Ubuntu"
    echo "    sudo dnf install java-11-openjdk  # Fedora/RHEL"
    exit 1
fi
JAVA_VER=$(java -version 2>&1 | head -1)
echo "  [OK] $JAVA_VER"

# ── 2. Download browsermob-proxy ───────────────────────────────
echo ""
echo "[2/3] Setting up browsermob-proxy ${BMP_VERSION}..."

if [ -d "$BMP_DIR" ]; then
    echo "  [OK] browsermob-proxy already present – skipping download."
else
    if command -v wget &>/dev/null; then
        wget -q --show-progress -O "$BMP_ZIP" "$BMP_URL"
    elif command -v curl &>/dev/null; then
        curl -L --progress-bar -o "$BMP_ZIP" "$BMP_URL"
    else
        echo "  [ERROR] Neither wget nor curl found. Please download manually:"
        echo "    $BMP_URL"
        exit 1
    fi

    echo "  Extracting..."
    unzip -q "$BMP_ZIP"
    mv "browsermob-proxy-${BMP_VERSION}" "$BMP_DIR"
    rm -f "$BMP_ZIP"
    chmod +x "$BMP_DIR/bin/browsermob-proxy"
    echo "  [OK] browsermob-proxy installed in ./${BMP_DIR}/"
fi

# ── 3. Python dependencies ─────────────────────────────────────
echo ""
echo "[3/3] Installing Python dependencies..."

if [ -n "$VIRTUAL_ENV" ]; then
    echo "  Using venv: $VIRTUAL_ENV"
fi

pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  [OK] All Python packages installed."

# ── Done ────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  Setup complete!"
echo ""
echo "  Run the analyzer:"
echo "    python main.py onet.pl"
echo "    python main.py https://wp.pl"
echo "    python main.py bbc.com"
echo "=============================================="
