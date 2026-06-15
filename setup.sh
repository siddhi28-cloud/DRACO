#!/bin/bash

echo "========================================="
echo "DRACO AGENT AUTOMATED INSTALLER"
echo "=========================================="

echo "[*] Updating system packages..."
sudo apt-get update -y


echo "[*] Installing critical system tools & security libraries..."
sudo apt-get install -y \
    python3-pip \
    python3-venv \
    build-essential \
    mailcap \
    file \
    tcpdump \
    wireshark-common

echo "[*] Creating local Python virtual environment (.venv)..."
python3 -m venv .venv

echo "[*] Installing required framework dependencies..."
source .venv/bin/activate
pip install --upgrade pip

# Ensure requirements.txt exists before running pip install
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    echo "[!] Warning: requirements.txt not found. Installing core packages manually..."
    pip install watchdog colorama nemoguardrails
fi

echo "[*] fetching final project artifacts and reference reports..."
REPORT_URL="https://example.com"
TARGET_DIR="./dedicated_secure_area"


mkdir -p "$TARGET_DIR"

# Download the ZIP file using curl
curl -L -o report_payload.zip "$REPORT_URL"

if [ $? -eq 0 ]; then
    echo "[✓] Download complete. Extracting files to $TARGET_DIR..."
    # Extract files silently (-q) into your watched data area (-d)
    unzip -q -o report_payload.zip -d "$TARGET_DIR"
    
    # Clean up the zip container to keep the workspace tidy
    rm report_payload.zip
    echo "[✓] Report assets successfully mounted."
else
    echo "[!] Error: Failed to download the report artifacts. Check your URL configuration."
fi
# =====================================================================

echo "=================================================="
echo "SETUP COMPLETE! Your workspace is isolated and ready."
echo "====================================================="
echo "To run your self-correcting agent, execute:"
echo "sudo .venv/bin/python main.py"
echo "======================================================="


