# Script to deploy Caldera and plugins
#!/bin/bash

# Exit on any error
set -e

# Variables
CALDERA_DIR="${HOME}/caldera"
PLUGIN_DIR="${CALDERA_DIR}/plugins/songbird"
SONGBIRD_SRC_DIR="$(dirname "$0")/plugin"

echo "[*] Installing dependencies..."
sudo apt-get update
sudo apt-get install -y git python3 python3-pip

echo "[*] Cloning MITRE Caldera..."
if [ ! -d "$CALDERA_DIR" ]; then
    git clone https://github.com/mitre/caldera.git "$CALDERA_DIR"
fi

echo "[*] Installing Python requirements..."
pip3 install -r "${CALDERA_DIR}/requirements.txt"

echo "[*] Deploying Songbird plugin..."
mkdir -p "$PLUGIN_DIR"
cp -r "${SONGBIRD_SRC_DIR}/." "$PLUGIN_DIR/"

echo "[*] Starting Caldera server..."
cd "$CALDERA_DIR"
python3 server.py --insecure

echo "[*] Deployment complete. Caldera is running."
