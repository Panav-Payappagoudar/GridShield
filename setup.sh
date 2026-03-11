#!/bin/bash
# GridShield Setup Script for Existing Codespaces
# This installs required system dependencies

echo "Installing system dependencies for GridShield..."

# Update package list
sudo apt-get update

# Install libpcap for Scapy packet capture
sudo apt-get install -y libpcap-dev tcpdump

# Install Python dependencies
pip3 install -r requirements.txt

echo ""
echo "✓ Setup complete!"
echo ""
echo "Now you can run:"
echo "  Terminal 1: sudo python3 main.py"
echo "  Terminal 2: sudo python3 simulator/modbus_sim.py"
echo ""
