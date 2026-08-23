#!/bin/bash
set -e
echo "============================================"
echo " KernelSurgical AI - Setup"
echo "============================================"
echo
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "Installing dependencies..."
pip install -r requirements.txt
echo
echo "============================================"
echo " Setup complete!"
echo " Run: ./run_demo.sh"
echo "============================================"
