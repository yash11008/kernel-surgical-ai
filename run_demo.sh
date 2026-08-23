#!/bin/bash
set -e
echo "============================================"
echo " KernelSurgical AI - Starting Demo"
echo "============================================"
source venv/bin/activate
streamlit run frontend/app.py --server.port 8501
