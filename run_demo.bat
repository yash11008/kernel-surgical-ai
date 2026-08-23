@echo off
echo ============================================
echo  KernelSurgical AI - Starting Demo
echo ============================================
call venv\Scripts\activate
streamlit run frontend\app.py --server.port 8501
