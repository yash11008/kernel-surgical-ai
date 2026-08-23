@echo off
echo ============================================
echo  KernelSurgical AI - Setup
echo ============================================
python -m venv venv
call venv\Scripts\activate
pip install -r requirements.txt
echo ============================================
echo  Setup complete! Run: run_demo.bat
echo ============================================
