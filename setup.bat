@echo off
echo === ModelTrust Setup ===
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Initializing database...
set FLASK_APP=run.py
flask db init
flask db migrate -m "initial"
flask db upgrade
echo.
echo Setup complete! Run run.bat to start the server.
pause
