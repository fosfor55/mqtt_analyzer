@echo off
echo paho-mqtt installing

if exist ".venv\Scripts\activate.bat" (
    echo Venv activation...
    call .venv\Scripts\activate.bat
) else (
    echo Venv was not found!
    echo Creating new venv...
    python -m venv .venv
    call .venv\Scripts\activate.bat
)

echo Installing paho-mqtt...

pip install paho-mqtt

echo Checking the installation:
pip show paho-mqtt

echo Success! paho-mqtt has been installed.

pause