#!/bin/bash

echo "paho-mqtt installing"

if [ -d ".venv/bin" ]; then
    echo "Venv activation..."
    source .venv/bin/activate
else
    echo "Venv was not found!"
    echo "Creating new venv..."
    python3 -m venv .venv
    source .venv/bin/activate
fi

echo "Installing paho-mqtt..."

pip install paho-mqtt

echo "Checking the installation:"
pip show paho-mqtt

echo "Success! paho-mqtt has been installed."

read -p "Press any key to continue..."