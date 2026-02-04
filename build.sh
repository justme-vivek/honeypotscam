#!/bin/bash
# Render build script to ensure Python 3.11 is used
echo "Building with Python 3.11..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
