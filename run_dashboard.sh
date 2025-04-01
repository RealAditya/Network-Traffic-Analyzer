#!/bin/bash

# Get the absolute path of the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change to the script directory
cd "$SCRIPT_DIR"

# Activate virtual environment
source "./venv/bin/activate"

# Run the dashboard with sudo while preserving the environment
sudo -E "./venv/bin/python" "$SCRIPT_DIR/dashboard.py" 