#!/bin/bash

# Ensure we're in the right directory
cd ~/network_analyzer

# Activate virtual environment
source ./venv/bin/activate

# Show usage if requested
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 [-i INTERFACE] [-l]"
    echo "Options:"
    echo "  -i, --interface INTERFACE  Specify network interface to capture from"
    echo "  -l, --list                List available network interfaces"
    echo "  -h, --help                Show this help message"
    exit 0
fi

# Run the analyzer with sudo while preserving the environment
sudo -E ./venv/bin/python network_analyzer.py "$@" 