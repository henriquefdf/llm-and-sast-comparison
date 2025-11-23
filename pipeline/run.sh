#!/bin/bash
set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VENV_DIR="$SCRIPT_DIR/venv-pipeline"

# Check if venv exists
if [ ! -d "$VENV_DIR" ]; then
    echo "[ERROR] Virtual environment not found at $VENV_DIR"
    echo "Please run ./setup.sh first."
    exit 1
fi

# Activate venv and run the pipeline with passed arguments
source "$VENV_DIR/bin/activate"
python3 "$SCRIPT_DIR/run_pipeline.py" "$@"
deactivate

