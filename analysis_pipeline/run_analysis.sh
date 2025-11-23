#!/bin/bash
source ../pipeline/venv-pipeline/bin/activate
pip install matplotlib seaborn
python3 analyze_results.py
