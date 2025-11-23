#!/usr/bin/env python3
"""
Re-analyze existing GPT and Gemini .jsonl results with updated analyzer logic.
This script parses the .jsonl files and generates CSV findings + reports.
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.llm_parser import parse_llm_results
from utils.analyzer import analyze_benchmark_results

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")
GROUND_TRUTH_CSV = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 
    "owasp-benchmark", 
    "expectedresults-1.2.csv"
)

def reanalyze_llm_tool(tool_name, jsonl_file):
    """
    Re-parse and re-analyze a single LLM tool's results.
    
    Args:
        tool_name: "GPT" or "Gemini"
        jsonl_file: Path to the .jsonl results file
    """
    print(f"\n=== Re-analyzing {tool_name} ===")
    
    output_dir = os.path.join(RESULTS_DIR, tool_name.lower())
    csv_output = os.path.join(output_dir, f"{tool_name.lower()}_results.csv")
    
    # 1. Parse JSONL to CSV
    print(f"▶ Parsing {tool_name} results...")
    parse_llm_results(jsonl_file, csv_output)
    
    # 2. Run analysis
    print(f"▶ Running analysis for {tool_name}...")
    analyze_benchmark_results(GROUND_TRUTH_CSV, csv_output, tool_name, output_dir)
    
    print(f"[SUCCESS] {tool_name} analysis complete!")

def main():
    # Re-analyze Gemini
    gemini_jsonl = os.path.join(RESULTS_DIR, "gemini", "gemini_results.jsonl")
    if os.path.exists(gemini_jsonl):
        reanalyze_llm_tool("Gemini", gemini_jsonl)
    else:
        print(f"[INFO] Gemini results not found: {gemini_jsonl}")
    
    # Re-analyze GPT
    gpt_jsonl = os.path.join(RESULTS_DIR, "gpt", "gpt_results.jsonl")
    if os.path.exists(gpt_jsonl):
        reanalyze_llm_tool("GPT", gpt_jsonl)
    else:
        print(f"[INFO] GPT results not found: {gpt_jsonl}")
    
    print("[SUCCESS] All LLM tools re-analyzed successfully!")

if __name__ == "__main__":
    main()
