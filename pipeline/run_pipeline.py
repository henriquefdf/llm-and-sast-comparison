import argparse
import os
import subprocess
import sys
import shutil
from tools import semgrep_runner, gemini_runner, gpt_runner
from utils import sarif_parser, llm_parser, analyzer

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
RESULTS_DIR = os.path.join(ROOT_DIR, "results")
BENCHMARK_DIR = os.path.join(ROOT_DIR, "owasp-benchmark")
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
CODEQL_HOME = os.path.join(TOOLS_DIR, "codeql-home", "codeql")
CODEQL_BIN = os.path.join(CODEQL_HOME, "codeql")
GROUND_TRUTH_CSV = os.path.join(BENCHMARK_DIR, "expectedresults-1.2.csv")

def run_command(command, cwd=None):
    print(f"Executing: {' '.join(command)}")
    try:
        subprocess.run(command, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        sys.exit(1)

def run_analysis(tool_name, csv_output, output_dir):
    print(f"Running Analysis for {tool_name}...")
    if os.path.exists(GROUND_TRUTH_CSV):
        analyzer.analyze_benchmark_results(GROUND_TRUTH_CSV, csv_output, tool_name, output_dir)
    else:
        print(f"[WARNING] Ground truth not found at {GROUND_TRUTH_CSV}. Skipping analysis report.")

def run_codeql():
    print("\n=== Running CodeQL ===")
    output_dir = os.path.join(RESULTS_DIR, "codeql")
    os.makedirs(output_dir, exist_ok=True)
    
    db_path = os.path.join(BENCHMARK_DIR, "codeql_db")
    sarif_output = os.path.join(output_dir, "codeql_results.sarif")
    csv_output = os.path.join(output_dir, "codeql_results.csv")

    # 1. Create Database (if not exists)
    if not os.path.exists(db_path):
        print("Creating CodeQL Database...")
        # CodeQL requires clean build
        run_command([
            CODEQL_BIN, "database", "create", db_path,
            "--language=java",
            "--overwrite",
            "--command=mvn clean package -DskipTests -Dspotless.check.skip=true",
            "--source-root", BENCHMARK_DIR
        ], cwd=BENCHMARK_DIR)
    else:
        print("CodeQL Database already exists. Skipping creation.")

    # 2. Analyze
    print("Running CodeQL Analysis...")
    run_command([
        CODEQL_BIN, "database", "analyze", db_path,
        "codeql/java-queries:codeql-suites/java-security-extended.qls",
        f"--format=sarifv2.1.0",
        f"--output={sarif_output}",
        "-j4", "--ram=4096", "--download"
    ], cwd=BENCHMARK_DIR)

    # 3. Parse Results
    print("Parsing CodeQL Results...")
    sarif_parser.parse_sarif(sarif_output, csv_output)
    
    # 4. Generate Report
    run_analysis("CodeQL", csv_output, output_dir)

def run_semgrep():
    print("\n=== Running Semgrep ===")
    output_dir = os.path.join(RESULTS_DIR, "semgrep")
    os.makedirs(output_dir, exist_ok=True)
    semgrep_runner.main(output_dir)
    
    csv_output = os.path.join(output_dir, "semgrep_results.csv")
    run_analysis("Semgrep", csv_output, output_dir)

def run_gemini():
    print("\n=== Running Gemini ===")
    output_dir = os.path.join(RESULTS_DIR, "gemini")
    os.makedirs(output_dir, exist_ok=True)
    
    jsonl_file = gemini_runner.run_gemini(output_dir)
    
    csv_output = os.path.join(output_dir, "gemini_results.csv")
    llm_parser.parse_llm_results(jsonl_file, csv_output)
    
    run_analysis("Gemini-2.5-flash", csv_output, output_dir)

def run_gpt():
    print("\n=== Running GPT ===")
    output_dir = os.path.join(RESULTS_DIR, "gpt")
    os.makedirs(output_dir, exist_ok=True)
    
    jsonl_file = gpt_runner.run_gpt(output_dir)
    
    csv_output = os.path.join(output_dir, "gpt_results.csv")
    llm_parser.parse_llm_results(jsonl_file, csv_output)
    
    run_analysis("gpt-5-mini", csv_output, output_dir)

def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark Analysis Pipeline")
    parser.add_argument("--tool", choices=["all", "codeql", "semgrep", "gemini", "gpt"], default="all", help="Tool to run")
    args = parser.parse_args()

    # Ensure results dir exists
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if args.tool == "all" or args.tool == "codeql":
        run_codeql()
    
    if args.tool == "all" or args.tool == "semgrep":
        run_semgrep()
        
    if args.tool == "all" or args.tool == "gemini":
        run_gemini()
        
    if args.tool == "all" or args.tool == "gpt":
        run_gpt()

    print("\n[SUCCESS] Pipeline Finished!")

if __name__ == "__main__":
    main()
