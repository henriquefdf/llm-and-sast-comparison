import os
import subprocess
import json
import csv
import re
import sys

def main(output_dir):
    benchmark_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "owasp-benchmark", "src", "main", "java", "org", "owasp", "benchmark", "testcode"))
    json_output = os.path.join(output_dir, "semgrep_raw.json")
    csv_output = os.path.join(output_dir, "semgrep_results.csv")
    
    print("Running Semgrep on benchmark directory...")
    
    command = [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--output", json_output,
        benchmark_dir
    ]
    
    try:
        # Run semgrep. We don't check=True because semgrep might return non-zero if findings exist
        subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"Error running semgrep: {e}")
        sys.exit(1)
        
    print("Parsing Semgrep JSON results...")
    
    if not os.path.exists(json_output):
        print(f"Semgrep output file {json_output} not found!")
        sys.exit(1)
        
    try:
        with open(json_output, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading Semgrep JSON: {e}")
        sys.exit(1)
        
    results = data.get("results", [])
    
    test_case_pattern = re.compile(r'BenchmarkTest(\d+)\.java')
    
    parsed_findings = []
    
    for result in results:
        path = result.get("path", "")
        rule_id = result.get("check_id", "UNKNOWN_RULE")
        
        # Try to extract CWE from metadata
        metadata = result.get("extra", {}).get("metadata", {})
        cwe = "UNKNOWN"
        cwe_data = metadata.get("cwe")
        
        if isinstance(cwe_data, list) and len(cwe_data) > 0:
            cwe_str = cwe_data[0]
        elif isinstance(cwe_data, str):
            cwe_str = cwe_data
        else:
            cwe_str = ""
            
        # Match something like "CWE-022" or "CWE-22"
        cwe_match = re.search(r'CWE-(\d+)', cwe_str, re.IGNORECASE)
        if cwe_match:
            # Padding with zeros if needed, though int conversion handles it
            cwe = str(int(cwe_match.group(1)))
            
        line = result.get("start", {}).get("line", -1)
        
        match = test_case_pattern.search(path)
        if match:
            test_case_id = match.group(1)
            parsed_findings.append({
                "test_case_id": test_case_id,
                "rule_id": rule_id,
                "cwe": cwe,
                "line": line
            })
            
    with open(csv_output, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['test_case_id', 'rule_id', 'cwe', 'line']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(parsed_findings)
        
    print(f"Semgrep parsing complete: {csv_output} ({len(parsed_findings)} findings)")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Please provide output directory")
