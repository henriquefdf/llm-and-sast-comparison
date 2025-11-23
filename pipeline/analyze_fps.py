import pandas as pd
import os

BENCHMARK_DIR = "../owasp-benchmark"
RESULTS_DIR = "../results/codeql"
GROUND_TRUTH_CSV = os.path.join(BENCHMARK_DIR, "expectedresults-1.2.csv")
FINDINGS_CSV = os.path.join(RESULTS_DIR, "codeql_results.csv")

def analyze_fps():
    # Load Ground Truth
    truth = pd.read_csv(GROUND_TRUTH_CSV, comment='#', header=None, names=['test_name', 'category', 'real_vulnerability', 'cwe'])
    truth['test_case_id'] = truth['test_name'].str.extract(r'(\d+)').astype(str)
    
    # Filter for Safe cases
    safe_cases = truth[truth['real_vulnerability'] == False]['test_case_id'].tolist()
    safe_cases_set = set(safe_cases)
    
    # Load Findings
    findings = pd.read_csv(FINDINGS_CSV)
    findings['test_case_id'] = findings['test_case_id'].astype(str).str.zfill(5)
    
    # Filter findings that are in safe cases
    fp_findings = findings[findings['test_case_id'].isin(safe_cases_set)]
    
    print(f"Total Safe Cases: {len(safe_cases)}")
    print(f"Total FP Findings: {len(fp_findings)}")
    
    print("\nTop Rules causing FPs:")
    print(fp_findings['rule_id'].value_counts().head(20))

if __name__ == "__main__":
    analyze_fps()
