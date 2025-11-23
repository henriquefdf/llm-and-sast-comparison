import json
import csv
import re
import sys
from tqdm import tqdm

def parse_llm_results(input_file, output_file):
    """
    Converte o output 'results.jsonl' (Gemini ou GPT) para o formato CSV.
    """
    TEST_CASE_REGEX = re.compile(r'BenchmarkTest(\d+)\.java')
    
    processed_lines = 0
    total_findings = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            total_lines = sum(1 for line in f)

        with open(input_file, 'r', encoding='utf-8') as infile, \
             open(output_file, 'w', encoding='utf-8', newline='') as outfile:
            
            writer = csv.writer(outfile)
            writer.writerow(['test_case_id', 'rule_id', 'cwe', 'line'])
            
            infile.seek(0)
            
            for line in tqdm(infile, total=total_lines, desc="Parsing LLM Results"):
                try:
                    data = json.loads(line)
                    processed_lines += 1
                    if not isinstance(data, dict): continue
                    if "fileName" not in data or "isVulnerable" not in data: continue

                    match = TEST_CASE_REGEX.search(data['fileName'])
                    if not match: continue
                    test_case_id = match.group(1)

                    if data.get("isVulnerable") is True:
                        findings = data.get("vulnerabilitiesFound", [])
                        for finding in findings:
                            cwe_raw = finding.get('cwe', 'CWE-UNKNOWN')
                            cwe = cwe_raw.replace('CWE-', '').strip()
                            line_num = finding.get('line', -1)
                            rule_id = "llm-finding"
                            writer.writerow([test_case_id, rule_id, cwe, line_num])
                            total_findings += 1
                            
                except json.JSONDecodeError:
                    pass

    except Exception as e:
        print(f"Erro no parse: {e}")

    print(f"LLM Results parseados: {output_file} ({total_findings} detecções)")
