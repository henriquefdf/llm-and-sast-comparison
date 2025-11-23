import json
import csv
import re

def parse_sarif(sarif_file_path, output_csv_path):
    """
    Analisa um arquivo SARIF, extrai o CWE de cada regra e
    salva os resultados em um arquivo CSV.
    """
    try:
        with open(sarif_file_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
    except Exception as e:
        print(f"Erro lendo SARIF: {e}")
        return

    test_case_pattern = re.compile(r'BenchmarkTest(\d+)\.java')
    cwe_pattern = re.compile(r'external/cwe/cwe-(\d+)')
    
    rule_to_cwe_map = {}
    
    for run in sarif_data.get('runs', []):
        rules = run.get('tool', {}).get('driver', {}).get('rules', [])
        for rule in rules:
            rule_id = rule.get('id')
            if not rule_id: continue
            tags = rule.get('properties', {}).get('tags', [])
            cwes = set()
            for tag in tags:
                match = cwe_pattern.search(tag)
                if match:
                    cwes.add(str(int(match.group(1))))
            if cwes:
                rule_to_cwe_map[rule_id] = cwes

    results = []
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'N/A')
            cwes = rule_to_cwe_map.get(rule_id, set())
            for location in result.get('locations', []):
                file_path = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'N/A')
                line = location.get('physicalLocation', {}).get('region', {}).get('startLine', -1)
                match = test_case_pattern.search(file_path)
                if match:
                    test_case_id = match.group(1)
                    for cwe in cwes:
                        results.append({
                            'test_case_id': test_case_id,
                            'rule_id': rule_id,
                            'cwe': cwe,
                            'line': line,
                        })
                    break 

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['test_case_id', 'rule_id', 'cwe', 'line']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"SARIF parseado: {output_csv_path} ({len(results)} detecções)")
