import json

with open('../results/codeql/codeql_results.sarif', 'r') as f:
    data = json.load(f)

rules = data['runs'][0]['tool']['driver']['rules']
target_rules = ['java/xss', 'java/stack-trace-exposure', 'java/http-response-splitting']
for rule in rules:
    if rule['id'] in target_rules:
        print(json.dumps(rule, indent=2))
