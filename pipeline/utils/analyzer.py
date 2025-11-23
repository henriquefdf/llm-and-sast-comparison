import pandas as pd
import argparse
from collections import defaultdict
import sys
import re
import os

# ==============================================================================

def calculate_metrics(vp, fp, fn, vn):
    """Calcula as métricas de desempenho consolidadas."""
    epsilon = 1e-9  # Evita divisão por zero
    precision = vp / (vp + fp + epsilon)
    recall = vp / (vp + fn + epsilon)  # Cobertura
    f1_score = 2 * (precision * recall) / (precision + recall + epsilon)
    fpr = fp / (fp + vn + epsilon)  # Taxa de Falsos Positivos
    return precision, recall, f1_score, fpr

def analyze_benchmark_results(ground_truth_csv, tool_findings_csv, tool_name, output_dir):
    """
    Compara os resultados de uma ferramenta com o gabarito (expectedresults-1.2.csv)
    e gera um CSV detalhado e um TXT de resumo.
    """
    print(f"--- Iniciando Análise: {tool_name} ---")
    mode_desc = "MODO DE ANÁLISE: FOCADO (Targeted Only) - Ignorando ruídos de outros CWEs."
    mode_desc += "\n[WARNING] EQUIVALÊNCIA GERAL: CWE-326 ↔ CWE-328 (todas as ferramentas)"
    if "semgrep" in tool_name.lower():
        mode_desc += "\n[WARNING] EXCEÇÃO SEMGREP: CWE-327 também equivale a 326/328"
    print(mode_desc)

    try:
        # Carrega o gabarito oficial
        truth = pd.read_csv(ground_truth_csv, comment='#', header=None, names=['test_name', 'category', 'real_vulnerability', 'cwe'])
        
        # Limpeza de colunas
        truth.columns = truth.columns.str.strip()
        truth.columns = truth.columns.str.replace(' ', '_')

        # Extração de IDs
        truth['test_case_id'] = truth['test_name'].str.extract(r'(\d+)').astype(str)
        truth['cwe'] = truth['cwe'].astype(str)
        
        # Mapa da verdade
        truth_map = {}
        for index, row in truth.iterrows():
            truth_map[row['test_case_id']] = {
                'is_vulnerable': row['real_vulnerability'],
                'target_cwe': row['cwe']
            }
        
    except FileNotFoundError:
        print(f"Erro: Arquivo do gabarito '{ground_truth_csv}' não encontrado.")
        return
    except KeyError as e:
        print(f"Erro de Chave ao processar o gabarito: {e}")
        return

    try:
        findings = pd.read_csv(tool_findings_csv)
        findings['test_case_id'] = findings['test_case_id'].astype(str).str.zfill(5)
        findings['cwe'] = findings['cwe'].astype(str)
        
        # Mapa de detecções
        findings_map = defaultdict(set)
        for index, row in findings.iterrows():
            findings_map[row['test_case_id']].add(row['cwe'])
            
    except FileNotFoundError:
        print(f"Aviso: Arquivo de detecções '{tool_findings_csv}' não encontrado.")
        findings_map = defaultdict(set)

    detailed_results = []
    overall_counts = {'VP': 0, 'FP': 0, 'FN': 0, 'VN': 0}
    
    # Contadores para o resumo
    cwe_hit_miss_counts = defaultdict(lambda: {'VP': 0, 'FN': 0, 'Total': 0})
    cwe_fp_counts = defaultdict(int)

    # Normalização de CWEs (pad to 3 digits)
    def normalize_cwe(cwe):
        if pd.isna(cwe) or cwe == 'nan': return '000'
        return str(cwe).split('.')[0].strip().zfill(3)

    # Itera sobre cada caso de teste que existe no gabarito
    for case_id, truth_data in truth_map.items():
        
        is_vulnerable = truth_data['is_vulnerable']
        # Normaliza o alvo
        target_cwe = normalize_cwe(truth_data['target_cwe'])
        
        # Obtém os CWEs reportados pela ferramenta para este caso (e normaliza)
        raw_reported_cwes = findings_map.get(case_id, set())
        reported_cwes = {normalize_cwe(c) for c in raw_reported_cwes}
        
        # --- LÓGICA DE ANÁLISE FOCADA (TARGETED ONLY) ---
        # Só nos importamos se a ferramenta encontrou O CWE ALVO.
        # Outros CWEs encontrados são considerados "ruído" e ignorados.
        
        # EQUIVALÊNCIA GERAL (TODAS AS FERRAMENTAS):
        # CWE-326 (Inadequate Encryption Strength) ↔ CWE-328 (Use of Weak Hash)
        # Diferentes ferramentas mapeiam algoritmos fracos para diferentes CWEs
        tool_found_target = target_cwe in reported_cwes
        
        if not tool_found_target:
            # Para TODAS as ferramentas: 326 <-> 328
            if target_cwe == "326" and "328" in reported_cwes:
                tool_found_target = True
            elif target_cwe == "328" and "326" in reported_cwes:
                tool_found_target = True
            
            # EXCEÇÃO ADICIONAL SEMGREP: CWE-327 também equivale a 326 e 328
            if not tool_found_target and "semgrep" in tool_name.lower():
                if target_cwe == "327" and ("326" in reported_cwes or "328" in reported_cwes):
                    tool_found_target = True
                elif (target_cwe == "326" or target_cwe == "328") and "327" in reported_cwes:
                    tool_found_target = True
        
        status = ""
        
        if is_vulnerable:
            cwe_hit_miss_counts[target_cwe]['Total'] += 1
            
            if tool_found_target:
                status = "VP" # Verdadeiro Positivo (Era vuln e ferramenta achou o CWE certo)
                overall_counts['VP'] += 1
                cwe_hit_miss_counts[target_cwe]['VP'] += 1
            else:
                status = "FN" # Falso Negativo (Era vuln e ferramenta NÃO achou o CWE certo)
                overall_counts['FN'] += 1
                cwe_hit_miss_counts[target_cwe]['FN'] += 1
        
        else: # É um código seguro (Armadilha)
            if tool_found_target:
                status = "FP" # Falso Positivo (Era seguro, mas ferramenta disse que tinha o CWE alvo)
                overall_counts['FP'] += 1
                cwe_fp_counts[target_cwe] += 1 # Contamos o FP para o CWE alvo (pois foi ele que foi "alucinado")
            else:
                status = "VN" # Verdadeiro Negativo (Era seguro e ferramenta NÃO reportou o CWE alvo)
                overall_counts['VN'] += 1

        # Nota: Se a ferramenta reportou outros CWEs (ex: 209 em um teste de 79),
        # eles são ignorados aqui e não contam como FP, pois não eram o alvo do teste.

        detailed_results.append({
            'test_case_id': case_id,
            'status': status,
            'is_truly_vulnerable': is_vulnerable,
            'target_cwe': target_cwe,
            'tool_found_target': tool_found_target,
            'all_reported_cwes': list(reported_cwes)
        })

    # --- 1. GERAÇÃO DO ARQUIVO CSV DETALHADO ---
    csv_output_path = os.path.join(output_dir, f"{tool_name}_detailed_results.csv")
    detailed_df = pd.DataFrame(detailed_results)
    detailed_df.to_csv(csv_output_path, index=False, encoding='utf-8')
    print(f"[SUCESSO] Relatório CSV detalhado salvo em: {csv_output_path}")

    # --- 2. GERAÇÃO DO ARQUIVO TXT DE RESUMO ---
    txt_output_path = os.path.join(output_dir, f"{tool_name}_summary_report.txt")
    precision, recall, f1_score, fpr = calculate_metrics(
        overall_counts['VP'], overall_counts['FP'],
        overall_counts['FN'], overall_counts['VN']
    )

    with open(txt_output_path, 'w', encoding='utf-8') as f:
        f.write(f"--- Relatório de Desempenho: {tool_name} ---\n")
        f.write("=" * (30 + len(tool_name)) + "\n")
        f.write(f"Modo de Análise: FOCADO (Targeted Only)\n")
        f.write("=" * (30 + len(tool_name)) + "\n\n")
        
        f.write("--- MÉTRICAS CONSOLIDADAS ---\n")
        f.write(f"Total de Casos de Teste Analisados: {len(truth_map)}\n")
        f.write(f"Verdadeiros Positivos (VP): {overall_counts['VP']:5d}\n")
        f.write(f"Falsos Positivos    (FP): {overall_counts['FP']:5d}\n")
        f.write(f"Falsos Negativos    (FN): {overall_counts['FN']:5d}\n")
        f.write(f"Verdadeiros Negativos (VN): {overall_counts['VN']:5d}\n")
        f.write("-" * 30 + "\n")
        f.write(f"Precisão (Precision): {precision:.2%}\n")
        f.write(f"Cobertura (Recall):   {recall:.2%}\n")
        f.write(f"Pontuação F1 (F1-Score):  {f1_score:.2%}\n")
        f.write(f"Taxa de Falsos Positivos: {fpr:.2%}\n")
        f.write("\n" + "=" * (30 + len(tool_name)) + "\n\n")

        f.write("--- DETALHAMENTO POR CWE (Target) ---\n")
        f.write(f"Nota: VPs e FPs são contados apenas se a ferramenta reportou o CWE ALVO do teste.\n")
        f.write(f"Outros CWEs encontrados (ruído) foram ignorados.\n\n")
        sorted_hits = sorted(cwe_hit_miss_counts.items())
        for cwe, counts in sorted_hits:
            f.write(f"  CWE-{cwe}: \tAcertos (VP): {counts['VP']:3d} | Falhas (FN): {counts['FN']:3d} (de {counts['Total']} casos)\n")
            
        f.write("\n--- DETECÇÕES EM CÓDIGO SEGURO (Falsos Positivos) ---\n")
        if not cwe_fp_counts:
            f.write("  Nenhum Falso Positivo detectado.\n")
        else:
            sorted_fps = sorted(cwe_fp_counts.items())
            for cwe, count in sorted_fps:
                cwe_label = cwe if cwe != 'N/A' else 'CWE Desconhecido'
                f.write(f"  CWE-{cwe_label}: \t{count} detecções erradas.\n")

    print(f"[SUCESSO] Relatório TXT de resumo salvo em: {txt_output_path}\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Analyze SAST tool results against OWASP Benchmark.")
    parser.add_argument("ground_truth", help="Path to the *expectedresults-1.2.csv* file.")
    parser.add_argument("tool_findings", help="Path to the tool's parsed findings CSV.")
    parser.add_argument("tool_name", help="A name for the tool (e.g., 'CodeQL') to label output files.")
    parser.add_argument("output_dir", help="Directory to save reports.")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    analyze_benchmark_results(args.ground_truth, args.tool_findings, args.tool_name, args.output_dir)
