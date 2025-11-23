import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import ast
import numpy as np

RESULTS_DIR = "../results"
OUTPUT_DIR = "output"
REPORTS_FILE = "reports.txt"

CWE_GROUPS = {
    "Weak Hash": {328, 327, 326, 400, 916, 732, 200},
    "Weak PRNG": {330, 338, 200, 532, 74, 20, 287, 352},
    "Path Traversal": {22, 23, 36, 73},
    "Command Injection": {78, 88},
    "SQL Injection": {89, 564},
    "LDAP Injection": {90},
    "XSS": {79, 80, 81, 82, 83, 84, 85, 86, 87, 116},
    "Secure Cookie": {614, 1004},
    "XPath Injection": {643},
    "Trust Boundary": {501}
}

CWE_TO_GROUP = {}
for group, cwes in CWE_GROUPS.items():
    for cwe in cwes:
        CWE_TO_GROUP[cwe] = group

def normalize_cwe(cwe_str):
    try:
        return int(cwe_str)
    except (ValueError, TypeError):
        return None

def check_match(target_cwe, reported_cwes, tool_name=None):
    target = normalize_cwe(target_cwe)
    if target is None:
        return False
    
    reported_ints = set()
    for c in reported_cwes:
        val = normalize_cwe(c)
        if val is not None:
            reported_ints.add(val)
            
    if target in reported_ints:
        return True
        
    if tool_name and tool_name.lower() == "semgrep":
        weak_crypto_set = {326, 327, 328}
        if target in weak_crypto_set:
            if not reported_ints.isdisjoint(weak_crypto_set):
                return True
                
    return False

def load_ground_truth():
    path = os.path.join("../owasp-benchmark", "expectedresults-1.2.csv")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Ground truth source not found at {path}")
        
    ground_truth = {}
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            parts = line.split(',')
            if len(parts) < 4:
                continue
                
            test_name = parts[0]
            try:
                tid = test_name.replace("BenchmarkTest", "")
            except:
                continue
                
            is_vuln_str = parts[2].lower()
            is_vuln = (is_vuln_str == 'true')
            
            try:
                cwe = int(parts[3])
            except ValueError:
                continue
                
            ground_truth[tid] = {
                'cwe': cwe,
                'vulnerable': is_vuln
            }
            
    return ground_truth

def load_tool_results(tool_name, csv_path):
    if not os.path.exists(csv_path):
        print(f"Warning: Results for {tool_name} not found at {csv_path}")
        return {}
        
    df = pd.read_csv(csv_path)
    results = {}
    for _, row in df.iterrows():
        try:
            tid_int = int(row['test_case_id'])
            tid = f"{tid_int:05d}"
        except ValueError:
            tid = str(row['test_case_id'])
            
        try:
            reported = ast.literal_eval(row['all_reported_cwes'])
        except:
            reported = []
        results[tid] = reported
    return results

def analyze_tool(tool_name, results, ground_truth):
    stats = {
        'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0,
        'by_cwe': {},
        'by_group': {}
    }
    
    for tid, gt in ground_truth.items():
        target_cwe = gt['cwe']
        is_vuln = gt['vulnerable']
        reported = results.get(tid, [])
        
        is_match = check_match(target_cwe, reported, tool_name=tool_name)
        
        if is_vuln:
            outcome = 'TP' if is_match else 'FN'
        else:
            outcome = 'FP' if is_match else 'TN'
        
        stats[outcome] += 1
        
        if target_cwe not in stats['by_cwe']:
            stats['by_cwe'][target_cwe] = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'Total': 0}
        stats['by_cwe'][target_cwe][outcome] += 1
        stats['by_cwe'][target_cwe]['Total'] += 1
        
        target_int = normalize_cwe(target_cwe)
        group = CWE_TO_GROUP.get(target_int, "Other")
        if group not in stats['by_group']:
            stats['by_group'][group] = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'Total': 0}
        stats['by_group'][group][outcome] += 1
        stats['by_group'][group]['Total'] += 1
        
    return stats

def calculate_metrics(stats):
    tp = stats['TP']
    fp = stats['FP']
    tn = stats['TN']
    fn = stats['FN']
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    
    return {
        'Precision': precision,
        'Recall': recall,
        'F1': f1,
        'Accuracy': accuracy,
        'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn
    }

def generate_plots(all_stats, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    # -----------------------------
    # Estilos globais
    # -----------------------------
    plt.rcParams.update({
        "figure.facecolor": "white",
        "axes.facecolor": "#F7F7F7",
        "axes.edgecolor": "#cccccc",
        "axes.grid": True,
        "grid.color": "#e0e0e0",
        "grid.linestyle": "--",
        "grid.linewidth": 0.6,
        "axes.titlesize": 16,
        "axes.labelsize": 13,
        "xtick.labelsize": 11,
        "ytick.labelsize": 11,
        "legend.fontsize": 12,
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans"]
    })

    sns.set_style("whitegrid")
    palette = sns.color_palette("Set2")  # Paleta moderna e equilibrada

    tools = list(all_stats.keys())
    metrics = ['Recall', 'Precision', 'F1']

    # -----------------------------
    # OVERALL COMPARISON
    # -----------------------------
    data = []
    for tool in tools:
        m = calculate_metrics(all_stats[tool])
        for metric in metrics:
            data.append({'Tool': tool, 'Metric': metric, 'Value': m[metric]})

    df = pd.DataFrame(data)

    plt.figure(figsize=(11, 6))
    ax = sns.barplot(data=df, x='Tool', y='Value', hue='Metric', palette=palette[:3], edgecolor='black')
    for container in ax.containers:
        ax.bar_label(container, fmt='%.2f', label_type='edge', padding=-15, color='black', fontweight='bold')
    plt.title('Overall Performance Comparison', fontsize=18, weight='bold')
    plt.ylim(0, 1.05)
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'overall_comparison.png'), dpi=300)
    plt.close()

    # -----------------------------
    # F1 SCORE COMPARISON (JUST F1)
    # -----------------------------
    f1_data = []
    for tool in tools:
        m = calculate_metrics(all_stats[tool])
        f1_data.append({'Tool': tool, 'F1': m['F1']})
    
    df_f1 = pd.DataFrame(f1_data)
    
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_f1, x='Tool', y='F1', hue='Tool', palette="RdYlGn", edgecolor='black', legend=False)
    plt.title('F1 Score by Tool', fontsize=18, weight='bold')
    plt.ylim(0, 1.05)
    plt.grid(alpha=0.25)
    for i, row in df_f1.iterrows():
        plt.text(i, row.F1 + 0.02, f"{row.F1:.4f}", ha='center', color='black', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'f1_comparison.png'), dpi=300)
    plt.close()

    # -----------------------------
    # AVERAGE F1 BY GROUP (ALL TOOLS)
    # -----------------------------
    group_avgs = {}
    for tool in tools:
        for group, s in all_stats[tool]['by_group'].items():
            m = calculate_metrics(s)
            if group not in group_avgs:
                group_avgs[group] = []
            group_avgs[group].append(m['F1'])
            
    avg_group_data = []
    for group, scores in group_avgs.items():
        avg_score = sum(scores) / len(scores) if scores else 0
        avg_group_data.append({'Group': group, 'Average F1': avg_score})
        
    df_avg_group = pd.DataFrame(avg_group_data).sort_values('Average F1', ascending=False)
    
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_avg_group, x='Average F1', y='Group', hue='Group', palette="RdYlGn", edgecolor='black', legend=False)
    plt.title('Average F1 Score by Group (All Tools)', fontsize=16, weight='bold')
    plt.xlim(0, 1.05)
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'average_f1_by_group.png'), dpi=300)
    plt.close()

    # -----------------------------
    # CONFUSION MATRIX COUNTS
    # -----------------------------
    counts_data = []
    for tool in tools:
        s = all_stats[tool]
        counts_data.append({
            'Tool': tool,
            'TP': s['TP'], 'FP': s['FP'],
            'TN': s['TN'], 'FN': s['FN']
        })

    df_counts = pd.DataFrame(counts_data).set_index('Tool')

    df_counts.plot(kind='bar', stacked=True, figsize=(11, 6),
                   color=sns.color_palette("Paired"), edgecolor='black')

    plt.title('Confusion Matrix Counts by Tool', fontsize=17, weight='bold')
    plt.ylabel('Count')
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'confusion_counts.png'), dpi=300)
    plt.close()

    # -----------------------------
    # F1 by GROUP - HEATMAP
    # -----------------------------
    group_data = []
    for tool in tools:
        for group, s in all_stats[tool]['by_group'].items():
            m = calculate_metrics(s)
            group_data.append({'Tool': tool, 'Group': group, 'F1': m['F1']})

    df_group = pd.DataFrame(group_data)
    if not df_group.empty:
        pivot = df_group.pivot(index='Group', columns='Tool', values='F1')
        plt.figure(figsize=(12, 8))
        sns.heatmap(
            pivot,
            annot=True,
            cmap="RdYlGn",
            vmin=0, vmax=1,
            linewidths=.5,
            cbar_kws={'shrink': 0.7},
            fmt=".2f"
        )
        plt.title('F1 Score by CWE Group', fontsize=18, weight='bold')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'f1_by_group_heatmap.png'), dpi=300)
        plt.close()

    # -----------------------------
    # F1 by CWE - HEATMAP
    # -----------------------------
    cwe_data = []
    for tool in tools:
        for cwe, s in all_stats[tool]['by_cwe'].items():
            m = calculate_metrics(s)
            cwe_data.append({'Tool': tool, 'CWE': f"CWE-{cwe}", 'F1': m['F1']})

    df_cwe_heat = pd.DataFrame(cwe_data)
    if not df_cwe_heat.empty:
        pivot_cwe = df_cwe_heat.pivot(index='CWE', columns='Tool', values='F1')
        plt.figure(figsize=(12, 11))
        sns.heatmap(
            pivot_cwe,
            annot=True,
            cmap="RdYlGn",
            vmin=0, vmax=1,
            linewidths=.4,
            cbar_kws={'shrink': 0.7},
            fmt=".2f"
        )
        plt.title('F1 Score by CWE', fontsize=18, weight='bold')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'f1_by_cwe_heatmap.png'), dpi=300)
        plt.close()

    # -----------------------------
    # TOP CWEs & GROUP PERFORMANCE
    # -----------------------------
    for tool in tools:
        # Top CWEs
        cwe_perf = []
        for cwe, s in all_stats[tool]['by_cwe'].items():
            m = calculate_metrics(s)
            cwe_perf.append({'CWE': str(cwe), 'F1': m['F1'], 'Count': s['Total']})

        df_cwe = pd.DataFrame(cwe_perf).sort_values('F1', ascending=False)

        plt.figure(figsize=(10, 6))
        sns.barplot(
            data=df_cwe.head(10),
            x='CWE', y='F1',
            hue='CWE',
            palette="RdYlGn",
            edgecolor='black',
            legend=False
        )
        plt.title(f'Top 10 CWEs for {tool}', fontsize=16, weight='bold')
        plt.ylim(0, 1.05)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{tool}_top_cwes.png'), dpi=300)
        plt.close()

        # Groups
        group_perf = []
        for group, s in all_stats[tool]['by_group'].items():
            m = calculate_metrics(s)
            group_perf.append({'Group': group, 'F1': m['F1']})

        df_group_tool = pd.DataFrame(group_perf).sort_values('F1', ascending=False)

        plt.figure(figsize=(10, 6))
        sns.barplot(
            data=df_group_tool,
            x='F1', y='Group',
            hue='Group',
            palette="RdYlGn",
            edgecolor='black',
            legend=False
        )
        plt.title(f'Group Performance – {tool}', fontsize=16, weight='bold')
        plt.xlim(0, 1.05)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{tool}_group_performance.png'), dpi=300)
        plt.close()


def write_report(all_stats, filename):
    with open(filename, 'w') as f:
        f.write("Analysis Report\n")
        f.write("================\n\n")
        
        for tool, stats in all_stats.items():
            m = calculate_metrics(stats)
            f.write(f"Tool: {tool}\n")
            f.write(f"  TP: {m['TP']}, FP: {m['FP']}, TN: {m['TN']}, FN: {m['FN']}\n")
            f.write(f"  Precision: {m['Precision']:.4f}\n")
            f.write(f"  Recall:    {m['Recall']:.4f}\n")
            f.write(f"  F1 Score:  {m['F1']:.4f}\n")
            f.write(f"  Accuracy:  {m['Accuracy']:.4f}\n\n")
            
            f.write("  Performance by Group:\n")
            for group, s in stats['by_group'].items():
                gm = calculate_metrics(s)
                f.write(f"    {group}: F1={gm['F1']:.4f} (TP={s['TP']}, FP={s['FP']})\n")
            f.write("\n")
            
            f.write("  Performance by CWE:\n")
            sorted_cwes = sorted(stats['by_cwe'].items(), key=lambda x: calculate_metrics(x[1])['F1'], reverse=True)
            for cwe, s in sorted_cwes:
                cm = calculate_metrics(s)
                f.write(f"    CWE-{cwe}: F1={cm['F1']:.4f} (TP={s['TP']}, FP={s['FP']})\n")
            f.write("\n" + "-"*40 + "\n\n")

def main():
    print("Loading Ground Truth...")
    try:
        ground_truth = load_ground_truth()
    except Exception as e:
        print(f"Error: {e}")
        return

    tools = {
        "CodeQL": os.path.join(RESULTS_DIR, "codeql", "CodeQL_detailed_results.csv"),
        "Semgrep": os.path.join(RESULTS_DIR, "semgrep", "Semgrep_detailed_results.csv"),
        "Gemini": os.path.join(RESULTS_DIR, "gemini", "Gemini_detailed_results.csv"),
        "GPT": os.path.join(RESULTS_DIR, "gpt", "GPT_detailed_results.csv")
    }
    
    all_stats = {}
    
    for tool_name, path in tools.items():
        print(f"Analyzing {tool_name}...")
        results = load_tool_results(tool_name, path)
        if not results:
            continue
            
        stats = analyze_tool(tool_name, results, ground_truth)
        all_stats[tool_name] = stats
        
    print("Generating Plots...")
    generate_plots(all_stats, OUTPUT_DIR)
    
    print("Writing Report...")
    write_report(all_stats, REPORTS_FILE)
    print("Done! Check 'output' directory.")

if __name__ == "__main__":
    main()
