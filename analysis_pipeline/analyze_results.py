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

GROUP_SEVERITY = {
    "Command Injection": "High",
    "SQL Injection": "High",
    "Path Traversal": "High",
    "LDAP Injection": "High",
    "XPath Injection": "High",
    "XSS": "High",
    "Trust Boundary": "Medium",
    "Secure Cookie": "Medium",
    "Weak PRNG": "Low",
    "Weak Hash": "Low"
}

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

def analyze_rq3_synergy(raw_results, ground_truth, output_dir):
    """RQ3: Exclusivity Rate (Synergy) between SAST vs LLM and 4 tools"""
    sast_llm_counts = {'Both': 0, 'Only SAST': 0, 'Only LLM': 0, 'Neither': 0}
    
    # 4 tools exclusivity
    tool_detection_counts = {0:0, 1:0, 2:0, 3:0, 4:0}
    exclusive_tools = {tool: 0 for tool in raw_results.keys()}
    
    for tid, gt in ground_truth.items():
        if not gt['vulnerable']:
            continue
            
        target_cwe = gt['cwe']
        
        # Tool matches
        matches = {}
        for tool, results in raw_results.items():
            matches[tool] = check_match(target_cwe, results.get(tid, []), tool)
            
        # SAST vs LLM match logic
        sast_match = matches.get("CodeQL", False) or matches.get("Semgrep", False)
        llm_match = matches.get("Gemini", False) or matches.get("GPT", False)
        
        if sast_match and llm_match:
            sast_llm_counts['Both'] += 1
        elif sast_match and not llm_match:
            sast_llm_counts['Only SAST'] += 1
        elif not sast_match and llm_match:
            sast_llm_counts['Only LLM'] += 1
        else:
            sast_llm_counts['Neither'] += 1
            
        # 4 tool overlap
        num_matches = sum(matches.values())
        tool_detection_counts[num_matches] += 1
        
        # Check exclusivity
        if num_matches == 1:
            for t, matched in matches.items():
                if matched:
                    exclusive_tools[t] += 1
                    break
                    
    # Plot SAST vs LLM Stacked Bar
    df_sast_llm = pd.DataFrame([sast_llm_counts])
    plt.figure(figsize=(10, 6))
    colors = ['#4daf4a', '#377eb8', '#ff7f00', '#e41a1c']
    ax = df_sast_llm.plot(kind='barh', stacked=True, color=colors, edgecolor='black', figsize=(10, 3))
    plt.title('RQ3: Synergy SAST vs LLM (True Positives Overlap)', fontsize=15, weight='bold')
    plt.xlabel('Number of Vulnerabilities')
    plt.yticks([0], ['SAST vs LLM'])
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.3), ncol=4)
    for c in ax.containers:
        ax.bar_label(c, label_type='center', color='white', weight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'rq3_synergy_sast_vs_llm.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    # Plot 4 tool distribution
    dist_df = pd.DataFrame({
        'Number of Detecting Tools': ['0 Tools', '1 Tool', '2 Tools', '3 Tools', '4 Tools'],
        'Count': [tool_detection_counts[0], tool_detection_counts[1], tool_detection_counts[2], tool_detection_counts[3], tool_detection_counts[4]]
    })
    plt.figure(figsize=(8, 5))
    ax2 = sns.barplot(data=dist_df, x='Number of Detecting Tools', y='Count', palette='viridis', edgecolor='black')
    plt.title('RQ3: Detection Distribution across 4 Tools', fontsize=15, weight='bold')
    for container in ax2.containers:
        ax2.bar_label(container, fmt='%d', label_type='edge', padding=3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'rq3_overlap_distribution.png'), dpi=300)
    plt.close()

    return {
        'sast_llm': sast_llm_counts,
        'detection_distribution': tool_detection_counts,
        'exclusive_tools': exclusive_tools
    }

def analyze_rq4_risk_severity(raw_results, ground_truth, output_dir):
    """RQ4: Risk and Severity for SAST vs LLM and raw recall for all 4 tools"""
    stats_ensemble = {
        'High':   {'SAST': {'TP': 0, 'FN': 0}, 'LLM': {'TP': 0, 'FN': 0}},
        'Medium': {'SAST': {'TP': 0, 'FN': 0}, 'LLM': {'TP': 0, 'FN': 0}},
        'Low':    {'SAST': {'TP': 0, 'FN': 0}, 'LLM': {'TP': 0, 'FN': 0}},
    }
    
    # Stats for individual tools
    stats_tools = {sev: {tool: {'TP': 0, 'FN': 0} for tool in raw_results.keys()} for sev in ['High', 'Medium', 'Low']}
    
    for tid, gt in ground_truth.items():
        if not gt['vulnerable']:
            continue
            
        target_cwe = gt['cwe']
        target_int = normalize_cwe(target_cwe)
        group = CWE_TO_GROUP.get(target_int, "Other")
        severity = GROUP_SEVERITY.get(group, None)
        
        if not severity:
            continue
            
        matches = {}
        for tool, results in raw_results.items():
            matches[tool] = check_match(target_cwe, results.get(tid, []), tool)
            if matches[tool]:
                stats_tools[severity][tool]['TP'] += 1
            else:
                stats_tools[severity][tool]['FN'] += 1
                
        sast_match = matches.get("CodeQL", False) or matches.get("Semgrep", False)
        llm_match = matches.get("Gemini", False) or matches.get("GPT", False)
        
        if sast_match: stats_ensemble[severity]['SAST']['TP'] += 1
        else:          stats_ensemble[severity]['SAST']['FN'] += 1
            
        if llm_match:  stats_ensemble[severity]['LLM']['TP'] += 1
        else:          stats_ensemble[severity]['LLM']['FN'] += 1
        
    ard_or_results = []
    for sev in ['High', 'Medium', 'Low']:
        sast_tp = stats_ensemble[sev]['SAST']['TP'] + 0.5
        sast_fn = stats_ensemble[sev]['SAST']['FN'] + 0.5
        llm_tp = stats_ensemble[sev]['LLM']['TP'] + 0.5
        llm_fn = stats_ensemble[sev]['LLM']['FN'] + 0.5
        
        p_llm = llm_tp / (llm_tp + llm_fn)
        p_sast = sast_tp / (sast_tp + sast_fn)
        ard = p_llm - p_sast
        
        odds_llm = llm_tp / llm_fn
        odds_sast = sast_tp / sast_fn
        or_val = odds_llm / odds_sast
        
        ard_or_results.append({'Severity': sev, 'ARD': ard, 'OR': or_val})
        
    df_ard_or = pd.DataFrame(ard_or_results)
    
    # Plot ARD for SAST vs LLM
    plt.figure(figsize=(8, 5))
    ax1 = sns.barplot(data=df_ard_or, x='Severity', y='ARD', palette='coolwarm', edgecolor='black', order=['High', 'Medium', 'Low'])
    plt.axhline(0, color='black', linewidth=1.2, linestyle='--')
    plt.title('RQ4: Absolute Risk Diff. (LLM vs SAST Ensemble)', fontsize=15, weight='bold')
    plt.ylabel('ARD (LLM Rate - SAST Rate)')
    for container in ax1.containers:
        ax1.bar_label(container, fmt='%.3f', label_type='edge', padding=3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'rq4_ard_sast_llm.png'), dpi=300)
    plt.close()
    
    # Plot OR for SAST vs LLM
    plt.figure(figsize=(8, 5))
    ax2 = sns.barplot(data=df_ard_or, x='Severity', y='OR', palette='YlOrRd', edgecolor='black', order=['High', 'Medium', 'Low'])
    plt.axhline(1, color='black', linewidth=1.2, linestyle='--')
    plt.title('RQ4: Odds Ratio (LLM vs SAST Ensemble)', fontsize=15, weight='bold')
    plt.ylabel('Odds Ratio (Log scale)')
    plt.yscale('log')
    for container in ax2.containers:
        ax2.bar_label(container, fmt='%.2f', label_type='edge', padding=3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'rq4_or_sast_llm.png'), dpi=300)
    plt.close()

    # Calculate raw recall for all 4 tools + ensembles per severity
    recall_results = []
    for sev in ['High', 'Medium', 'Low']:
        for tool in raw_results.keys():
            tp = stats_tools[sev][tool]['TP']
            fn = stats_tools[sev][tool]['FN']
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            recall_results.append({'Severity': sev, 'Entity': tool, 'Recall': recall})
            
        # Add Ensembles
        s_tp = stats_ensemble[sev]['SAST']['TP']
        s_fn = stats_ensemble[sev]['SAST']['FN']
        recall_results.append({'Severity': sev, 'Entity': 'SAST Ensemble', 'Recall': s_tp / (s_tp + s_fn) if (s_tp + s_fn) > 0 else 0})
        
        l_tp = stats_ensemble[sev]['LLM']['TP']
        l_fn = stats_ensemble[sev]['LLM']['FN']
        recall_results.append({'Severity': sev, 'Entity': 'LLM Ensemble', 'Recall': l_tp / (l_tp + l_fn) if (l_tp + l_fn) > 0 else 0})

    df_recall = pd.DataFrame(recall_results)
    plt.figure(figsize=(12, 6))
    ax3 = sns.barplot(data=df_recall, x='Severity', y='Recall', hue='Entity', palette='Set2', edgecolor='black', order=['High', 'Medium', 'Low'])
    plt.title('RQ4: Recall by Severity (All Tools & Ensembles)', fontsize=16, weight='bold')
    plt.ylabel('Recall (Hit Probability)')
    plt.ylim(0, 1.05)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'rq4_recall_by_severity.png'), dpi=300)
    plt.close()

    return {
        'ard_or': ard_or_results,
        'recall': df_recall.to_dict(orient='records')
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

def write_report(all_stats, filename, rq3_data=None, rq4_data=None):
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

        if rq3_data:
            sast_llm = rq3_data['sast_llm']
            f.write("RQ3: Exclusivity Rate (Synergy) SAST vs LLM\n")
            f.write("===============================================\n")
            f.write(f"  Detected by Both (Intersection): {sast_llm['Both']}\n")
            f.write(f"  Detected Only by SAST Ensemble: {sast_llm['Only SAST']}\n")
            f.write(f"  Detected Only by LLM Ensemble: {sast_llm['Only LLM']}\n")
            f.write(f"  Detected by Neither (FN in both): {sast_llm['Neither']}\n\n")
            
            f.write("RQ3: Cross-Tool Overlap (All 4 Tools)\n")
            f.write("=======================================\n")
            dist = rq3_data['detection_distribution']
            f.write(f"  Vulnerabilities detected by 4 tools: {dist[4]}\n")
            f.write(f"  Vulnerabilities detected by 3 tools: {dist[3]}\n")
            f.write(f"  Vulnerabilities detected by 2 tools: {dist[2]}\n")
            f.write(f"  Vulnerabilities detected by 1 tool: {dist[1]}\n")
            f.write(f"  Vulnerabilities detected by 0 tools: {dist[0]}\n\n")
            
            f.write("  Exclusivity Breakdown (Single Tool Detections):\n")
            for t, cnt in rq3_data['exclusive_tools'].items():
                f.write(f"    Exclusive to {t}: {cnt}\n")
            f.write("\n")
            
        if rq4_data:
            f.write("RQ4: Risk and Severity (LLM vs SAST Ensemble)\n")
            f.write("=============================================\n")
            for res in rq4_data['ard_or']:
                f.write(f"  Severity: {res['Severity']}\n")
                f.write(f"    Absolute Risk Difference (ARD): {res['ARD']:.4f}\n")
                f.write(f"    Odds Ratio (OR): {res['OR']:.4f}\n")
            f.write("\n")
            
            f.write("RQ4: Recall by Severity (All Entities)\n")
            f.write("======================================\n")
            for sev in ['High', 'Medium', 'Low']:
                f.write(f"  Severity: {sev}\n")
                for item in rq4_data['recall']:
                    if item['Severity'] == sev:
                        f.write(f"    {item['Entity']}: {item['Recall']:.4f}\n")
            f.write("\n")

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
        "Gemini": os.path.join(RESULTS_DIR, "gemini", "Gemini-2.5-flash_detailed_results.csv"),
        "GPT": os.path.join(RESULTS_DIR, "gpt", "gpt-5-mini_detailed_results.csv")
    }
    
    all_stats = {}
    raw_results = {}
    
    for tool_name, path in tools.items():
        print(f"Analyzing {tool_name}...")
        results = load_tool_results(tool_name, path)
        if not results:
            continue
            
        stats = analyze_tool(tool_name, results, ground_truth)
        all_stats[tool_name] = stats
        raw_results[tool_name] = results
        
    print("Generating Plots...")
    generate_plots(all_stats, OUTPUT_DIR)
    
    rq3_data = None
    rq4_data = None
    if len(raw_results) == 4:
        print("Generating RQ3 and RQ4 Plots (Synergy & Risk/Severity for 4 tools)...")
        rq3_data = analyze_rq3_synergy(raw_results, ground_truth, OUTPUT_DIR)
        rq4_data = analyze_rq4_risk_severity(raw_results, ground_truth, OUTPUT_DIR)
    
    
    print("Writing Report...")
    write_report(all_stats, REPORTS_FILE, rq3_data, rq4_data)
    print("Done! Check 'output' directory.")

if __name__ == "__main__":
    main()
