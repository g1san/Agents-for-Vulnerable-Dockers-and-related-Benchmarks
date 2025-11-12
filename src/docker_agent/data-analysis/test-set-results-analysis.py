"""Run the agent by providing it with a CVE ID."""
import math
import json
import builtins
import numpy as np
import pandas as pd
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from IPython.display import display


#* Prints a brief summary of how test sets went by combining all results
def result_summary(model: str):
    wsm = "custom_no_tool"
    with builtins.open('./../services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[20:]        # From the 20th onward is the test set
    cve_data = {}
    cve_results = {}
    print(f"CVE #WS-OK/#Docker-OK(#Docker+Scout-OK)")
    for cve in sorted(cve_list):
        cve_results[cve] = {
            "Web Search OK": 0,
            "Docker OK": 0,
            "WS + Docker OK": 0,
            "Docker Scout OK": 0,
            "Docker + Scout OK": 0,
            "WS + Docker + Scout OK": 0,
        }
        for test_set in ["1st"]:
            try:
                with builtins.open(f'./../../../tests/{model}/{test_set}-test-set-results/{cve}/{wsm}/logs/milestones.json', 'r') as f:
                    milestones = json.load(f)     
                with builtins.open(f'./../../../tests/{model}/{test_set}-test-set-results/{cve}/{wsm}/logs/web_search_results.json', 'r') as f:
                    web_search_data = json.load(f)
                with builtins.open(f'./../../../tests/{model}/{test_set}-test-set-results/{cve}/{wsm}/logs/code.json', 'r') as f:
                    code_data = json.load(f)
                with builtins.open(f'./../../../tests/{model}/{test_set}-test-set-results/{cve}/{wsm}/logs/stats.json', 'r') as f:
                    stats = json.load(f)

                if milestones["hard_service"] and milestones["hard_version"] and milestones["soft_services"]: 
                    cve_results[cve]["Web Search OK"] += 1
                    if milestones["docker_builds"] and milestones["docker_runs"] and milestones["code_hard_version"] and milestones["network_setup"]:
                        cve_results[cve]["WS + Docker OK"] += 1
                        if stats["docker_scout_vulnerable"]:
                            cve_results[cve]["WS + Docker + Scout OK"] += 1

                if milestones["docker_builds"] and milestones["docker_runs"] and milestones["code_hard_version"] and milestones["network_setup"]:
                    cve_results[cve]["Docker OK"] += 1
                    if stats["docker_scout_vulnerable"]: cve_results[cve]["Docker + Scout OK"] += 1

                if stats["docker_scout_vulnerable"]: cve_results[cve]["Docker Scout OK"] += 1

            except Exception as e: 
                print(f"{cve} NOT OK {e}\n")       

        # print(f"{cve:<20}{cve_results[cve]}")
        print(f"{cve:<20}{cve_results[cve]["Web Search OK"]}/{cve_results[cve]["Docker OK"]}({cve_results[cve]["Docker + Scout OK"]})")
        cve_data[cve] = (cve_results[cve]["Web Search OK"], cve_results[cve]["Docker OK"], cve_results[cve]["Docker Scout OK"])

    overall_results = {
        "CVEs with OK WS+Docker": 0,
        "CVEs with OK Docker (WS ablation)": 0,
        "CVEs with OK WS+Docker+Scout": 0,
        "CVEs with OK Docker+Scout (WS ablation)": 0,
        "CVEs with OK Scout": 0
    }
    for cve in cve_list:
        results = cve_results[cve]
        if results["WS + Docker OK"] > 0: overall_results["CVEs with OK WS+Docker"] += 1
        if results["Docker OK"] > 0: overall_results["CVEs with OK Docker (WS ablation)"] += 1
        if results["WS + Docker + Scout OK"] > 0: overall_results["CVEs with OK WS+Docker+Scout"] += 1
        if results["Docker + Scout OK"] > 0: overall_results["CVEs with OK Docker+Scout (WS ablation)"] += 1
        if results["Docker Scout OK"] > 0: overall_results["CVEs with OK Scout"] += 1

    for label, value in overall_results.items():
        temp1 = (value*100) / len(cve_list)
        if label in ["CVEs with OK WS+Docker+Scout", "CVEs with OK Docker+Scout (WS ablation)"]:
            if label == "CVEs with OK WS+Docker+Scout":
                temp2 = (value*100) / (overall_results["CVEs with OK WS+Docker"])
            elif label == "CVEs with OK Docker+Scout (WS ablation)":
                temp2 = (value*100) / (overall_results["CVEs with OK Docker (WS ablation)"])
            print(f"{label:<40}{round(temp1, 2)}% ({round(temp2, 2)}% considering only working environments)")
        else:
            print(f"{label:<40}{round(temp1, 2)}%")
    
    
    total_cves = len(cve_data)
    cve_list = sorted(cve_data.keys())

    # Calculate statistics
    ws_ok = sum(1 for v in cve_data.values() if v[0] > 0)
    docker_ok = sum(1 for v in cve_data.values() if v[1] > 0)
    scout_ok = sum(1 for v in cve_data.values() if v[2] > 0)
    ws_docker_ok = sum(1 for v in cve_data.values() if v[0] > 0 and v[1] > 0)
    ws_docker_scout_ok = sum(1 for v in cve_data.values() if v[0] > 0 and v[1] > 0 and v[2] > 0)
    docker_scout_ok = sum(1 for v in cve_data.values() if v[1] > 0 and v[2] > 0)

    # Figure 1: Overall Success Rates
    fig1, ax1 = plt.subplots(figsize=(12, 7))
    categories = ['WS+Docker', 'Docker\n(WS ablation)', 'WS+Docker\n+Scout', 
                  'Docker+Scout\n(WS ablation)', 'Scout Only']
    values = [ws_docker_ok, docker_ok, ws_docker_scout_ok, docker_scout_ok, scout_ok]
    percentages = [v/total_cves*100 for v in values]

    colors = ['#2ecc71', '#3498db', '#e74c3c', '#f39c12', '#9b59b6']
    bars = ax1.bar(categories, percentages, color=colors, alpha=0.7, edgecolor='black', linewidth=1.5)

    for bar, pct, val in zip(bars, percentages, overall_results.values()):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{pct:.1f}%\n({val}/{total_cves})',
                ha='center', va='bottom', fontweight='bold', fontsize=11)

    ax1.set_ylabel('Success Rate (%)', fontsize=13, fontweight='bold')
    ax1.set_title(f'CVE Testing Success Rates by Configuration (n={total_cves})', 
                  fontsize=15, fontweight='bold', pad=20)
    ax1.set_ylim(0, max(percentages) * 1.25)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    ax1.legend(fontsize=11)
    plt.tight_layout()
    plt.show()

    # Figure 2: Success Categories Distribution
    fig2, ax2 = plt.subplots(figsize=(10, 8))
    success_categories = {
        'All 3 Components OK': sum(1 for v in cve_data.values() if v[0] == 3 and v[1] > 0 and v[2] > 0),
        'WS+Docker OK\n(Scout Failed)': sum(1 for v in cve_data.values() if v[0] > 0 and v[1] > 0 and v[2] == 0),
        'Docker Only OK\n(No WS)': sum(1 for v in cve_data.values() if v[0] == 0 and v[1] > 0),
        'WS Only OK\n(No Docker)': sum(1 for v in cve_data.values() if v[0] > 0 and v[1] == 0),
        'All Failed': sum(1 for v in cve_data.values() if v[0] == 0 and v[1] == 0)
    }

    colors_pie = ['#27ae60', '#3498db', '#e67e22', '#f1c40f', '#e74c3c']
    explode = (0.1, 0.05, 0.05, 0.05, 0.1)
    wedges, texts, autotexts = ax2.pie(success_categories.values(), labels=success_categories.keys(), 
                                         autopct='%1.1f%%', colors=colors_pie, explode=explode,
                                         startangle=90, textprops={'fontsize': 11, 'fontweight': 'bold'})
    ax2.set_title('CVE Success Category Distribution', fontsize=15, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.show()

    # Figure 3: Web Search Success Distribution
    fig3, ax3 = plt.subplots(figsize=(10, 7))
    ws_scores = [v[0] for v in cve_data.values()]
    ws_distribution = [ws_scores.count(i) for i in range(4)]
    bars3 = ax3.bar(['0/3', '1/3', '2/3', '3/3'], ws_distribution, 
                    color=['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71'],
                    alpha=0.7, edgecolor='black', linewidth=1.5, width=0.6)

    for bar, count in zip(bars3, ws_distribution):
        height = bar.get_height()
        if count > 0:
            ax3.text(bar.get_x() + bar.get_width()/2., height + 0.8,
                    f'{count}\n({count/total_cves*100:.1f}%)',
                    ha='center', va='bottom', fontweight='bold', fontsize=11)

    ax3.set_xlabel('Web Search Success Score', fontsize=13, fontweight='bold')
    ax3.set_ylabel('Number of CVEs', fontsize=13, fontweight='bold')
    ax3.set_title('Web Search Success Distribution\n(3 test runs per CVE)', 
                  fontsize=15, fontweight='bold', pad=20)
    ax3.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()
    plt.show()

    # Figure 4: Docker vs Web Search Correlation
    fig4, ax4 = plt.subplots(figsize=(10, 8))
    ws_scores = [v[0] for v in cve_data.values()]
    docker_scores = [v[1] for v in cve_data.values()]

    scatter = ax4.scatter(ws_scores, docker_scores, alpha=0.6, s=120, 
                          c=range(len(ws_scores)), cmap='viridis', edgecolors='black', linewidth=1.5)
    ax4.set_xlabel('Web Search Success (0-3)', fontsize=13, fontweight='bold')
    ax4.set_ylabel('Docker Success (0-3)', fontsize=13, fontweight='bold')
    ax4.set_title('Web Search vs Docker Success Correlation', fontsize=15, fontweight='bold', pad=20)
    ax4.grid(True, alpha=0.3, linestyle='--')
    ax4.set_xticks([0, 1, 2, 3])
    ax4.set_yticks([0, 1, 2, 3])
    ax4.plot([0, 3], [0, 3], 'r--', alpha=0.5, linewidth=2, label='Perfect correlation')
    ax4.legend(fontsize=11)
    plt.tight_layout()
    plt.show()

    # Figure 5: Scout Verification Rate
    fig5, ax5 = plt.subplots(figsize=(10, 7))
    scout_conditional = [
        ('With WS+Docker', ws_docker_scout_ok, ws_docker_ok),
        ('Without WS\n(Docker only)', docker_scout_ok, docker_ok)
    ]

    x_pos = np.arange(len(scout_conditional))
    conditional_rates = [item[1]/item[2]*100 if item[2] > 0 else 0 for item in scout_conditional]
    bars5 = ax5.bar(x_pos, conditional_rates, color=['#e74c3c', '#f39c12'], 
                    alpha=0.7, edgecolor='black', linewidth=1.5, width=0.5)

    for i, (bar, rate, item) in enumerate(zip(bars5, conditional_rates, scout_conditional)):
        height = bar.get_height()
        ax5.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{rate:.1f}%\n({item[1]}/{item[2]})',
                ha='center', va='bottom', fontweight='bold', fontsize=12)

    ax5.set_xticks(x_pos)
    ax5.set_xticklabels([item[0] for item in scout_conditional], fontsize=12)
    ax5.set_ylabel('Scout Verification Rate (%)', fontsize=13, fontweight='bold')
    ax5.set_title('Docker Scout Vulnerability Detection Rate\n(Among Working Environments)', 
                  fontsize=15, fontweight='bold', pad=20)
    ax5.set_ylim(0, max(conditional_rates) * 1.3)
    ax5.grid(axis='y', alpha=0.3, linestyle='--')
    ax5.axhline(y=26.5, color='blue', linestyle='--', alpha=0.5, linewidth=2,
                label='~26.5% (reported avg)')
    ax5.legend(fontsize=11)
    plt.tight_layout()
    plt.show()

    # Figure 6: Per-CVE Heatmap (Sorted)
    fig6, ax6 = plt.subplots(figsize=(7, 20))
    # Sort CVEs by: WS (desc), Docker (desc), Scout (desc), CVE-ID (asc)
    sorted_cves = sorted(cve_list, key=lambda cve: (-cve_data[cve][0], -cve_data[cve][1], -cve_data[cve][2], cve))
    data_matrix = np.array([[v[0]/3, v[1]/3, v[2]/3] for v in [cve_data[cve] for cve in sorted_cves]])

    im = ax6.imshow(data_matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
    ax6.set_xticks([0, 1, 2])
    ax6.set_xticklabels(['Web Search\n(0-3)', 'Docker\n(0-3)', 'Scout\n(0-3)'], fontsize=11, fontweight='bold')
    ax6.set_yticks(range(len(sorted_cves)))
    ax6.set_yticklabels(sorted_cves, fontsize=8)
    ax6.set_title("Per-CVE Success Heatmap", fontsize=15, fontweight='bold', pad=20)

    # Add text annotations
    for i in range(len(sorted_cves)):
        for j in range(3):
            text = ax6.text(j, i, f'{int(data_matrix[i, j]*3)}',
                           ha="center", va="center", color="black", fontweight='bold', fontsize=7)

    # cbar = plt.colorbar(im, ax=ax6)
    # cbar.set_label('Success Rate (0=Failed, 1=All Passed)', fontsize=11, fontweight='bold')
    plt.tight_layout()
    plt.show()

    # Figure 7: Per-CVE Grouped Bar Chart (Top 30 CVEs by year)
    fig7, ax7 = plt.subplots(figsize=(16, 8))
    cve_subset = cve_list[:30]  # First 30 CVEs
    x = np.arange(len(cve_subset))
    width = 0.25

    ws_vals = [cve_data[cve][0] for cve in cve_subset]
    docker_vals = [cve_data[cve][1] for cve in cve_subset]
    scout_vals = [cve_data[cve][2] for cve in cve_subset]

    bars1 = ax7.bar(x - width, ws_vals, width, label='Web Search', color='#3498db', alpha=0.8, edgecolor='black')
    bars2 = ax7.bar(x, docker_vals, width, label='Docker', color='#2ecc71', alpha=0.8, edgecolor='black')
    bars3 = ax7.bar(x + width, scout_vals, width, label='Scout', color='#e74c3c', alpha=0.8, edgecolor='black')

    ax7.set_xlabel('CVE ID', fontsize=12, fontweight='bold')
    ax7.set_ylabel('Success Count (out of 3 tests)', fontsize=12, fontweight='bold')
    ax7.set_title('Per-CVE Success Scores (First 30 CVEs)', fontsize=15, fontweight='bold', pad=20)
    ax7.set_xticks(x)
    ax7.set_xticklabels(cve_subset, rotation=90, ha='right', fontsize=8)
    ax7.legend(fontsize=11, loc='upper right')
    ax7.set_ylim(0, 3.5)
    ax7.grid(axis='y', alpha=0.3, linestyle='--')
    ax7.axhline(y=3, color='green', linestyle='--', alpha=0.3, linewidth=1)
    plt.tight_layout()
    plt.show()

    # Figure 8: Per-CVE Grouped Bar Chart (Last 30 CVEs - more recent)
    fig8, ax8 = plt.subplots(figsize=(16, 8))
    cve_subset = cve_list[-30:]  # Last 30 CVEs
    x = np.arange(len(cve_subset))

    ws_vals = [cve_data[cve][0] for cve in cve_subset]
    docker_vals = [cve_data[cve][1] for cve in cve_subset]
    scout_vals = [cve_data[cve][2] for cve in cve_subset]

    bars1 = ax8.bar(x - width, ws_vals, width, label='Web Search', color='#3498db', alpha=0.8, edgecolor='black')
    bars2 = ax8.bar(x, docker_vals, width, label='Docker', color='#2ecc71', alpha=0.8, edgecolor='black')
    bars3 = ax8.bar(x + width, scout_vals, width, label='Scout', color='#e74c3c', alpha=0.8, edgecolor='black')

    ax8.set_xlabel('CVE ID', fontsize=12, fontweight='bold')
    ax8.set_ylabel('Success Count (out of 3 tests)', fontsize=12, fontweight='bold')
    ax8.set_title('Per-CVE Success Scores (Last 30 CVEs - More Recent)', fontsize=15, fontweight='bold', pad=20)
    ax8.set_xticks(x)
    ax8.set_xticklabels(cve_subset, rotation=90, ha='right', fontsize=8)
    ax8.legend(fontsize=11, loc='upper right')
    ax8.set_ylim(0, 3.5)
    ax8.grid(axis='y', alpha=0.3, linestyle='--')
    ax8.axhline(y=3, color='green', linestyle='--', alpha=0.3, linewidth=1)
    plt.tight_layout()
    plt.show()
            
    return cve_data
result_summary(model="GPT-4o")


#* Chose one model and various benchmark logs set of that model, the output will show a stacked bar plot considering all WSMs
#* For each CVE there are two bars:
#* First is the number of runs with OK Web Search
#* Second is the number of runs with OK Docker *#
def cve_consistency_graph(cve_list: list, model: str, logs_sets: list, horizontal: bool):
    df = []
    modes = ["custom_no_tool"]
    
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for logs_set in logs_sets:
        file_name = f"./../../../tests/{model}/{logs_set}-test-set-results/"
        for cve in cve_list:
            for wsm in modes:
                try:
                    with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                        milestones = json.load(f)
                        
                    with builtins.open(file_name + f"{cve}/{wsm}/logs/stats.json", "r") as f:
                        stats = json.load(f)

                    df.append({
                        "cve": cve,
                        "web_search_mode": wsm,
                        "logs_set": logs_set,
                        "cve_id_ok": milestones["cve_id_ok"],
                        "hard_service": milestones["hard_service"],
                        "hard_version": milestones["hard_version"],
                        "soft_services": milestones["soft_services"],
                        "docker_builds": milestones["docker_builds"],
                        "docker_runs": milestones["docker_runs"],
                        "code_hard_version": milestones["code_hard_version"],
                        "network_setup": milestones["network_setup"],
                        "docker_scout_vulnerable": stats["docker_scout_vulnerable"]
                    })
                    
                except Exception as e: 
                    print(cve, wsm, f"'milestones.json' does not exist\t({e})")
                    continue
    print("="*10 + "END ERROR MESSAGES" + "="*10 + "\n"*3)            
    
    df = pd.DataFrame(df)
    cves_ok_ws_data = {}
    cves_ok_docker_data = {}
    for wsm in modes:
        cves_ok_ws_data[f"Runs with Correct Web Search ('{wsm}' mode)"] = []
        cves_ok_docker_data[f"Runs with Working Docker ('{wsm}' mode)"] = []
    
    df_grouped_cve = df.groupby("cve")
    ws_milestones = ["hard_service", "hard_version", "soft_services"]
    docker_milestones = ["docker_builds", "docker_runs", "code_hard_version", "network_setup"]
    
    cve_totals = []
    for cve, cve_group in df_grouped_cve:
        total_ws = 0
        total_docker = 0
        for wsm, wsm_group in cve_group.groupby("web_search_mode"):
            total_ws += len(wsm_group[wsm_group[ws_milestones].all(axis=1)])
            total_docker += len(wsm_group[wsm_group[docker_milestones].all(axis=1)])
        cve_totals.append((cve, total_ws, total_docker))
    
    # Sort by total web search (descending), then by total docker (descending)
    cve_totals.sort(key=lambda x: (-x[1], -x[2]))
    sorted_cve_list = [cve for cve, _, _ in cve_totals]
    
    # Rebuild data in sorted order
    for cve in sorted_cve_list:
        cve_group = df_grouped_cve.get_group(cve)
        for wsm, wsm_group in cve_group.groupby("web_search_mode"):
            cves_ok_ws_data[f"Runs with Correct Web Search ('{wsm}' mode)"].append(len(wsm_group[wsm_group[ws_milestones].all(axis=1)]))
            cves_ok_docker_data[f"Runs with Working Docker ('{wsm}' mode)"].append(len(wsm_group[wsm_group[docker_milestones].all(axis=1)]))

    print(cves_ok_ws_data)
    print(cves_ok_docker_data)
    
    if horizontal:
        y = np.arange(len(sorted_cve_list))
        height = 0.33
        fig, ax = plt.subplots(figsize=(10, max(8, len(sorted_cve_list) * 0.5)))
        left = np.zeros(len(sorted_cve_list))
        # Web Search colors - vibrant, intense tones
        ws_colors = ["#FF1744"]
        for (label, values), color in zip(cves_ok_ws_data.items(), ws_colors):
            p = ax.barh(y, values, height, label=label, left=left, color=color)
            left += values

        left = np.zeros(len(sorted_cve_list))
        # Docker colors - deep, saturated tones
        docker_colors = ["#2741C7"]
        for (label, values), color in zip(cves_ok_docker_data.items(), docker_colors):
            p = ax.barh(y + height, values, height, label=label, left=left, color=color)
            left += values

        ax.set_xlabel("Number of Runs")
        ax.set_title(f"CVE Consistency across All Runs")
        ax.set_yticks(y + height / 2, range(0, len(sorted_cve_list)))
        ax.legend(loc='upper left', bbox_to_anchor=(1.01, 1.0), borderaxespad=0)
        ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.grid(axis='x', alpha=0.33, linewidth=1, color='black')
        plt.tight_layout()
        plt.show()
    else:
        x = np.arange(len(cve_list))
        width = 0.33
        fig, ax = plt.subplots(figsize=(max(8, len(sorted_cve_list) * 0.5), 5))
        bottom = np.zeros(len(cve_list))
        colors = ["#FF1744"]
        for (label, values), color in zip(cves_ok_ws_data.items(), colors):
            p = ax.bar(x, values, width, label=label, bottom=bottom, color=color)
            # for rect, value, btm in zip(p, values, bottom):
            #     ax.text(
            #         x = rect.get_x() + rect.get_width() / 2,
            #         y = btm + rect.get_height() / 2,
            #         s = f'{int(value)}' if value > 0 else '',
            #         ha='center', va='center', color='black', fontsize=10, fontweight='bold'
            #     )
            bottom += values

        bottom = np.zeros(len(cve_list))
        colors = ["#2741C7"]
        for (label, values), color in zip(cves_ok_docker_data.items(), colors):
            p = ax.bar(x + width, values, width, label=label, bottom=bottom, color=color)
            # for rect, value, btm in zip(p, values, bottom):
            #     ax.text(
            #         x = rect.get_x() + rect.get_width() / 2,
            #         y = btm + rect.get_height() / 2,
            #         s = f'{int(value)}' if value > 0 else '',
            #         ha='center', va='center', color='black', fontsize=10, fontweight='bold'
            #     )
            bottom += values

        ax.set_ylabel("Number of Runs")
        ax.set_title(f"CVE Consistency across All Runs")
        ax.set_xticks(x + width / 2, range(0, len(sorted_cve_list)))
        # ax.legend(loc='upper left', ncols=1)
        ax.legend(loc='upper left', bbox_to_anchor=(1.01, 1), borderaxespad=0)
        # ax.set_ylim(0, ylim)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.grid(axis='y', alpha=0.33, linewidth=1, color='black')
        plt.show()
    
    return df
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[20:]
# logs_sets = ["1st", "2nd", "3rd"]
# cve_consistency_graph(cve_list=cve_list, model="gpt-oss-120b", logs_sets=logs_sets, horizontal=False)




