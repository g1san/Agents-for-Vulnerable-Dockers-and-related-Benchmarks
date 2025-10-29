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



#* Chose one model and various benchmark logs set of that model, the output will show a bar plot, 
#* three bars for each WSM:
#* First is the number of total runs
#* Second is the number of runs with OK Web Search
#* Third is the number of runs with OK Docker *#
def wsm_performance_graph(cve_list: list, model: str, logs_sets: list):
    df = []
    if model in ["GPT-4o", "GPT-5"]: modes = ["custom", "custom_no_tool", "openai"]
    else: modes = ["custom", "custom_no_tool"]
    
    
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for logs_set in logs_sets:
        file_name = f"./../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
        for cve in cve_list:
            for wsm in modes:
                try:
                    with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                        milestones = json.load(f)

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
                    })
                    
                except Exception as e: 
                    print(cve, wsm, f"'milestones.json' does not exist\t({e})")
                    continue
    print("="*10 + "END ERROR MESSAGES" + "="*10 + "\n"*3)            
    
    df = pd.DataFrame(df)
    df_grouped = df.groupby("web_search_mode")
    wsm_data = {
        "Total Runs": [],
        "Runs with Correct Web Search": [],
        "Runs with Working Docker": [],
    }
    ws_milestones = ["hard_service", "hard_version", "soft_services"]
    docker_milestones = ["docker_builds", "docker_runs", "code_hard_version", "network_setup"]
    ylim = 0
    for wsm, group in df_grouped:
        if len(group) > ylim: ylim = int(1.4*len(group))
        wsm_data["Total Runs"].append(len(group))
        wsm_data["Runs with Correct Web Search"].append(len(group[group[ws_milestones].all(axis=1)]))
        wsm_data["Runs with Working Docker"].append(len(group[group[docker_milestones].all(axis=1)]))
    
    print(wsm_data)
    x = np.arange(len(modes))  # the label locations
    width = 0.25  # the width of the bars
    multiplier = 0
    
    colors = ["green", "orange", "purple"]
    fig, ax = plt.subplots(layout='constrained')
    
    for (data_label, value), color in zip(wsm_data.items(), colors):
        offset = width * multiplier
        rects = ax.bar(x + offset, value, width, label=data_label, color=color)
        ax.bar_label(rects, padding=len(modes))
        multiplier += 1
    
    # Add some text for labels, title and custom x-axis tick labels, etc.
    title = "Web Search Mode Performance Comparison"
    ax.set_ylabel('Number of Runs')
    ax.set_title(title)
    ax.set_xticks(x + width, modes)
    # ax.legend(loc='upper left', ncols=1)
    ax.legend()
    ax.set_ylim(0, ylim)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.grid(axis='y', alpha=0.33, linewidth=1, color='black')
    plt.show()
    
    return df
with builtins.open('services.json', "r") as f:
    jsonServices = json.load(f)
cve_list = list(jsonServices.keys())[:20]
logs_sets = ["5th", "6th", "7th"]
wsm_performance_graph(cve_list=cve_list, model="GPT-4o", logs_sets=logs_sets)


#* Chose one model and various benchmark logs set of that model, the output will show a three bar plots, one for each WSM 
#* Each graph will show two bars for each CVE:
#* First is the number of runs with OK Web Search
#* Second is the number of runs with OK Docker *#
def wsm_consistency_graph(cve_list: list, model: str, logs_sets: list):
    df = []
    if model in ["GPT-4o", "GPT-5"]: modes = ["custom", "custom_no_tool", "openai"]
    else: modes = ["custom", "custom_no_tool"]
    
    
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for logs_set in logs_sets:
        file_name = f"./../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
        for cve in cve_list:
            for wsm in modes:
                try:
                    with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                        milestones = json.load(f)

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
                    })
                    
                except Exception as e: 
                    print(cve, wsm, f"'milestones.json' does not exist\t({e})")
                    continue
    print("="*10 + "END ERROR MESSAGES" + "="*10 + "\n"*3)            
    
    df = pd.DataFrame(df)
    df_grouped_wsm = df.groupby("web_search_mode")
    for wsm, group_wsm in df_grouped_wsm:
        df_grouped_cve = group_wsm.groupby("cve")
        cves_data = {
            "Runs with Correct Web Search": [],
            "Runs with Working Docker": [],
        }
        ws_milestones = ["hard_service", "hard_version", "soft_services"]
        docker_milestones = ["docker_builds", "docker_runs", "code_hard_version", "network_setup"]
        ylim = 0
        for cve, group in df_grouped_cve:
            if len(group) > ylim: ylim = int(1.33*len(group)) + 1
            cves_data["Runs with Correct Web Search"].append(len(group[group[ws_milestones].all(axis=1)]))
            cves_data["Runs with Working Docker"].append(len(group[group[docker_milestones].all(axis=1)]))

        print(wsm, cves_data)
        
        # --- Convert to DataFrame for multi-key sorting ---
        df_plot = pd.DataFrame({
            "cve": list(df_grouped_cve.groups.keys()),
            "Runs with Correct Web Search": cves_data["Runs with Correct Web Search"],
            "Runs with Working Docker": cves_data["Runs with Working Docker"],
        })

        # Sort by both columns descending
        df_plot = df_plot.sort_values(
            by=["Runs with Correct Web Search", "Runs with Working Docker"],
            ascending=[False, False]
        ).reset_index(drop=True)

        # --- Plot ---
        x = np.arange(len(df_plot))
        width = 0.33
        colors = ["orange", "purple"]

        fig, ax = plt.subplots(figsize=(10, 4))
        ax.bar(x, df_plot["Runs with Correct Web Search"], width, label="Runs with Correct Web Search", color=colors[0])
        ax.bar(x + width, df_plot["Runs with Working Docker"], width, label="Runs with Working Docker", color=colors[1])

        ax.set_ylabel("Number of Runs")
        ax.set_title(f"'{wsm}' Web Search Mode Consistency")
        ax.set_xticks(x + width / 2, df_plot["cve"], rotation=45)
        # ax.legend(loc='upper left', ncols=1)
        ax.legend()
        ax.set_ylim(0, ylim)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.grid(axis='y', alpha=0.33, linewidth=1, color='black')
        plt.show()
    
    return df
with builtins.open('services.json', "r") as f:
    jsonServices = json.load(f)
cve_list = list(jsonServices.keys())[:20]
logs_sets = ["5th", "6th", "7th"]
wsm_consistency_graph(cve_list=cve_list, model="GPT-4o", logs_sets=logs_sets)


#* Chose one model and various benchmark logs set of that model, the output will show a one bar plot (ALL RUNS ARE CONSIDERED)
#* For each CVE there are two bars:
#* First is the number of runs with OK Web Search
#* Second is the number of runs with OK Docker *#
def cve_consistency_graph(cve_list: list, model: str, logs_sets: list):
    df = []
    if model in ["GPT-4o", "GPT-5"]: modes = ["custom", "custom_no_tool", "openai"]
    else: modes = ["custom", "custom_no_tool"]
    
    
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for logs_set in logs_sets:
        file_name = f"./../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
        for cve in cve_list:
            for wsm in modes:
                try:
                    with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                        milestones = json.load(f)

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
                    })
                    
                except Exception as e: 
                    print(cve, wsm, f"'milestones.json' does not exist\t({e})")
                    continue
    print("="*10 + "END ERROR MESSAGES" + "="*10 + "\n"*3)            
    
    df = pd.DataFrame(df)
    df_grouped_cve = df.groupby("cve")
    cves_data = {
        "Runs with Correct Web Search": [],
        "Runs with Working Docker": [],
    }
    ws_milestones = ["hard_service", "hard_version", "soft_services"]
    docker_milestones = ["docker_builds", "docker_runs", "code_hard_version", "network_setup"]
    ylim = 0
    for cve, group in df_grouped_cve:
        if len(group) > ylim: ylim = int(1.25*len(group))
        cves_data["Runs with Correct Web Search"].append(len(group[group[ws_milestones].all(axis=1)]))
        cves_data["Runs with Working Docker"].append(len(group[group[docker_milestones].all(axis=1)]))

    print(wsm, cves_data)
    
    # --- Convert to DataFrame for multi-key sorting ---
    df_plot = pd.DataFrame({
        "cve": list(df_grouped_cve.groups.keys()),
        "Runs with Correct Web Search": cves_data["Runs with Correct Web Search"],
        "Runs with Working Docker": cves_data["Runs with Working Docker"],
    })

    # Sort by both columns descending
    df_plot = df_plot.sort_values(
        by=["Runs with Correct Web Search", "Runs with Working Docker"],
        ascending=[False, False]
    ).reset_index(drop=True)

    # --- Plot ---
    x = np.arange(len(df_plot))
    width = 0.33
    colors = ["orange", "purple"]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(x, df_plot["Runs with Correct Web Search"], width, label="Runs with Correct Web Search", color=colors[0])
    ax.bar(x + width, df_plot["Runs with Working Docker"], width, label="Runs with Working Docker", color=colors[1])

    ax.set_ylabel("Number of Runs")
    ax.set_title(f"CVE Consistency across All Runs")
    ax.set_xticks(x + width / 2, df_plot["cve"], rotation=45)
    # ax.legend(loc='upper left', ncols=1)
    ax.legend()
    ax.set_ylim(0, ylim)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.grid(axis='y', alpha=0.33, linewidth=1, color='black')
    plt.show()
    
    return df
with builtins.open('services.json', "r") as f:
    jsonServices = json.load(f)
cve_list = list(jsonServices.keys())[:20]
logs_sets = ["5th", "6th", "7th"]
cve_consistency_graph(cve_list=cve_list, model="GPT-4o", logs_sets=logs_sets)


def wsm_ablation_performance_graph(cve_list: list, model: list, logs_set: list, web_search_modes: list):
    df = {}
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for model, logs_set, wsms in zip(models, logs_sets, web_search_modes):
        file_name = f"./../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
        if wsms == "all": modes = ["custom", "custom_no_tool", "openai"]
        elif wsms == "all-openai": modes = ["custom", "custom_no_tool"]
        else: modes = [wsms]
        for cve in cve_list:
            for wsm in modes:
                try:
                    with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                        milestones = json.load(f)

                    df[f"{cve}-{wsm}"] = {
                        "cve_id_ok": milestones["cve_id_ok"],
                        "hard_service": milestones["hard_service"],
                        "hard_version": milestones["hard_version"],
                        "soft_services": milestones["soft_services"],
                        "docker_builds": milestones["docker_builds"],
                        "docker_runs": milestones["docker_runs"],
                        "code_hard_version": milestones["code_hard_version"],
                        "network_setup": milestones["network_setup"],
                    }

                except Exception as e: 
                    print(cve, wsm, f"'milestones.json' does not exist\t({e})")
                    continue
    
    if include_twwsr_data:
        file_name += "test-wrong-web-search-results/"
        for cve in cve_list:
            for wsm in modes:
                try:
                    with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                        milestones = json.load(f)
                    
                    milestones["hard_service"] = True
                    milestones["hard_version"] = True
                    milestones["soft_services"] = True

                    if correct_web_search_only and (not milestones["cve_id_ok"] or not milestones["hard_service"] or not milestones["hard_version"] or not milestones["soft_services"]): continue
                    if correct_docker_only and (not milestones["docker_builds"] or not milestones["docker_runs"] or not milestones["code_hard_version"] or not milestones["network_setup"]): continue

                    try:
                        with builtins.open(file_name + f"{cve}/{wsm}/logs/stats.json", "r") as f:
                            stats = json.load(f)
                    except:
                        stats = {
                            "num_containers": np.nan,
                            "test_iteration": np.nan,
                            "starting_image_builds": np.nan,
                            "image_build_failures": np.nan,
                            "starting_container_runs": np.nan,
                            "container_run_failures": np.nan,
                            "not_vuln_version_fail": np.nan,
                            "docker_misconfigured": np.nan,
                            "docker_scout_vulnerable": np.nan,
                            "exploitable": np.nan,
                            "static_and_dynamic_va": np.nan,
                            "services_ok": np.nan,
                            "requires_manual_setup": np.nan,
                        }

                    df.append({
                        "cve": cve,
                        "web_search_mode": wsm,

                        "cve_id_ok": milestones["cve_id_ok"],
                        "hard_service": milestones["hard_service"],
                        "hard_version": milestones["hard_version"],
                        "soft_services": milestones["soft_services"],
                        "docker_builds": milestones["docker_builds"],
                        "docker_runs": milestones["docker_runs"],
                        "code_hard_version": milestones["code_hard_version"],
                        "network_setup": milestones["network_setup"],

                        "num_containers": stats["num_containers"],
                        "test_iteration": stats["test_iteration"],
                        "starting_image_builds": stats["starting_image_builds"],
                        "image_build_failures": stats["image_build_failures"],
                        "starting_container_runs": stats["starting_container_runs"],
                        "container_run_failures": stats["container_run_failures"],
                        "not_vuln_version_fail": stats["not_vuln_version_fail"],
                        "docker_misconfigured": stats["docker_misconfigured"],
                        "docker_scout_vulnerable": stats["docker_scout_vulnerable"],
                        "exploitable": stats["exploitable"],
                        "static_and_dynamic_va": stats["docker_scout_vulnerable"] and stats["exploitable"],
                        "services_ok": stats["services_ok"],
                        "requires_manual_setup": stats["requires_manual_setup"],
                    })

                except: continue
    
    print("="*10 + "END ERROR MESSAGES" + "="*10 + "\n"*3)            
    df = pd.DataFrame(df)
    return df