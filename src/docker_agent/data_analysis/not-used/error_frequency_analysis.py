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


def stacked_bar_plot(data: dict, models_logs_sets: list, wsm: str):
    width = 0.5
    fig, ax = plt.subplots()
    bottom = np.zeros(len(models_logs_sets))
    for boolean, error_count in data.items():
        p = ax.bar(models_logs_sets, error_count, width, label=boolean, bottom=bottom)
        for rect, value, btm in zip(p, error_count, bottom):
            ax.text(
                x = rect.get_x() + rect.get_width() / 2,
                y = btm + rect.get_height() / 2,
                s = f'{int(value)}' if value > 0 else '',
                ha='center', va='center', color='black', fontsize=10, fontweight='bold'
            )
        bottom += error_count
        
    # for i, h in enumerate(mean_test_iterations):
    #     ax.hlines(y=h, xmin=i - 0.25, xmax=i + 0.25, linewidth=2)
    #     ax.text(i, h + 2, str(h), ha='center', va='bottom', fontsize=9, fontweight='bold')

    # # Add one sample line to the legend to represent all
    # ax.hlines(y=0, xmin=0, xmax=0, linewidth=2, color='gray', label='Mean Test Iterations')
    title = "Number of testing errors by type"
    if wsm is not None: title += f" ('{wsm}' Web Search Mode)"
    ax.set_title(title)
    ax.legend()
    # ax.legend(loc='center left', bbox_to_anchor=(0.75, 0.75))

    plt.show()
    

def get_data(cve_list: list[str], model: str, logs_set: str, iteration: str, web_search_mode: str, correct_web_search_only: bool, correct_docker_only: bool, include_twwsr_data: bool):
    file_name = f"./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
    if iteration != "": file_name += f"{iteration}-iteration/"
    if web_search_mode == "all": modes = ["custom", "custom_no_tool", "openai"]
    elif web_search_mode == "all-openai": modes = ["custom", "custom_no_tool"]
    else: modes = [web_search_mode]
    
    df = []
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for cve in cve_list:
        for wsm in modes:
            try:
                with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                    milestones = json.load(f)
                
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
                
            except Exception as e: 
                print(cve, wsm, f"does not exist\t({e})")
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
  

#* STACKED BAR PLOT TO VISUALIZE HOW TESTING LOOP ERRORS ARE DISTRIBUTED FOR SPECIFIC WSM*#
def wsm_test_loop_errors(cve_list: list, models: tuple, logs_sets: tuple, wsm: str):
    image_build_errors, container_run_errors, not_vuln_version_errors, wrong_network_setup_errors, mean_errors, mean_test_iterations = [], [], [], [], [], []
    for model, logs_set in zip(models, logs_sets):
        if wsm == "openai" and model not in ["GPT-4o", "GPT-5"]: continue
        print(model, logs_set)
        df = get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=False,
        )
        image_build_failures = df['image_build_failures'].sum()
        container_run_failures = df['container_run_failures'].sum()
        not_vuln_version_fail = df['not_vuln_version_fail'].sum()
        docker_misconfigured = df['docker_misconfigured'].sum()
        
        image_build_errors.append(image_build_failures)
        container_run_errors.append(container_run_failures)
        not_vuln_version_errors.append(not_vuln_version_fail)
        wrong_network_setup_errors.append(docker_misconfigured)
        mean_errors.append(((image_build_failures + container_run_failures + not_vuln_version_fail + docker_misconfigured) / len(df)).round(2))
        mean_test_iterations.append(df['test_iteration'].mean().round(2))
        
    data = {
        "Image Build Errors": image_build_errors,
        "Container Run Errors": container_run_errors,
        "Not Vulnerable Version": not_vuln_version_errors,
        "Wrong Network Setup": wrong_network_setup_errors,
    }
    print(f"Mean Errors {mean_errors}")
    print(f"Mean Test Iterations {mean_test_iterations}")
    stacked_bar_plot(
        data=data,
        models=models if wsm != "openai" else ("GPT-4o", "GPT-5"), 
        wsm=wsm,
    )
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "GPT-4o", "GPT-5")
# logs_sets = ("1st", "5th", "3rd")
# wsm_test_loop_errors(cve_list=cve_list, models=models, logs_sets=logs_sets, wsm="openai")

