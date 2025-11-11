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


#* GENERATE THE '{wsm}-benchmark.xlsx' and '{wsm}-benchmark.csv' FILEs *#
def generate_excel_csv():
    # CVE identifiers
    with builtins.open('./../services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[:20]
    
    data = {}
    web_search_modes = ['custom_no_tool', 'custom', 'openai']
    for mode in web_search_modes:
        data[mode] = []
        with builtins.open(f'./../../dockers/{mode}-milestones.json', 'r') as f:
            mode_milestones = json.load(f)
    
        milestones = list(next(iter(mode_milestones.values())).keys())

        for m in milestones:
            milestone_data = ['Yes' if mode_milestones[cve][m] else 'No' for cve in mode_milestones]
            data[mode].append(milestone_data)
        
        query_values = []
        number_of_services = []
        input_token_values = []
        output_token_values = []
        cost_values = []
        test_iteration_values = []
        num_containers_values = []
        for cve in cve_list:
            with builtins.open(f'./../../dockers/{cve}/{mode}/logs/web_search_results.json', 'r') as f:
                web_search_data = json.load(f)
                
            # Query value
            if mode == 'custom_no_tool':
                query_values.append(cve)
            elif mode == 'custom':
                query_values.append(web_search_data['query'])
            elif mode == 'openai':
                query_values.append("")
                
            number_of_services.append(len(web_search_data['services']))    # Number of services
            input_token_values.append(web_search_data['input_tokens'])          # Input token value
            output_token_values.append(web_search_data['output_tokens'])        # Output token value
            
            # Web search cost in dollars
            input_token_cost = 2.50 / 1000000               # GPT-4o single input token cost
            output_token_cost = 10.00 / 1000000             # GPT-4o single output token cost
            web_search_openai_tool_cost = 25.00 / 1000      # OpenAI web search tool cost for a single call
            if mode == 'custom_no_tool' or mode == 'custom':
                cost = (web_search_data['input_tokens'] * input_token_cost) + (web_search_data['output_tokens'] * output_token_cost)
                cost_values.append(round(cost, 5))
            elif mode == 'openai':
                cost = web_search_openai_tool_cost + (web_search_data['output_tokens'] * output_token_cost)
                cost_values.append(round(cost, 5))
                
            with builtins.open(f'./../../dockers/{cve}/{mode}/logs/stats.json', 'r') as f:
                code_stats = json.load(f)
                
            test_iteration_values.append(code_stats['test_iterations'])
            num_containers_values.append(code_stats['num_containers'])    
        
        data[mode].append(query_values)
        data[mode].append(number_of_services)
        data[mode].append(input_token_values)
        data[mode].append(output_token_values)
        data[mode].append(cost_values)
        data[mode].append(test_iteration_values)
        data[mode].append(num_containers_values)
        

    # Construct MultiIndex columns
    arrays = [[cve for cve in cve_list for _ in (0, 1, 2)], ['custom_no_tool', 'custom', 'openai'] * len(cve_list)]
    tuples = list(zip(*arrays))
    column = pd.MultiIndex.from_tuples(tuples, names=["CVE", "Web Search Mode"])

    # Combine datasets
    combined_data = []
    for row_custom_no_tool, row_custom, row_openai in zip(data['custom_no_tool'], data['custom'], data['openai']):
        combined = [val for pair in zip(row_custom_no_tool, row_custom, row_openai) for val in pair]
        combined_data.append(combined)

    # Create DataFrame
    df = pd.DataFrame(combined_data, columns=column, index=milestones + ['Query', 'Number of Services', 'Input Tokens', 'Output Tokens', 'Cost', 'Test Iterations', 'Number of Containers'])
    df.to_excel(f'./../../dockers/benchmark-milestones.xlsx')
    df.to_csv(f'./../../dockers/benchmark-milestones.csv')
    return df
# df = generate_excel_csv()


def generate_excel_csv_mono_mode(model, logs_set, mode):
    # CVE identifiers
    main_path = Path(f"./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/")
    
    with builtins.open('./../services.json', "r") as f:
        jsonServices = json.load(f)
        
    cve_list = list(jsonServices.keys())[:20]
    
    data = []
    for cve in cve_list:
        cve_data = {}
        cve_logs_path = main_path / f"{cve}/{mode}/logs"
        
        with builtins.open(cve_logs_path / 'milestones.json', 'r') as f:
            cve_milestones = json.load(f)
            for milestone, value in cve_milestones.items():
                cve_data[milestone] = value 
                
        cve_data["Web Search Mode"] = mode
            
        with builtins.open(cve_logs_path / 'web_search_results.json', 'r') as f:
            web_search_data = json.load(f)
            
        # Query value
        if mode == 'custom_no_tool':
            cve_data["Web Query"] = cve
        elif mode == 'custom':
            cve_data["Web Query"] = web_search_data['query']
        elif mode == 'openai':
            cve_data["Web Query"] = ""
            
        cve_data["Attack Type"] = web_search_data['attack_type']
        cve_data["Number of Proposed Services"] = len(web_search_data['services'])  # Number of services
        cve_data["Input Tokens"] = web_search_data['input_tokens']                  # Input token value
        cve_data["Output Tokens"] = web_search_data['output_tokens']                # Output token value
        
        # Web search cost in dollars
        if model == "GPT-4o":
            input_token_cost = 2.50 / 1000000               # GPT-4o single input token cost
            output_token_cost = 10.00 / 1000000             # GPT-4o single output token cost
            web_search_openai_tool_cost = 25.00 / 1000      # OpenAI web search tool cost for a single call
        elif model == "GPT-5":
            input_token_cost = 1.25 / 1000000               # GPT-5 single input token cost
            output_token_cost = 10.00 / 1000000             # GPT-5 single output token cost
            web_search_openai_tool_cost = 10.00 / 1000      # OpenAI web search tool cost for a single call
            
        if mode == 'custom_no_tool' or mode == 'custom':
            cost = (web_search_data['input_tokens'] * input_token_cost) + (web_search_data['output_tokens'] * output_token_cost)
            cve_data["Web Search Costs"] = round(cost, 5)
        elif mode == 'openai':
            cost = web_search_openai_tool_cost + (web_search_data['output_tokens'] * output_token_cost)
            cve_data["Web Search Costs"] = round(cost, 5)
        
        try:
            with builtins.open(cve_logs_path / 'stats.json', 'r') as f:
                code_stats = json.load(f) 
            cve_data["Number of Containers"] = code_stats['num_containers']
            cve_data["Test Iterations"] = code_stats['test_iterations']
            cve_data["Starting Image Builds"] = code_stats['starting_image_builds']
            cve_data["Image Build Failures"] = code_stats['image_build_failures']
            cve_data["Starting Container Runs"] = code_stats['starting_container_runs']
            cve_data["Container Run Failures"] = code_stats['container_run_failures']
            cve_data["Not Vulnerable Version Failures"] = code_stats['not_vuln_version_fail']
            cve_data["Docker Misconfigured"] = code_stats['docker_misconfigured']
            cve_data["Docker Scout Vulnerable"] = code_stats['docker_scout_vulnerable']
            cve_data["Exploitable"] = code_stats['exploitable']
            cve_data["Requires Manual Setup"] = code_stats['requires_manual_setup']
            
        except:
            cve_data["Number of Containers"] = None
            cve_data["Test Iterations"] = None
            cve_data["Starting Image Builds"] = None
            cve_data["Image Build Failures"] = None
            cve_data["Starting Container Runs"] = None
            cve_data["Container Run Failures"] = None
            cve_data["Not Vulnerable Version Failures"] = None
            cve_data["Docker Misconfigured"] = None
            cve_data["Docker Scout Vulnerable"] = None
            cve_data["Exploitable"] = None
            cve_data["Requires Manual Setup"] = None
            
        data.append(cve_data)

    # Create DataFrame
    milestones = ['cve_id_ok', 'hard_service', 'hard_version', 'soft_services', 'docker_runs', 'code_hard_version', 'services_ok', 'docker_vulnerable', 'exploitable']
    stats = ['Web Search Mode', 'Web Query', 'Attack Type', 'Number of Proposed Services', 'Input Tokens', 'Output Tokens', 'Web Search Costs', 'Number of Containers', 'Test Iterations', 'Starting Image Builds', 'Image Build Failures', 'Starting Container Runs', 'Container Run Failures', 'Not Vulnerable Version Failures']
    df = pd.DataFrame(data=data, index=cve_list)
    df.to_excel(main_path / f'{mode}-benchmark.xlsx')
    df.to_csv(main_path / f'{mode}-benchmark.csv')
    return df
# df = generate_excel_csv_mono_mode(model="GPT-5", logs_set="1st", mode="openai")


def get_cve_df(model: str, logs_set: str, iteration: str, mode: str):
    # CVE identifiers
    with builtins.open('./../services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[:20]
    
    data = []
    for cve in cve_list:
        cve_data = {}
        cve_data['cve_id'] = cve
        cve_data['web_search_mode'] = mode
        
        if iteration != "":
            with builtins.open(f'./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/{iteration}-iteration/{mode}-milestones.json', 'r') as f:
                mode_milestones = json.load(f)
        else:
            with builtins.open(f'./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/{mode}-milestones.json', 'r') as f:
                mode_milestones = json.load(f)

        for milestone, value in mode_milestones[cve].items():
            if milestone != 'exploitable':
                cve_data[milestone] = True if value else False
        
        data.append(cve_data)

    # Create DataFrame
    df = pd.DataFrame(data)
    return df 


def get_twwsr_df(model: str, logs_set: str, iteration: str, mode: str):
    # CVE identifiers
    with builtins.open('./../services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[:20]
    
    data = []
    for cve in cve_list:
        cve_data = {}
        cve_data['cve_id'] = cve
        cve_data['web_search_mode'] = mode
        
        try:
            if iteration != "":
                with builtins.open(f'./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/{iteration}-iteration/test-wrong-web-search-results/{cve}/{mode}/logs/milestones.json', 'r') as f:
                    milestones = json.load(f)
            else:
                with builtins.open(f'./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/test-wrong-web-search-results/{cve}/{mode}/logs/milestones.json', 'r') as f:
                    milestones = json.load(f)

            for milestone, value in milestones.items():
                if milestone != 'exploitable':
                    cve_data[milestone] = True if value else False

            data.append(cve_data)
        except:
            continue

    # Create DataFrame
    df = pd.DataFrame(data)
    return df 


#* PRINT MILESTONE RELATED STATS *#
def extract_milestones_stats(model: str, logs_set: str, mode: str):    
    data = {}
    with builtins.open(f'./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/{mode}-milestones.json', 'r') as f:
        mode_milestones = json.load(f)
        
    milestones = list(next(iter(mode_milestones.values())).keys())

    for m in milestones:
        data[m] = [1 if mode_milestones[cve][m] else 0 for cve in mode_milestones].count(1) * 100 /len(mode_milestones)
    
    for milestone, value in data.items():
        print(f"{milestone} --> {value}%")
    return data  
# data = extract_milestones_stats(model="GPT-5", logs_set="3rd", mode='custom_no_tool')

def is_achieved(x):
    if pd.isna(x):
        return False
    if isinstance(x, (int, float, np.integer, np.floating)):
        try:
            return float(x) != 0.0 and not math.isclose(float(x), 0.0)
        except:
            return True
    s = str(x).strip()
    if s == "":
        return False
    s_low = s.lower()
    falsey = {"0", "0.0", "false", "none", "nan", "n/a", "no", "not started", "not_started", "falsey"}
    truthy = {"1", "yes", "true", "done", "completed", "complete", "y", "ok", "found"}
    if s_low in falsey:
        return False
    if s_low in truthy:
        return True
    try:
        num = float(s_low)
        return not math.isclose(num, 0.0)
    except:
        pass
    return True


#* PRINT WSM RELATED STATS *#
def web_search_mode_stats(model: str, logs_set: str, iteration: str, mode: str):
    print(f"model: {model}, logs_set: {logs_set}, iteration: {iteration if iteration else "none"}, mode: {mode if mode else "all"}")
    if mode == "":
        df = pd.concat([
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='custom'), 
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='custom_no_tool'), 
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='openai'),
        ])
    else:
        df = get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode=mode)
    
    milestones = [c for c in df.columns if c not in ['cve_id','web_search_mode']]
    # interpret 'True'/'False' strings if necessary
    bool_df = df[milestones].map(lambda x: str(x).strip().lower()=='true')
    pass_rates = bool_df.mean()
    bool_df

    pass_rates.plot(kind='bar')
    plt.ylabel('Fraction passing')
    plt.title('Milestone pass rates (funnel)')
    plt.ylim(0,1)
    plt.show()

    adj_cond = []
    for i in range(len(milestones)-1):
        prev = milestones[i]
        nxt = milestones[i+1]
        prev_pass = bool_df[prev]
        denom = prev_pass.sum()
        if denom == 0:
            prob = np.nan
        else:
            prob = ((prev_pass) & (bool_df[nxt])).sum() / denom
        adj_cond.append({'from': prev, 'to': nxt, 'P(next|prev)': prob, 'prev_pass_count': denom})
    adj_cond_df = pd.DataFrame(adj_cond)
    display(adj_cond_df)
    #! I do not think this is useful, the milestones do not have a consequential correlation


    # 4) Most common pass/fail patterns
    patterns = bool_df.astype(int).astype(str).agg(''.join, axis=1)
    pattern_counts = patterns.value_counts().reset_index()
    pattern_counts.columns = ['pattern', 'count']
    # Add human readable pattern labels (mapping 1/0 to milestone names)
    def pattern_to_list(pat):
        return {milestones[i]: ('pass' if ch=='1' else 'fail') for i,ch in enumerate(pat)}
    pattern_counts['example_milestone_states'] = pattern_counts['pattern'].map(lambda p: str(pattern_to_list(p)))
    display(pattern_counts)
    
    binary = df[milestones].map(is_achieved).astype(int)

    # Per-CVE summary
    per_cve = pd.DataFrame({
        "cve_id": df["cve_id"],
        "milestones_achieved": binary.sum(axis=1),
        "milestones_total": len(milestones)
    })
    per_cve["milestones_percent"] = (per_cve["milestones_achieved"] / per_cve["milestones_total"]) * 100

    # Add web_search_mode for grouping
    per_cve["web_search_mode"] = df["web_search_mode"]

    # --- Group-level stats ---
    agg_stats = per_cve.groupby("web_search_mode").agg(
        num_cves=("cve_id", "count"),
        mean_achieved=("milestones_achieved", "mean"),
        median_achieved=("milestones_achieved", "median"),
        min_achieved=("milestones_achieved", "min"),
        max_achieved=("milestones_achieved", "max")
    )

    # Milestone-specific achievement rates per web_search_mode
    milestone_by_mode = df.groupby("web_search_mode")[milestones].apply(lambda g: g.map(is_achieved).mean() * 100)

    # Show tables
    display("Milestone achievement summary by web_search_mode", agg_stats.reset_index())
    display("Milestone-specific achievement rates by web_search_mode (%)", milestone_by_mode.reset_index())

    # Plot average milestones achieved
    plt.figure(figsize=(8,5))
    plt.bar(['Mode 1', 'Mode 2', 'Mode 3'], agg_stats["mean_achieved"])
    plt.ylabel("Average milestones achieved")
    plt.title("Average milestones achieved by web_search_mode")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Heatmap of milestone-specific achievement %
    plt.figure(figsize=(5,5))
    plt.imshow(milestone_by_mode.T, aspect="auto", cmap="Reds")
    plt.colorbar(label="% Achieved")
    plt.xticks(range(len(milestone_by_mode.index)), ['Mode 1', 'Mode 2', 'Mode 3'])
    plt.yticks(range(len(milestone_by_mode.columns)), milestone_by_mode.columns)
    # plt.title("Milestone achievement rates by web_search_mode")
    plt.tight_layout()
    plt.show()
    
    return df
    # df.groupby(['cve_id'])    
# df = web_search_mode_stats(model="GPT-4o", logs_set="5th", iteration="", mode="")


def barh_mean_std(df, feature: str):
    df_grouped_mean = df.groupby(feature).mean(numeric_only=True)
    df_grouped_std = df.groupby(feature).std(numeric_only=True)
    for col in df_grouped_mean.columns:
        plt.figure(figsize=(int(max(df_grouped_mean[col].dropna()) + abs(max(df_grouped_std[col].dropna())) + 1), len(df_grouped_mean.index)))
        plt.grid()
        
        plt.barh(
            df_grouped_mean.index,
            df_grouped_mean[col],
            xerr=df_grouped_std[col],
            capsize=5,
            height=0.6,
        )
        plt.title(f"Mean and Std of '{col}' by '{feature}'")
        plt.ylabel(feature)
        plt.yticks(np.arange(len(df_grouped_mean.index)), df_grouped_mean.index)
        plt.xlabel(col)
        plt.tight_layout()
        plt.show()


def barh_service_wsm(df, unique_services):
    x = np.arange(len(unique_services))
    width = 0.2     # Bar tickness
    plt.figure(figsize=(5, 15))
    plt.grid()
    
    max_frequency = 0
    grouped_df = df.groupby("web_search_mode")
    for wsm, group in grouped_df:
        service_occurrence_distribution = {}
        for service in unique_services:
            service_occurrence_distribution[service] = 0
            
        for service, occurrences in group['service_name'].value_counts().items():
            service_occurrence_distribution[service] = occurrences
            
        if max_frequency < max(service_occurrence_distribution.values()):
            max_frequency = max(service_occurrence_distribution.values())
        
        if wsm == 'custom': 
            color = 'green'
            new_x = x + width
        if wsm == 'custom_no_tool': 
            color = 'blue'
            new_x = x
        elif wsm == 'openai':
            color = 'red'
            new_x = x - width
        plt.barh(y=new_x, width=[service_occurrence_distribution.get(service, 0) for service in unique_services], height=width, label=wsm, color=color)
    
    plt.xticks(range(0, max_frequency + 1, 1))
    plt.xlabel("Frequency")
    plt.yticks(x, unique_services)
    plt.ylabel("Service Name")
    plt.title("Most frequently Used Services by Web Search Mode")
    plt.legend()
    plt.tight_layout()
    plt.show()


#* SERVICE RELATED STATS *#
def services_stats(cve_list: list[str], model: str, logs_set: str, iteration: str, web_search_mode: str, filtered_milestones: bool):
    file_name = f"./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
    if iteration != "": file_name += f"{iteration}-iteration/"
    if web_search_mode != "": modes = [web_search_mode]
    else: modes = ["custom", "custom_no_tool", "openai"]
    
    df, unique_services, unique_dep_types = [], set(), set()
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for cve in cve_list:
        for wsm in modes: 
            web_search_results = None
            try:
                with builtins.open(file_name + f"{cve}/{wsm}/logs/milestones.json", "r") as f:
                    milestones = json.load(f)
                
                if filtered_milestones and (not milestones["cve_id_ok"] or not milestones["hard_service"] or not milestones["hard_version"] or not milestones["soft_services"]): continue

                with builtins.open(file_name + f"{cve}/{wsm}/logs/web_search_results.json", "r") as f:
                    web_search_results = json.load(f)
                    
                with builtins.open(file_name + f"{cve}/{wsm}/logs/stats.json", "r") as f:
                    stats = json.load(f)

                for service in web_search_results["services"]:
                    unique_services.add(service["name"].split("/")[-1].lower())
                    unique_dep_types.add(service["dependency_type"])
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
                        
                        "service_name": service["name"].split("/")[-1].lower(),
                        "service_dependency_type": service["dependency_type"],
                        "service_name_dependency_type": f"{service["name"].split("/")[-1].lower()}-{service["dependency_type"]}",
                        
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
                        "services_ok": stats["services_ok"],
                        "requires_manual_setup": stats["requires_manual_setup"],
                    })
            except Exception as e: print(cve, wsm, f"does not exist\t({e})")
    print("="*10 + "END ERROR MESSAGES" + "="*10 + "\n"*3)
            
    df = pd.DataFrame(df)

    print("Most Common Services")
    print(df['service_name'].value_counts())

    print("\n\n\nMost Common Dependency Types")
    print(df['service_dependency_type'].value_counts())
        
    print("\n\n\nMost Common (Service, Dependency Type) Combinations")
    print(df['service_name_dependency_type'].value_counts())
        
    grouped_df = df.groupby("service_dependency_type")
    for dep_type, group in grouped_df:
        print(f"\n\n\nMost Common Services for Dependency Type '{dep_type}' (total={len(group)})")
        print(group['service_name'].value_counts())   

    # Most frequently Used Services by Web Search Mode
    # barh_service_wsm(df, unique_services)
    
    # Group by feature and compute mean & std
    # barh_mean_std(df, feature="web_search_mode")    #! Use either 'service_name' or 'web_search_mode'
    
    return df
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# df = services_stats(
#     cve_list=cve_list, 
#     model="GPT-4o", 
#     logs_set="5th", 
#     iteration="", 
#     web_search_mode="",
#     filtered_milestones=True,
# )


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


#* VULNERABILITY ASSESSMENT RELATED STATS *#
def vuln_ass_stats(df):
    # Ensure that 'df' contains only the runs that produced a working Docker
    display(df)
    print(df.mean(numeric_only=True))

    docker_ok_cves = set()
    static_cves = set()
    dynamic_cves = set()
    stat_dyn_cves = set()
    for index in range(0, len(df)):
        row = df.iloc[index]
        docker_ok_cves.add(row["cve"])
        if row["docker_scout_vulnerable"]:
            static_cves.add(row["cve"])
        if row["exploitable"]:
            dynamic_cves.add(row["cve"])
        if row["static_and_dynamic_va"]:
            stat_dyn_cves.add(row["cve"])

    print("\n\n\n")
    print(f"CVEs Docker OK ({len(docker_ok_cves)})\n{sorted(docker_ok_cves)}\n\n\n")
    print(f"CVEs Static VA ({len(static_cves)})\n{sorted(static_cves)}\n\n\n")
    print(f"CVEs Dynamic VA ({len(dynamic_cves)})\n{sorted(dynamic_cves)}\n\n\n")
    print(f"CVEs Static + Dynamic VA ({len(stat_dyn_cves)})\n{sorted(stat_dyn_cves)}\n\n\n")
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# df = vuln_ass_stats(get_data(
#     cve_list=cve_list, 
#     model="gpt-oss-120b",
#     logs_set="1st", 
#     iteration="", 
#     web_search_mode="all-openai",
#     correct_web_search_only=False,
#     correct_docker_only=True,
#     include_twwsr_data=False,
# ))


#* HORIZONTAL BAR PLOT FOR BEST RUN OF EACH CVE *#
def best_cve_runs(model: str, logs_set: str, iteration: str, mode: str):
    print(f"model: {model}, logs_set: {logs_set}, iteration: {iteration if iteration else "none"}, mode: {mode if mode else "all"}")
    if mode == "all":
        df = pd.concat([
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='custom'), 
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='custom_no_tool'), 
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='openai'),
        ])
    elif mode == "all-openai":
        df = pd.concat([
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='custom'), 
            get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode='custom_no_tool'), 
        ])
    else:
        df = get_cve_df(model=model, iteration=iteration, logs_set=logs_set, mode=mode)
    
    grouped_df = df.drop(columns='web_search_mode', axis=1).groupby('cve_id')

    best_cve_run = {}
    for cve, group in grouped_df:
        best_result = 0
        for index, row in group.iterrows():
            result = 0
            milestones = row.iloc[1:]
            for m, val in milestones.items():
                if val:
                    result += 1
                else:
                    break

            if result > best_result:
                best_result = result
        best_cve_run[cve] = best_result

    milestone_list = df.columns[1:].tolist()
    milestone_list[0] = ""

    # Prints the graph ordered by best run
    # print("Sorted by best results")
    # cves, values = zip(*sorted(best_cve_run.items(), key=lambda x:x[1]))
    # colors = ['royalblue', 'orange', 'purple']
    # plt.figure(figsize=(len(milestone_list) - 2, len(best_cve_run)/2))
    # 
    # for cve, val in zip(cves, values):
    #     start = 0
    # 
    #     # First segment: up to min(val, 4)
    #     seg1 = min(val, 1) - start
    #     if seg1 > 0:
    #         plt.barh(cve, seg1, left=start, color=colors[0])
    #         start += seg1
    # 
    #     # Second segment: from 4 to min(val, 7)
    #     seg2 = min(val, 4) - start
    #     if seg2 > 0:
    #         plt.barh(cve, seg2, left=start, color=colors[1])
    #         start += seg2
    # 
    #     # Third segment: from 7 to val (max 8)
    #     seg3 = val - start
    #     if seg3 > 0:
    #         plt.barh(cve, seg3, left=start, color=colors[2])
    # 
    # plt.yticks(fontsize=10)
    # plt.xticks(range(len(milestone_list)), milestone_list, rotation=30)
    # plt.xlabel("Milestones")
    # plt.ylabel("CVE-ID")
    # plt.title("Best run for each CVE")
    # plt.tight_layout()
    # plt.grid(axis='x')
    # plt.show()
    
    
    # Prints the graph ordered by CVE-ID
    print("Sorted by CVE-ID")
    cves, values = zip(*sorted(best_cve_run.items(), key=lambda x:x[0]))
    colors = ['royalblue', 'orange', 'purple']
    plt.figure(figsize=(len(milestone_list) - 2, len(best_cve_run)/2))

    for cve, val in zip(cves, values):
        start = 0

        # First segment: up to min(val, 4)
        seg1 = min(val, 1) - start
        if seg1 > 0:
            plt.barh(cve, seg1, left=start, color=colors[0])
            start += seg1

        # Second segment: from 4 to min(val, 7)
        seg2 = min(val, 4) - start
        if seg2 > 0:
            plt.barh(cve, seg2, left=start, color=colors[1])
            start += seg2

        # Third segment: from 7 to val (max 8)
        seg3 = val - start
        if seg3 > 0:
            plt.barh(cve, seg3, left=start, color=colors[2])

    plt.yticks(fontsize=10)
    plt.xticks(range(len(milestone_list)), milestone_list, rotation=30)
    plt.xlabel("Milestones")
    plt.ylabel("CVE-ID")
    plt.title("Best run for each CVE")
    plt.tight_layout()
    plt.grid(axis='x')
    plt.show()
# best_cve_runs(model="GPT-5", logs_set="3rd", iteration="", mode="all")     # Use mode="all" to consider all web search modes, mode="all-openai" to exclude the "openai" web search mode
    

def bar_plot(data: dict, models_logs_sets: list, ylim: int, wsm: str):
    x = np.arange(len(models_logs_sets))  # the label locations
    width = 0.25  # the width of the bars
    multiplier = 0

    colors = ["green", "orange", "purple"]
    fig, ax = plt.subplots(layout='constrained')

    for (attribute, measurement), color in zip(data.items(), colors):
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute, color=color)
        ax.bar_label(rects, padding=len(models_logs_sets))
        multiplier += 1

    # Add some text for labels, title and custom x-axis tick labels, etc.
    title = "Model Performance Comparison"
    if wsm is not None: title += f" ('{wsm}' Web Search Mode)"
    ax.set_ylabel('Number of runs')
    ax.set_title(title)
    ax.set_xticks(x + width, models_logs_sets)
    ax.legend(loc='upper left', ncols=1)
    ax.set_ylim(0, ylim)
    
    plt.show()


#* BAR PLOT TO VISUALIZE MODEL ALL-RUN PERFORMANCE *#
def all_run_comparison(cve_list: list, models: tuple, logs_sets: tuple, web_search_modes: tuple, include_twwsr_data: tuple):
    total_runs, correct_web_search_runs, working_docker_runs, models_logs_sets = [], [], [], []
    for model, logs_set, wsm, twwsr in zip(models, logs_sets, web_search_modes, include_twwsr_data):
        print(model, logs_set)
        total_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=False,
            include_twwsr_data=twwsr,
        )))
        correct_web_search_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=True,
            correct_docker_only=False,
            include_twwsr_data=twwsr,
        )))
        working_docker_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=True,
            include_twwsr_data=twwsr,
        )))
        models_logs_sets.append(f"{model} ({logs_set}-BS)")
    data = {
        "Total Runs": total_runs,
        "Correct Web Search Runs": correct_web_search_runs,
        "Working Docker Runs": working_docker_runs,
    }
    bar_plot(
      data=data, 
      models_logs_sets=models_logs_sets, 
      ylim=90, 
      wsm=None,
    )
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "GPT-4o", "GPT-5")
# logs_sets = ("1st", "5th", "3rd")
# web_search_modes = ("all-openai", "all", "all")
# include_twwsr_data = (False, False, False)
# all_run_comparison(cve_list=cve_list, models=models, logs_sets=logs_sets, web_search_modes=web_search_modes, include_twwsr_data=include_twwsr_data)
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("GPT-4o", "GPT-4o", "GPT-4o")
# logs_sets = ("5th", "6th", "7th")
# web_search_modes = ("all", "all", "all")
# include_twwsr_data = (True, True, True)
# all_run_comparison(cve_list=cve_list, models=models, logs_sets=logs_sets, web_search_modes=web_search_modes, include_twwsr_data=include_twwsr_data)



#* BAR PLOT TO VISUALIZE MODEL PERFORMANCE FOR SPECIFIC WSM *#
def wsm_run_comparison(cve_list: list, models: tuple, logs_sets: tuple, wsm: str, include_twwsr_data: tuple):
    total_runs, correct_web_search_runs, working_docker_runs, models_logs_sets = [], [], [], []
    for model, logs_set, twwsr in zip(models, logs_sets, include_twwsr_data):
        if wsm == "openai" and model not in ["GPT-4o", "GPT-5"]:
            print("The 'openai' web search mode is supported only by GPT-4o and GPT-5!")
            return
        print(model, logs_set)
        total_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=False,
            include_twwsr_data=twwsr,
        )))
        correct_web_search_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=True,
            correct_docker_only=False,
            include_twwsr_data=twwsr,
        )))
        working_docker_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=True,
            include_twwsr_data=twwsr,
        )))
        models_logs_sets.append(f"{model} ({logs_set}-BS)")
    data = {
        "Total Runs": total_runs,
        "Correct Web Search Runs": correct_web_search_runs,
        "Working Docker Runs": working_docker_runs,
    }
    bar_plot(
        data=data, 
        models_logs_sets=models_logs_sets, 
        ylim=40, 
        wsm=wsm,
    )
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "gpt-oss-120b")
# logs_sets = ("1st", "2nd")
# include_twwsr_data = (False, False)
# wsm_run_comparison(cve_list=cve_list, models=models, logs_sets=logs_sets, wsm="custom", include_twwsr_data=include_twwsr_data)
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("GPT-4o", "GPT-4o", "GPT-4o")
# logs_sets = ("5th", "6th", "7th")
# include_twwsr_data = (False, False, False)
# wsm_run_comparison(cve_list=cve_list, models=models, logs_sets=logs_sets, wsm="openai", include_twwsr_data=include_twwsr_data)


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
    
    
#* STACKED BAR PLOT TO VISUALIZE HOW TESTING LOOP ERRORS ARE DISTRIBUTED *#
def all_run_test_loop_errors(cve_list: list, models: tuple, logs_sets: tuple, web_search_modes: tuple, include_twwsr_data: tuple):
    image_build_errors, container_run_errors, not_vuln_version_errors, wrong_network_setup_errors, mean_errors, mean_test_iterations, models_logs_sets = [], [], [], [], [], [], []
    for model, logs_set, wsm, twwsr in zip(models, logs_sets, web_search_modes, include_twwsr_data):
        print(model, logs_set)
        df = get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=False,
            include_twwsr_data=twwsr,
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
        models_logs_sets.append(f"{model} ({logs_set}-BS)")

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
      models_logs_sets=models_logs_sets,
      wsm=None,
    )
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "GPT-4o", "GPT-5")
# logs_sets = ("1st", "5th", "3rd")
# web_search_modes = ("all-openai", "all", "all")
# include_twwsr_data = (False, False, False)
# all_run_test_loop_errors(cve_list=cve_list, models=models, logs_sets=logs_sets, web_search_modes=web_search_modes, include_twwsr_data=include_twwsr_data)
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("GPT-4o", "GPT-4o", "GPT-4o")
# logs_sets = ("5th", "6th", "7th")
# web_search_modes = ("all", "all", "all")
# include_twwsr_data = (True, True, True)
# all_run_test_loop_errors(cve_list=cve_list, models=models, logs_sets=logs_sets, web_search_modes=web_search_modes, include_twwsr_data=include_twwsr_data)


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
        file_name = f"./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
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
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# logs_sets = ["5th", "6th", "7th"]
# wsm_performance_graph(cve_list=cve_list, model="GPT-4o", logs_sets=logs_sets)


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
        file_name = f"./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
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
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# logs_sets = ["5th", "6th", "7th"]
# wsm_consistency_graph(cve_list=cve_list, model="GPT-4o", logs_sets=logs_sets)


#* Chose one model and various benchmark logs set of that model, the output will show a stacked bar plot considering all WSMs
#* For each CVE there are two bars:
#* First is the number of runs with OK Web Search
#* Second is the number of runs with OK Docker *#
def cve_consistency_graph(cve_list: list, model: str, logs_sets: list, horizontal: bool):
    df = []
    if model in ["GPT-4o", "GPT-5"]:
        modes = ["custom", "custom_no_tool", "openai"]
    else:
        modes = ["custom", "custom_no_tool"]
    
    print("="*10 + "START ERROR MESSAGES" + "="*10)
    for logs_set in logs_sets:
        file_name = f"./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
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
        ws_colors = ["#FF1744", "#00E5FF", "#FFEA00"]
        for (label, values), color in zip(cves_ok_ws_data.items(), ws_colors):
            p = ax.barh(y, values, height, label=label, left=left, color=color)
            left += values

        left = np.zeros(len(sorted_cve_list))
        # Docker colors - deep, saturated tones
        docker_colors = ["#D50000", "#00B8D4", "#FFD600"]
        for (label, values), color in zip(cves_ok_docker_data.items(), docker_colors):
            p = ax.barh(y + height, values, height, label=label, left=left, color=color)
            left += values

        ax.set_xlabel("Number of Runs")
        ax.set_title(f"CVE Consistency across All Runs")
        ax.set_yticks(y + height / 2, sorted_cve_list)
        ax.legend(loc='upper left', bbox_to_anchor=(1.01, 1.0), borderaxespad=0)
        ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.grid(axis='x', alpha=0.33, linewidth=1, color='black')
        plt.tight_layout()
        plt.show()
    else:
        x = np.arange(len(cve_list))
        width = 0.33
        fig, ax = plt.subplots(figsize=(15, 4))
        bottom = np.zeros(len(cve_list))
        colors = ["#FF1744", "#00E5FF", "#FFEA00"]
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
        colors = ["#D50000", "#00B8D4", "#FFD600"]
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
        ax.set_xticks(x + width / 2, cve_list, rotation=45)
        # ax.legend(loc='upper left', ncols=1)
        ax.legend(loc='upper left', bbox_to_anchor=(1.01, 1), borderaxespad=0)
        # ax.set_ylim(0, ylim)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.grid(axis='y', alpha=0.33, linewidth=1, color='black')
        plt.show()
    
    return df
# with builtins.open('./../services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# logs_sets = ["5th", "6th", "7th"]
# cve_consistency_graph(cve_list=cve_list, model="GPT-4o", logs_sets=logs_sets, horizontal=False)
