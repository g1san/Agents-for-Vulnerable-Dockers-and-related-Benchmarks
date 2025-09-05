"""Run the agent by providing it with a CVE ID."""
import math
import json
import builtins
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import Image, display
from langchain_core.messages import SystemMessage

# My modules
from configuration import langfuse_handler, WebSearchResult, CodeGenerationResult, Milestones
from prompts import SYSTEM_PROMPT
from graph import compiled_workflow

def draw_graph():
    try:
        display(Image(compiled_workflow.get_graph().draw_mermaid_png(output_file_path="Mermaid Chart.png")))
        
    except Exception as e:
        print(f"Rendering failed with code {e}.\nHere's the Mermaid source:\n{compiled_workflow.get_graph().draw_mermaid()}")

    
def benchmark_web_search(web_search_mode: str):
    try:
        filename = 'services.json'
        with builtins.open(filename, "r") as f:
            jsonServices = json.load(f)
            
        milestone_file = f'./../../dockers/{web_search_mode}-milestones.json'
        cve_list = list(jsonServices.keys())[:20]   # Limit to first 20 CVEs for benchmarking
        milestones = {}
        for cve in cve_list:
            result = compiled_workflow.invoke(
                input={
                    "cve_id": cve,
                    "web_search_tool": web_search_mode,
                    "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                    "debug": "benchmark_web_search"
                },
                config={"callbacks": [langfuse_handler], "recursion_limit": 100},
            )
            milestones[cve] = dict(result['milestones'])
            with builtins.open(milestone_file, "w") as f:
                json.dump(milestones, f, indent=4)
                
        return milestones

    except Exception as e:
        print(f"Workflow invocation failed: {e}.")
    
    
def benchmark_web_search_from_logs(web_search_mode: str):
    try:
        filename = 'services.json'
        with builtins.open(filename, "r") as f:
            jsonServices = json.load(f)
            
        milestone_file = f'./../../dockers/{web_search_mode}-milestones.json'
        cve_list = list(jsonServices.keys())[:20]   # Limit to first 20 CVEs for benchmarking
        milestones = {}
        for cve in cve_list:
            with builtins.open(f'./../dockers/{cve}/logs/{cve}_web_search_{web_search_mode}.json', 'r') as f:
                web_search_data = json.load(f)
            
            result = compiled_workflow.invoke(
                input={
                    "cve_id": cve,
                    "web_search_tool": "skip",
                    "web_search_result": WebSearchResult(
                        desc=web_search_data['desc'], 
                        attack_type=web_search_data['attack_type'], 
                        services=web_search_data['services'], 
                        service_vers=web_search_data['service_vers'], 
                        service_type=web_search_data['service_type'], 
                        service_desc=web_search_data['service_desc']
                    ),
                    "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                    "debug": "benchmark_web_search"
                },
                config={"callbacks": [langfuse_handler], "recursion_limit": 100},
            )
            
            milestones[cve] = dict(result['milestones'])
            with builtins.open(milestone_file, "w") as f:
                json.dump(milestones, f, indent=4)
                
        return milestones

    except Exception as e:
        print(f"Workflow invocation failed: {e}.")


def benchmark_code_from_logs(web_search_mode: str):
    try:
        with builtins.open('services.json', "r") as f:
            jsonServices = json.load(f)
            
        cve_list = list(jsonServices.keys())[:20]   # Limit to first 20 CVEs for benchmarking
        for cve in cve_list:
            with builtins.open(f'./../../dockers/{cve}/logs/{cve}_web_search_{web_search_mode}.json', 'r') as f:
                web_search_data = json.load(f)

            with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'r') as f:
                milestones = json.load(f)
            
            result = compiled_workflow.invoke(
                input={
                    "cve_id": cve,
                    "web_search_tool": web_search_mode,
                    "web_search_result": web_search_data,
                    "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                    "milestones": milestones[cve],
                    "debug": "benchmark_code"
                },
                config={"callbacks": [langfuse_handler], "recursion_limit": 100},
            )
            
            # Append new milestones to JSON file
            with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'w') as f:
                milestones[cve] = dict(result['milestones'])
                json.dump(milestones, f, indent=4)

        return milestones

    except Exception as e:
        print(f"Workflow invocation failed: {e}.")


def test_workflow():
    try:
        cve = "CVE-2021-28164"  #   CVE-2021-28164    CVE-2022-46169    CVE-2024-23897
        web_search_mode = "custom"
        
        with builtins.open(f'./../../dockers/{cve}/logs/{cve}_web_search_{web_search_mode}.json', 'r') as f:
            web_search_data = json.load(f)
        
        with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'r') as f:
            milestones = json.load(f)
        
        result = compiled_workflow.invoke(
            input={
                "cve_id": cve,
                "web_search_tool": web_search_mode,
                "web_search_result": web_search_data,
                # "code": CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
                "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                "milestones": milestones[cve],
                "debug": "benchmark_code"
            },
            config={"callbacks": [langfuse_handler], "recursion_limit": 100},
        )
                
        return result
    except Exception as e:
        print(f"Workflow invocation failed: {e}.")


def generate_excel_csv():
    # CVE identifiers
    with builtins.open('services.json', "r") as f:
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
            with builtins.open(f'./../../dockers/{cve}/logs/{cve}_web_search_{mode}.json', 'r') as f:
                web_search_data = json.load(f)
                
            # Query value
            if mode == 'custom_no_tool':
                query_values.append(cve)
            elif mode == 'custom':
                query_values.append(web_search_data['query'])
            elif mode == 'openai':
                query_values.append("")
                
            number_of_services.append(len(set(web_search_data['services'])))    # Number of services
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
                
            with builtins.open(f'./../../dockers/{cve}/{mode}/logs/{cve}_{mode}_code_stats.json', 'r') as f:
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


def extract_milestones_stats(logs_set: str):    
    data = {}
    web_search_modes = ['custom_no_tool', 'custom', 'openai']
    for mode in web_search_modes:
        data[mode] = {}
        with builtins.open(f'./../../benchmark_logs/{logs_set}-benchmark-session/milestones-after-analysis/{mode}-milestones.json', 'r') as f:
            mode_milestones = json.load(f)
            
        milestones = list(next(iter(mode_milestones.values())).keys())

        for m in milestones:
            data[mode][m] = [1 if mode_milestones[cve][m] else 0 for cve in mode_milestones].count(1) * 100 /len(mode_milestones)
         
    return data  


def get_cve_df(logs_set: str):
    # CVE identifiers
    with builtins.open('services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[:20]
    
    data = []
    web_search_modes = ['custom_no_tool', 'custom', 'openai']
    for cve in cve_list:
        for mode in web_search_modes:
            cve_data = {}
            cve_data['cve_id'] = cve
            cve_data['web_search_mode'] = mode
            
            with builtins.open(f'./../../benchmark_logs/{logs_set}-benchmark-session/milestones-after-analysis/{mode}-milestones.json', 'r') as f:
                mode_milestones = json.load(f)

            for milestone, value in mode_milestones[cve].items():
                if milestone != 'exploitable':
                    cve_data[milestone] = True if value else False
            
            data.append(cve_data)

    # Create DataFrame
    df = pd.DataFrame(data)
    return df 
        
            
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


def compute_some_stats():
    df = pd.concat([get_cve_df(logs_set="1st"), get_cve_df(logs_set="2nd")])
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
    
    # df.groupby(['cve_id'])


def best_cve_runs():
    # df = pd.concat([get_cve_df(logs_set="1st"), get_cve_df(logs_set="2nd")])
    df = get_cve_df(logs_set="2nd")
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

    sorted(best_cve_run.items(), key=lambda x:x[1])
    milestone_list = df.columns[1:].tolist()
    milestone_list[0] = ""
    milestone_list

    cves, values = zip(*sorted(best_cve_run.items(), key=lambda x:x[1]))
    colors = ['orange', 'purple', 'yellow']
    # Plot
    plt.figure(figsize=(8, 10))

    for cve, val in zip(cves, values):
        start = 0

        # First segment: up to min(val, 4)
        seg1 = min(val, 4) - start
        if seg1 > 0:
            plt.barh(cve, seg1, left=start, color=colors[0])
            start += seg1

        # Second segment: from 4 to min(val, 7)
        seg2 = min(val, 7) - start
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


def test_docker_scout():
    #! Isolate all nodes except the "test_docker" one before running this (check "graph.py") !#
    try:
        with builtins.open('services.json', "r") as f:
            jsonServices = json.load(f)
        
        modes = ['custom_no_tool', 'custom', 'openai']          
        cve_list = list(jsonServices.keys())[:20]   # Limit to first 20 CVEs for benchmarking

        for web_search_mode in modes:
            with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'r') as f:
                og_milestones = json.load(f)
                
            for cve in cve_list:
                cve_milestones = og_milestones[cve]
                if not cve_milestones['docker_runs']:
                    continue
                
                with builtins.open(f'./../../dockers/{cve}/logs/{cve}_web_search_{web_search_mode}.json', 'r') as f:
                    web_search_data = json.load(f)

                print(f"[{cve}][{web_search_mode}] Starting test...")
                result = compiled_workflow.invoke(
                    input={
                        "cve_id": cve,
                        "web_search_tool": web_search_mode,
                        "web_search_result": web_search_data,
                        "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                        "milestones": cve_milestones,
                        "debug": "benchmark_code"
                    },
                    config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                )

                new_milestones = dict(result['milestones'])
                for milestone, og, new in zip(cve_milestones.keys(), cve_milestones.values(), new_milestones.values()):
                    print(f"\t[{cve}][{web_search_mode}] '{milestone}': {og} --> {new}.")
                print(f"[{cve}][{web_search_mode}] Ending test...\n\n\n")
            
    except Exception as e:
        print(f"Workflow invocation failed: {e}.")
        
        
def recompute_milestones():
    #! Isolate all nodes except the "test_docker" one before running this (check "graph.py") !#
    try:
        with builtins.open('services.json', "r") as f:
            jsonServices = json.load(f)
        
        modes = ['custom_no_tool', 'custom', 'openai']
        cve_list = list(jsonServices.keys())[:20]   # Limit to first 20 CVEs for benchmarking
        for web_search_mode in modes:
            milestones = {}
            with builtins.open(f'./../../dockers/milestones-after-analysis/{web_search_mode}-milestones.json', 'r') as f:
                og_milestones = json.load(f)
                
            for cve in cve_list:
                cve_milestones = og_milestones[cve].copy()
                if not cve_milestones['docker_runs']:
                    with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'w') as f:
                        milestones[cve] = cve_milestones
                        json.dump(milestones, f, indent=4)
                    continue
                
                cve_milestones['services_ok'] = False
                cve_milestones['code_main_version'] = False
                cve_milestones['docker_vulnerable'] = False
                
                with builtins.open(f'./../../dockers/{cve}/logs/{cve}_web_search_{web_search_mode}.json', 'r') as f:
                    web_search_data = json.load(f)

                print(f"[{cve}][{web_search_mode}] Starting test...")
                result = compiled_workflow.invoke(
                    input={
                        "cve_id": cve,
                        "web_search_tool": web_search_mode,
                        "web_search_result": web_search_data,
                        "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                        "milestones": cve_milestones,
                        "debug": "benchmark_code"
                    },
                    config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                )

                new_milestones = dict(result['milestones'])
                for milestone, og, new in zip(og_milestones[cve].keys(), og_milestones[cve].values(), new_milestones.values()):
                    if og != new:
                        print(f"\t[{cve}][{web_search_mode}] '{milestone}': {og} --> {new}.")
                print(f"[{cve}][{web_search_mode}] Ending test...\n\n\n")
                
                # Append new milestones to JSON file
                with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'w') as f:
                    milestones[cve] = dict(result['milestones'])
                    json.dump(milestones, f, indent=4)
            
    except Exception as e:
        print(f"Workflow invocation failed: {e}.")
        

# draw_graph()
# result = test_workflow()
# milestones = benchmark_web_search("custom_no_tool")
# milestones = benchmark_web_search_from_logs("custom_no_tool")
# milestones = benchmark_code_from_logs("openai")
# df = generate_excel_csv()
# data = extract_milestones_stats(logs_set="2nd")
# compute_some_stats()
# best_cve_runs()
# test_docker_scout()
# recompute_milestones()    
