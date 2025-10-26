"""Run the agent by providing it with a CVE ID."""
import math
import json
import builtins
import subprocess
import numpy as np
import pandas as pd
from pathlib import Path
import matplotlib.pyplot as plt
from IPython.display import Image, display
from langchain_core.messages import SystemMessage

# My modules
from configuration import langfuse_handler
from prompts import SYSTEM_PROMPT
from graph import compiled_workflow


def down_docker(code_dir_path):
    # Ensure Docker is down and containers and volumes are removed
    subprocess.run(
        ["sudo", "docker", "compose", "down", "--volumes"],
        cwd=code_dir_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def remove_all_images():
    image_ids = subprocess.check_output(["docker", "images", "-aq"]).decode().split()

    if image_ids:
        subprocess.run(
            ["docker", "rmi", "-f"] + image_ids,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )


#* DRAW AGENTIC WORKFLOW GRAPH USING MERMAID CHART *#
def draw_graph():
    try:
        # print(compiled_workflow.get_graph().draw_mermaid())
        display(Image(compiled_workflow.get_graph().draw_mermaid_png(output_file_path="Mermaid Chart.png")))
        
    except Exception as e:
        print(f"Rendering failed with code {e}.\nHere's the Mermaid source:\n{compiled_workflow.get_graph().draw_mermaid()}")
# draw_graph()


#* GENERATE THE '{wsm}-milestones.json' FILE OUT OF ALL DOCKERS IN THE 'docker' FOLDER *#
def milestone_file(web_search_mode: str):
    try:
        with builtins.open('services.json', "r") as f:
            jsonServices = json.load(f)
            
        milestones = {}
        cve_list = list(jsonServices.keys())[:20]   # Limit to first 20 CVEs for benchmarking
        for cve in cve_list:
            with builtins.open(f'./../../dockers/{cve}/{web_search_mode}/logs/milestones.json', 'r') as f:
                milestone_data = json.load(f)
                
            milestones[cve] = milestone_data
        
        with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'w') as f:
            json.dump(milestones, f, indent=4)
        return milestones

    except Exception as e:
        print(f"Workflow invocation failed: {e}.")
# milestones = milestone_file("custom")
# milestones = milestone_file("custom_no_tool")
# milestones = milestone_file("openai")


#* TEST THE DOCKERS IN THE 'docker' FOLDER *#
def assess_dockers(cve_list: list[str], model_name: str, model_docker_name: str, logs_set: str, web_search_mode: str):
    if web_search_mode == "all": web_search_mode = ["custom", "custom_no_tool", "openai"]
    else: web_search_mode = [f"{web_search_mode}"]
    
    for wsm in web_search_mode:
        for cve in cve_list: 
            logs_path = Path(f"./../../benchmark_logs/{model_docker_name}/{logs_set}-benchmark-session/{cve}/{wsm}/logs/")
            with builtins.open(logs_path / 'milestones.json', 'r') as f:
                milestones = json.load(f)

            with builtins.open(logs_path / 'web_search_results.json', 'r') as f:
                web_search_data = json.load(f)
                
            if milestones["docker_builds"] and milestones["docker_runs"] and milestones["code_hard_version"]:
                with builtins.open(logs_path / 'code.json', 'r') as f:
                    code_data = json.load(f)

                with builtins.open(logs_path / 'stats.json', 'r') as f:
                    stats = json.load(f)

                try:
                    result = compiled_workflow.invoke(
                        input={
                            "model_name": model_name,
                            "cve_id": cve,
                            "web_search_tool": wsm,
                            "verbose_web_search": False,
                            "web_search_result": web_search_data,
                            "code": code_data,
                            "messages": [SystemMessage(content=SYSTEM_PROMPT)]
                        },
                        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                    )

                    if stats["docker_scout_vulnerable"] != result["stats"].docker_scout_vulnerable:
                        print(f"{cve} 'docker_scout_vulnerable' {stats["docker_scout_vulnerable"]} --> {result["stats"].docker_scout_vulnerable}")

                except Exception as e:
                    code_dir_path = Path(f"./../../dockers/{cve}/{wsm}/")
                    down_docker(code_dir_path=code_dir_path)
                    remove_all_images()
                    print(f"\n\n===== [AGENTIC WORKFLOW FAILED] =====\n{e}\n"+"="*37+"\n\n")
                    continue          
            else:
                continue

            for m, val in result["milestones"]:
                if val != milestones[m]:
                    print(f"{cve} '{m}' {milestones[m]} --> {val}")
            print("\n\n\n")
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# print(len(cve_list), cve_list)
# df = assess_dockers(
#     cve_list=cve_list,
#     model_name="gpt-4o",
#     model_docker_name="GPT-4o",
#     logs_set="5th",
#     web_search_mode="all",
# )


#* RUN AGENT *#
def run_agent(cve_list: list[str], web_search_mode: str, model_name: str, verbose_web_search: bool, reuse_web_search: bool, reuse_web_search_and_code: bool):
        if web_search_mode == "all": web_search_mode = ["custom", "custom_no_tool", "openai"]
        elif web_search_mode == "all-openai": web_search_mode = ["custom", "custom_no_tool"]
        else: web_search_mode = [f"{web_search_mode}"]
        
        for wsm in web_search_mode:        
            for cve in cve_list:                
                if reuse_web_search or reuse_web_search_and_code:
                    with builtins.open(f'./../../dockers/{cve}/{wsm}/logs/web_search_results.json', 'r') as f:
                        web_search_data = json.load(f)
                    if reuse_web_search_and_code:
                        with builtins.open(f'./../../dockers/{cve}/{wsm}/logs/code.json', 'r') as f:
                            code_data = json.load(f)
                
                #! Uncomment this to reuse the web_search_results file from the 'benchmark_logs' folder !#
                # with builtins.open(f'./../../benchmark_logs/GPT-4o/5th-benchmark-session/{cve}/{wsm}/logs/web_search_results.json', 'r') as f:   
                #     web_search_data = json.load(f)
                # logs_dir_path = Path(f"./../../dockers/{cve}/{wsm}/logs")
                # logs_dir_path.mkdir(parents=True, exist_ok=True)
                # web_search_file = logs_dir_path / 'web_search_results.json'
                # with builtins.open(web_search_file, 'w') as fp:
                #     json.dump(web_search_data, fp, indent=4)    

                try:
                    if reuse_web_search:
                        result = compiled_workflow.invoke(
                            input={              
                                "model_name": model_name,
                                "cve_id": cve,
                                "web_search_tool": wsm,
                                "verbose_web_search": verbose_web_search,
                                "web_search_result": web_search_data,
                                "messages": [SystemMessage(content=SYSTEM_PROMPT)]
                            },
                            config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                        )
                    elif reuse_web_search_and_code:
                        result = compiled_workflow.invoke(
                            input={             
                                "model_name": model_name,
                                "cve_id": cve,
                                "web_search_tool": wsm,
                                "verbose_web_search": verbose_web_search,
                                "web_search_result": web_search_data,
                                "code": code_data,
                                "messages": [SystemMessage(content=SYSTEM_PROMPT)]
                            },
                            config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                        )
                    else:
                        result = compiled_workflow.invoke(
                            input={             
                                "model_name": model_name,
                                "cve_id": cve,
                                "web_search_tool": wsm,
                                "verbose_web_search": verbose_web_search,
                                "messages": [SystemMessage(content=SYSTEM_PROMPT)]
                            },
                            config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                        )

                    if len(cve_list) == 1 and len(web_search_mode) == 1:
                        return result
                except Exception as e:
                    code_dir_path = Path(f"./../../dockers/{cve}/{wsm}/")
                    down_docker(code_dir_path=code_dir_path)
                    remove_all_images()
                    print(f"\n\n===== [AGENTIC WORKFLOW FAILED] =====\n{e}\n"+"="*37+"\n\n")
                    continue      
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# print(len(cve_list), cve_list)
# result = run_agent(
#     cve_list=cve_list,
#     web_search_mode="all-openai",
#     model_name="gpt-oss:120b",                #* Models supported: 'gpt-4o','gpt-5','mistralai/Mistral-7B-Instruct-v0.1', 'gpt-oss-20b', 'gpt-oss-120b' *#
#     verbose_web_search=False,
#     reuse_web_search=False,
#     reuse_web_search_and_code=False,
# )


#* TEST THE DOCKERS IN THE 'docker' FOLDER *#
def test_wrong_web_search(cve_list: list[str], model_name: str, model_docker_name: str, logs_set: str, web_search_mode: str):
    if web_search_mode == "all": web_search_mode = ["custom", "custom_no_tool", "openai"]
    else: web_search_mode = [f"{web_search_mode}"]
    ok_dockers, new_ok_dockers = 0, 0
    
    for wsm in web_search_mode:
        for cve in cve_list: 
            logs_path = Path(f"./../../benchmark_logs/{model_docker_name}/{logs_set}-benchmark-session/{cve}/{wsm}/logs/")
            with builtins.open(logs_path / 'milestones.json', 'r') as f:
                milestones = json.load(f)

            with builtins.open(logs_path / 'web_search_results.json', 'r') as f:
                web_search_data = json.load(f)
                
            if milestones["docker_builds"] and milestones["docker_runs"] and milestones["code_hard_version"] and milestones["network_setup"]: ok_dockers += 1
            
            elif not milestones["hard_service"] or not milestones["hard_version"] or not milestones["soft_services"]:
                try:
                    result = compiled_workflow.invoke(
                        input={
                            "model_name": model_name,
                            "cve_id": cve,
                            "web_search_tool": wsm,
                            "verbose_web_search": False,
                            "web_search_result": web_search_data,
                            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                            "debug": "relax-web-search-constraints"
                        },
                        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                    )
                    if result["milestones"].docker_builds and result["milestones"].docker_runs and result["milestones"].code_hard_version and result["milestones"].network_setup: new_ok_dockers += 1
                        
                except Exception as e:
                    code_dir_path = Path(f"./../../dockers/{cve}/{wsm}/")
                    down_docker(code_dir_path=code_dir_path)
                    remove_all_images()
                    print(f"\n\n===== [AGENTIC WORKFLOW FAILED] =====\n{e}\n"+"="*37+"\n\n")
                    continue 
            
            else:
                continue
            print("\n\n\n")
            
    print(f"Docker already ok: {ok_dockers}\nNew Dockers ok: {new_ok_dockers}\n\n\n\n\n")
with builtins.open('services.json', "r") as f:
    jsonServices = json.load(f)
cve_list = list(jsonServices.keys())[:20]
print(len(cve_list), cve_list)
df = test_wrong_web_search(
    cve_list=cve_list,
    model_name="gpt-4o",
    model_docker_name="GPT-4o",
    logs_set="5th",
    web_search_mode="all",
)


#* GENERATE THE '{wsm}-benchmark.xlsx' and '{wsm}-benchmark.csv' FILEs *#
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
    main_path = Path(f"./../../benchmark_logs/{model}/{logs_set}-benchmark-session/")
    
    with builtins.open('services.json', "r") as f:
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
    with builtins.open('services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[:20]
    
    data = []
    for cve in cve_list:
        cve_data = {}
        cve_data['cve_id'] = cve
        cve_data['web_search_mode'] = mode
        
        if iteration != "":
            with builtins.open(f'./../../benchmark_logs/{model}/{logs_set}-benchmark-session/{iteration}-iteration/{mode}-milestones.json', 'r') as f:
                mode_milestones = json.load(f)
        else:
            with builtins.open(f'./../../benchmark_logs/{model}/{logs_set}-benchmark-session/{mode}-milestones.json', 'r') as f:
                mode_milestones = json.load(f)

        for milestone, value in mode_milestones[cve].items():
            if milestone != 'exploitable':
                cve_data[milestone] = True if value else False
        
        data.append(cve_data)

    # Create DataFrame
    df = pd.DataFrame(data)
    return df 


#* PRINT MILESTONE RELATED STATS *#
def extract_milestones_stats(model: str, logs_set: str, mode: str):    
    data = {}
    with builtins.open(f'./../../benchmark_logs/{model}/{logs_set}-benchmark-session/{mode}-milestones.json', 'r') as f:
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
    file_name = f"./../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
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
# with builtins.open('services.json', "r") as f:
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


def get_data(cve_list: list[str], model: str, logs_set: str, iteration: str, web_search_mode: str, correct_web_search_only: bool, correct_docker_only: bool):
    file_name = f"./../../benchmark_logs/{model}/{logs_set}-benchmark-session/"
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
                
            except Exception as e: print(cve, wsm, f"does not exist\t({e})")
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
# with builtins.open('services.json', "r") as f:
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
    print("Sorted by best results")
    cves, values = zip(*sorted(best_cve_run.items(), key=lambda x:x[1]))
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
    

def bar_plot(data: dict, models: set, ylim: int, wsm: str):
    x = np.arange(len(models))  # the label locations
    width = 0.25  # the width of the bars
    multiplier = 0

    colors = ["green", "orange", "purple"]
    fig, ax = plt.subplots(layout='constrained')

    for (attribute, measurement), color in zip(data.items(), colors):
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute, color=color)
        ax.bar_label(rects, padding=len(models))
        multiplier += 1

    # Add some text for labels, title and custom x-axis tick labels, etc.
    title = "Model Performance Comparison"
    if wsm is not None: title += f" ('{wsm}' Web Search Mode)"
    ax.set_ylabel('Number of runs')
    ax.set_title(title)
    ax.set_xticks(x + width, models)
    ax.legend(loc='upper left', ncols=1)
    ax.set_ylim(0, ylim)
    
    plt.show()


#* BAR PLOT TO VISUALIZE MODEL ALL-RUN PERFORMANCE *#
def all_run_comparison(cve_list: list, models: tuple, logs_sets: tuple, web_search_modes: tuple):
    total_runs, correct_web_search_runs, working_docker_runs = [], [], []
    for model, logs_set, wsm in zip(models, logs_sets, web_search_modes):
        print(model, logs_set)
        total_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=False,
        )))
        correct_web_search_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=True,
            correct_docker_only=False,
        )))
        working_docker_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=True,
        )))
    data = {
        "Total Runs": total_runs,
        "Correct Web Search Runs": correct_web_search_runs,
        "Working Docker Runs": working_docker_runs,
    }
    bar_plot(
      data=data, 
      models=models, 
      ylim=80, 
      wsm=None,
    )
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "GPT-4o", "GPT-5")
# logs_sets = ("1st", "5th", "3rd")
# web_search_modes = ("all-openai", "all", "all")
# all_run_comparison(cve_list=cve_list, models=models, logs_sets=logs_sets, web_search_modes=web_search_modes)


#* BAR PLOT TO VISUALIZE MODEL PERFORMANCE FOR SPECIFIC WSM *#
def wsm_run_comparison(cve_list: list, models: tuple, logs_sets: tuple, wsm: str):
    total_runs, correct_web_search_runs, working_docker_runs = [], [], []
    for model, logs_set in zip(models, logs_sets):
        if wsm == "openai" and model not in ["GPT-4o", "GPT-5"]: continue
        print(model, logs_set)
        total_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=False,
        )))
        correct_web_search_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=True,
            correct_docker_only=False,
        )))
        working_docker_runs.append(len(get_data(
            cve_list=cve_list, 
            model=model, 
            logs_set=logs_set, 
            iteration="", 
            web_search_mode=wsm,
            correct_web_search_only=False,
            correct_docker_only=True,
        )))
    data = {
        "Total Runs": total_runs,
        "Correct Web Search Runs": correct_web_search_runs,
        "Working Docker Runs": working_docker_runs,
    }
    bar_plot(
        data=data, 
        models=models if wsm != "openai" else ("GPT-4o", "GPT-5"), 
        ylim=30, 
        wsm=wsm,
    )
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "GPT-4o", "GPT-5")
# logs_sets = ("1st", "5th", "3rd")
# wsm_run_comparison(cve_list=cve_list, models=models, logs_sets=logs_sets, wsm="openai")


def stacked_bar_plot(data: dict, models: set, wsm: str):
    width = 0.5
    fig, ax = plt.subplots()
    bottom = np.zeros(len(models))
    for boolean, error_count in data.items():
        p = ax.bar(models, error_count, width, label=boolean, bottom=bottom)
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
    ax.legend(loc='center left', bbox_to_anchor=(0.75, 0.75))

    plt.show()
    
    
#* STACKED BAR PLOT TO VISUALIZE HOW TESTING LOOP ERRORS ARE DISTRIBUTED *#
def all_run_test_loop_errors(cve_list: list, models: tuple, logs_sets: tuple, web_search_modes: tuple):
    image_build_errors, container_run_errors, not_vuln_version_errors, wrong_network_setup_errors, mean_errors, mean_test_iterations = [], [], [], [], [], []
    for model, logs_set, wsm in zip(models, logs_sets, web_search_modes):
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
      models=models,
      wsm=None,
    )
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "GPT-4o", "GPT-5")
# logs_sets = ("1st", "5th", "3rd")
# web_search_modes = ("all-openai", "all", "all")
# all_run_test_loop_errors(cve_list=cve_list, models=models, logs_sets=logs_sets, web_search_modes=web_search_modes)


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
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# models = ("gpt-oss-120b", "GPT-4o", "GPT-5")
# logs_sets = ("1st", "5th", "3rd")
# wsm_test_loop_errors(cve_list=cve_list, models=models, logs_sets=logs_sets, wsm="openai")




#! US THIS CODE TO REWRITE SOME DATA !#
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
#         
# cve_list = list(jsonServices.keys())[:19]
# print(len(cve_list), cve_list)
# web_search_mode = "custom_no_tool"
#         
# for cve in cve_list:            
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/milestones.json', 'r') as f:
#         milestones = json.load(f)
#     
#     if not milestones["soft_services"] or not milestones["hard_service"] or not milestones["hard_version"]:
#         print("SKIP", cve, web_search_mode)
#         continue
# 
#     #! Uncomment this to reuse the web_search_results file from the 'docker' folder !#
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/web_search_results.json', 'r') as f:
#         web_search_data = json.load(f)
#     #! Uncomment this to reuse the web_search_results file from the 'benchmark_logs' folder !#
#     # with builtins.open(f'./../../benchmark_logs/GPT-5/1st-benchmark-session/{cve}/{web_search_mode}/logs/web_search_results.json', 'r') as f:   
#     #     web_search_data = json.load(f)
#     # logs_dir_path = Path(f"./../../dockers/{cve}/{web_search_mode}/logs")
#     # logs_dir_path.mkdir(parents=True, exist_ok=True)
#     # web_search_file = logs_dir_path / 'web_search_results.json'
#     # with builtins.open(web_search_file, 'w') as fp:
#     #     json.dump(web_search_data, fp, indent=4)    
# 
#     #! Uncomment this to reuse the code files from the 'docker' folder !#
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/code.json', 'r') as f:
#         code_data = json.load(f)
# 
#     for index, fn in enumerate(code_data["file_name"]):
#         if f"./../../dockers/{cve}/{web_search_mode}" not in code_data["file_name"][index]:
#             code_data["file_name"][index] = f"./../../dockers/{cve}/{web_search_mode}/{fn}"
#     
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/code.json', "w") as f:
#         json.dump(code_data, f, indent=4)
#     
#     print(cve, web_search_mode)