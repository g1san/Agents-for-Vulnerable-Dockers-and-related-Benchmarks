import json
import builtins
import pandas as pd
from pathlib import Path
from IPython.display import display


#* GENERATE THE VALIDATION SET PANDAS DATAFRAME FOR A GIVEN MODEL AND LOGS SET *#
def get_val_set_data(model: str, logs_set: str, add_ablation_results: bool = False):
    main_path = Path(f'./../../../benchmark_logs/{model}/{logs_set}-benchmark-session')
    
    # This is the Validation Set, therefore only the first 20 CVE identifiers are considered
    with builtins.open('./../services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[:20]
    wsm2modeX = {
        'openai': 'OpenAI Search',
        'custom': 'Custom Search',
        'custom_no_tool': 'CVE-based Search',
    }
    
    df = []
    if model == "gpt-oss-120b":
        web_search_modes =['custom', 'custom_no_tool']
    else:
        web_search_modes = ['custom', 'custom_no_tool', 'openai']
    for cve in cve_list:
        for mode in web_search_modes:
            if add_ablation_results and Path(main_path / f'test-wrong-web-search-results/{cve}/{mode}/logs').exists():
                cve_wsm_logs_path = main_path / f'test-wrong-web-search-results/{cve}/{mode}/logs'           
            else:
                cve_wsm_logs_path = main_path / f'{cve}/{mode}/logs'
                     
            entry = {'model': model, 'logs_set': logs_set, 'cve_id': cve, 'web_search_mode': wsm2modeX[mode]}
            
            with builtins.open(cve_wsm_logs_path / 'milestones.json', 'r') as f:
                milestones = json.load(f)

            entry = entry | milestones

            with builtins.open(Path(f'./../../../benchmark_logs/{model}/{logs_set}-benchmark-session/{cve}/{mode}/logs/web_search_results.json'), 'r') as f:
                web_search_results = json.load(f)
                
            entry['attack_type'] = web_search_results['attack_type']
            entry['number_of_services'] = len(web_search_results['services'])
            entry['input_token_values'] = web_search_results['input_tokens']
            entry['output_token_values'] = web_search_results['output_tokens']
            
            # Query value
            if mode == 'custom_no_tool':
                entry['query'] = cve
            elif mode == 'custom':
                entry['query'] = web_search_results['query']
            elif mode == 'openai':
                entry['query'] =  ""

            # Web search cost in dollars
            if model == "GPT-4o":
                input_token_cost = 2.50 / 1000000               # GPT-4o single input token cost
                output_token_cost = 10.00 / 1000000             # GPT-4o single output token cost
                web_search_openai_tool_cost = 25.00 / 1000      # OpenAI web search tool cost for a single call (Non-reasoning model)
            
            elif model == "GPT-5":
                input_token_cost = 1.25 / 1000000               # GPT-5 single input token cost
                output_token_cost = 10.00 / 1000000             # GPT-5 single output token cost
                web_search_openai_tool_cost = 10.00 / 1000      # OpenAI web search tool cost for a single call (Reasoning model)
            
            if model != "gpt-oss-120b":
                if mode == 'custom_no_tool' or mode == 'custom':
                    cost = (web_search_results['input_tokens'] * input_token_cost) + (web_search_results['output_tokens'] * output_token_cost)
                    entry['web_search_cost'] = round(cost, 5)
                elif mode == 'openai':
                    cost = web_search_openai_tool_cost + (web_search_results['output_tokens'] * output_token_cost)
                    entry['web_search_cost'] = round(cost, 5)
            
            try:
                with builtins.open(cve_wsm_logs_path / 'stats.json', 'r') as f:
                    stats = json.load(f)

                entry = entry | stats
            except:
                entry = entry | {
                    "num_containers": None,
                    "test_iteration": None,
                    "starting_image_builds": None,
                    "image_build_failures": None,
                    "starting_container_runs": None,
                    "container_run_failures": None,
                    "not_vuln_version_fail": None,
                    "docker_misconfigured": None,
                    "docker_scout_vulnerable": None,
                    "exploitable": None,
                    "services_ok": None,
                    "requires_manual_setup": None,
                }
            
            test_error_list = []
            with builtins.open(cve_wsm_logs_path / 'final_report.txt', 'r') as f:
                final_report = f.read()
                for x in range(10):
                    if f"Test iteration #{x} failed! See 'log{x}.txt' for details." in final_report:
                        test_error = final_report.split(f"Test iteration #{x} failed! See 'log{x}.txt' for details.")[1].split('\n')[1].split(':')[0][3:]
                        test_error_list.append(test_error)
                    else:
                        break
            entry['test_errors'] = test_error_list
            df.append(entry)

    # Create DataFrame
    df = pd.DataFrame(df)
    return df
# display(get_val_set_data(model="GPT-4o", logs_set="7th", add_ablation_results=True))



#* GENERATE THE TEST SET PANDAS DATAFRAME FOR A GIVEN MODEL AND LOGS SET *#
def get_test_set_data(model: str, logs_set: str):
    main_path = Path(f'./../../../tests/{model}/{logs_set}-test-set-results')
    
    # This is the Test Set, therefore only the last 100 CVE identifiers are considered
    with builtins.open('./../services.json', "r") as f:
        jsonServices = json.load(f)
    cve_list = list(jsonServices.keys())[20:]
    wsm2modeX = {
        'openai': 'OpenAI Search',
        'custom': 'Custom Search',
        'custom_no_tool': 'CVE-based Search',
    }
    
    df = []
    web_search_modes = ['custom_no_tool']
    for cve in cve_list:
        cve_path = main_path / f'{cve}'
        for mode in web_search_modes:
            cve_wsm_logs_path = cve_path / f'{mode}/logs'            
            entry = {'model': model, 'logs_set': logs_set, 'cve_id': cve, 'web_search_mode': wsm2modeX[mode]}
            
            with builtins.open(cve_wsm_logs_path / 'milestones.json', 'r') as f:
                milestones = json.load(f)

            entry = entry | milestones

            with builtins.open(cve_wsm_logs_path / 'web_search_results.json', 'r') as f:
                web_search_results = json.load(f)
                
            entry['attack_type'] = web_search_results['attack_type']
            entry['number_of_services'] = len(web_search_results['services'])
            entry['input_token_values'] = web_search_results['input_tokens']
            entry['output_token_values'] = web_search_results['output_tokens']
            
            # Query value
            if mode == 'custom_no_tool':
                entry['query'] = cve
            elif mode == 'custom':
                entry['query'] = web_search_results['query']
            elif mode == 'openai':
                entry['query'] =  ""

            # Web search cost in dollars
            if model == "GPT-4o":
                input_token_cost = 2.50 / 1000000               # GPT-4o single input token cost
                output_token_cost = 10.00 / 1000000             # GPT-4o single output token cost
                web_search_openai_tool_cost = 25.00 / 1000      # OpenAI web search tool cost for a single call (Non-reasoning model)
            
            elif model == "GPT-5":
                input_token_cost = 1.25 / 1000000               # GPT-5 single input token cost
                output_token_cost = 10.00 / 1000000             # GPT-5 single output token cost
                web_search_openai_tool_cost = 10.00 / 1000      # OpenAI web search tool cost for a single call (Reasoning model)
            
            if model != "gpt-oss-120b":
                if mode == 'custom_no_tool' or mode == 'custom':
                    cost = (web_search_results['input_tokens'] * input_token_cost) + (web_search_results['output_tokens'] * output_token_cost)
                    entry['web_search_cost'] = round(cost, 5)
                elif mode == 'openai':
                    cost = web_search_openai_tool_cost + (web_search_results['output_tokens'] * output_token_cost)
                    entry['web_search_cost'] = round(cost, 5)
            
            try:
                with builtins.open(cve_wsm_logs_path / 'stats.json', 'r') as f:
                    stats = json.load(f)

                entry = entry | stats
            except:
                entry = entry | {
                    "num_containers": None,
                    "test_iteration": None,
                    "starting_image_builds": None,
                    "image_build_failures": None,
                    "starting_container_runs": None,
                    "container_run_failures": None,
                    "not_vuln_version_fail": None,
                    "docker_misconfigured": None,
                    "docker_scout_vulnerable": None,
                    "exploitable": None,
                    "services_ok": None,
                    "requires_manual_setup": None,
                }

            df.append(entry)

    # Create DataFrame
    df = pd.DataFrame(df)
    return df
# display(get_test_set_data(model="GPT-4o", logs_set="1st"))


# df_gpt4o = pd.concat([
#         get_test_set_data(model="GPT-4o", logs_set="1st"),
#         get_test_set_data(model="GPT-4o", logs_set="2nd"),
#         get_test_set_data(model="GPT-4o", logs_set="3rd"),
#     ])
# ig_ok = df_gpt4o['hard_service'] & df_gpt4o['hard_version'] & df_gpt4o['soft_services']
# eg_ok = df_gpt4o["docker_builds"] & df_gpt4o["docker_runs"] & df_gpt4o["code_hard_version"] & df_gpt4o["network_setup"]
# va_ok = df_gpt4o["docker_scout_vulnerable"]
# cve_list_gpt4o = df_gpt4o[eg_ok & va_ok]["cve_id"].unique()
# display(len(cve_list_gpt4o), sorted(cve_list_gpt4o))
# 
# 
# df_gpt_oss_120b = pd.concat([
#         get_test_set_data(model="gpt-oss-120b", logs_set="1st"),
#         get_test_set_data(model="gpt-oss-120b", logs_set="2nd"),
#         get_test_set_data(model="gpt-oss-120b", logs_set="3rd"),
#     ])
# ig_ok = df_gpt_oss_120b['hard_service'] & df_gpt_oss_120b['hard_version'] & df_gpt_oss_120b['soft_services']
# eg_ok = df_gpt_oss_120b["docker_builds"] & df_gpt_oss_120b["docker_runs"] & df_gpt_oss_120b["code_hard_version"] & df_gpt_oss_120b["network_setup"]
# va_ok = df_gpt_oss_120b["docker_scout_vulnerable"]
# cve_list_gpt_oss_120b = df_gpt_oss_120b[eg_ok & va_ok]["cve_id"].unique()
# display(len(cve_list_gpt_oss_120b), sorted(cve_list_gpt_oss_120b))
# 
# count = 0
# for cve in cve_list_gpt4o:
#     if cve not in cve_list_gpt_oss_120b:
#         print("GPT-4o", cve, count := count + 1)
# print()
# count = 0
# for cve in cve_list_gpt_oss_120b:
#     if cve not in cve_list_gpt4o:
#         print("gpt-oss:120B", cve, count := count + 1)
# 
# 
# df = pd.concat([
#         get_test_set_data(model="GPT-4o", logs_set="1st"),
#         get_test_set_data(model="GPT-4o", logs_set="2nd"),
#         get_test_set_data(model="GPT-4o", logs_set="3rd"),
#         get_test_set_data(model="gpt-oss-120b", logs_set="1st"),
#         get_test_set_data(model="gpt-oss-120b", logs_set="2nd"),
#         get_test_set_data(model="gpt-oss-120b", logs_set="3rd"),
#     ])
# ig_ok = df['hard_service'] & df['hard_version'] & df['soft_services']
# eg_ok = df["docker_builds"] & df["docker_runs"] & df["code_hard_version"] & df["network_setup"]
# va_ok = df["docker_scout_vulnerable"]
# cve_list = df[eg_ok & va_ok]["cve_id"].unique()
# display(len(cve_list), sorted(cve_list))




