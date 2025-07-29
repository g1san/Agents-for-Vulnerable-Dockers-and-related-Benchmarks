"""Run the agent by providing it with a CVE ID."""

from langchain_core.messages import SystemMessage

# My modules
from configuration import langfuse_handler, WebSearchResult, CodeGenerationResult
from prompts import SYSTEM_PROMPT
from graph import compiled_workflow

def draw_graph():
    """Display the image of the compiled graph"""
    from IPython.display import Image, display
    
    try:
        display(Image(compiled_workflow.get_graph().draw_mermaid_png(output_file_path="Mermaid Chart.png")))
        
    except Exception as e:
        print(f"Rendering failed with code {e}.\nHere's the Mermaid source:\n{compiled_workflow.get_graph().draw_mermaid()}")

    
def benchmark_web_search(web_search_mode: str):
    try:
        import json
        filename = 'services.json'
        with open(filename, "r") as f:
            jsonServices = json.load(f)
            
        milestone_file = f'./../web_search_benchmark_logs/{web_search_mode}-milestones.json'
        cve_list = list(jsonServices.keys())
        milestones = {}
        for cve in cve_list[:20]: # Limit to first 20 CVEs for benchmarking
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
            with open(milestone_file, "w") as f:
                json.dump(milestones, f, indent=4)
                
        return milestones

    except Exception as e:
        print(f"Workflow invocation failed: {e}.")
    
    
def benchmark_web_search_from_logs(web_search_mode: str):
    try:
        import json
        filename = 'services.json'
        with open(filename, "r") as f:
            jsonServices = json.load(f)
            
        milestone_file = f'./../web_search_benchmark_logs/{web_search_mode}-milestones.json'
        cve_list = list(jsonServices.keys())
        milestones = {}
        for cve in cve_list[:20]: # Limit to first 20 CVEs for benchmarking
            with open(f'./../web_search_benchmark_logs/{cve}/logs/{cve}_web_search_{web_search_mode}.json', 'r') as f:
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
            with open(milestone_file, "w") as f:
                json.dump(milestones, f, indent=4)
                
        return milestones

    except Exception as e:
        print(f"Workflow invocation failed: {e}.")


def test_workflow():
    try:
        return compiled_workflow.invoke(
            input={
                "cve_id": "CVE-2021-28164",#    CVE-2021-28164    CVE-2022-46169    CVE-2024-23897  #NOTE: to test GT update use CVE-2017-7525
                "web_search_tool": "custom",#   custom  custom_no_tool  openai  skip        #NOTE: if 'skip' is used, initialize "web_search_result" with valid data
                #"web_search_result": WebSearchResult(desc="", attack_type="", services=[], service_vers=[], service_type=[], service_desc=[]),
                #"code": CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
                "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                "debug": "benchmark_web_search"#        (DEFAULT="")    skip_to_test    benchmark_web_search
            },
            config={"callbacks": [langfuse_handler], "recursion_limit": 100},
        )
    except Exception as e:
        print(f"Workflow invocation failed: {e}.")


def generate_excel():
    import pandas as pd
    import json

    # CVE identifiers
    with open('services.json', "r") as f:
        jsonServices = json.load(f)  
    cve_list = list(jsonServices.keys())[:20]
    
    data = {}
    web_search_modes = ['custom_no_tool', 'custom', 'openai']
    for mode in web_search_modes:
        data[mode] = []
        with open(f'./../web_search_benchmark_logs/{mode}-milestones.json', 'r') as f:
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
        for cve in cve_list:
            with open(f'./../web_search_benchmark_logs/{cve}/logs/{cve}_web_search_{mode}.json', 'r') as f:
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
        
        data[mode].append(query_values)
        data[mode].append(number_of_services)
        data[mode].append(input_token_values)
        data[mode].append(output_token_values)
        data[mode].append(cost_values)

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
    df = pd.DataFrame(combined_data, columns=column, index=milestones + ['Query', 'Number of Services', 'Input Tokens', 'Output Tokens', 'Cost'])
    df.to_excel(f'./../web_search_benchmark_logs/benchmark-milestones.xlsx')
    return df


def extract_stats():
    import json
    
    data = {}
    web_search_modes = ['custom_no_tool', 'custom', 'openai']
    for mode in web_search_modes:
        data[mode] = {}
        with open(f'./../web_search_benchmark_logs/{mode}-milestones.json', 'r') as f:
            mode_milestones = json.load(f)
            
        milestones = list(next(iter(mode_milestones.values())).keys())

        for m in milestones:
            data[mode][m] = [1 if mode_milestones[cve][m] else 0 for cve in mode_milestones].count(1)
         
    return data   
            

# draw_graph()
# result = test_workflow()
# milestones = benchmark_web_search("openai")
# milestones = benchmark_web_search_from_logs("custom_no_tool")
df = generate_excel()
# df = extract_stats()