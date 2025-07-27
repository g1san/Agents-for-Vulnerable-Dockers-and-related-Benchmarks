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


def extract_stats():
    import pandas as pd
    import numpy as np
    import json

    # CVE identifiers
    with open('services.json', "r") as f:
        jsonServices = json.load(f)  
    cve_list = list(jsonServices.keys())[:20]

    # Custom data from JSON milestone file
    with open(f'./../web_search_benchmark_logs/custom-milestones.json', 'r') as f:
        custom_milestones = json.load(f)
 
    custom_data = []
    milestones = list(next(iter(custom_milestones.values())).keys())

    for m in milestones:
        row = ['Yes' if custom_milestones[cve][m] else 'No' for cve in custom_milestones]
        custom_data.append(row)
    
    # OpenAI data from JSON milestone file
    with open(f'./../web_search_benchmark_logs/openai-milestones.json', 'r') as f:
        openai_milestones = json.load(f)
 
    openai_data = []
    milestones = list(next(iter(openai_milestones.values())).keys())

    for m in milestones:
        row = ['Yes' if openai_milestones[cve][m] else 'No' for cve in openai_milestones]
        openai_data.append(row)

    # Construct MultiIndex columns
    arrays = [[cve for cve in cve_list for _ in (0, 1)], ['custom', 'openai'] * len(cve_list)]
    tuples = list(zip(*arrays))
    column = pd.MultiIndex.from_tuples(tuples, names=["CVE", "Web Search Mode"])

    # Combine both datasets
    data = []
    for row_custom, row_openai in zip(custom_data, openai_data):
        combined = [val for pair in zip(row_custom, row_openai) for val in pair]
        data.append(combined)

    # Create DataFrame
    df = pd.DataFrame(data, columns=column, index=milestones)
    df.to_excel(f'./../web_search_benchmark_logs/benchmark-milestones.xlsx')
    return df
        

# draw_graph()
# result = test_workflow()
# milestones = benchmark_web_search("custom")
# milestones = benchmark_web_search_from_logs("custom")
# milestones = benchmark_web_search("openai")
# milestones = benchmark_web_search_from_logs("openai")
df = extract_stats()
df