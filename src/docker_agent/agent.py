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
    import json
    filename = 'services.json'
    with open(filename, "r") as f:
        jsonServices = json.load(f)

    cve_list = list(jsonServices.keys())
    for cve in cve_list:
        try:
            result = compiled_workflow.invoke(
                input={
                    "cve_id": cve,
                    "web_search_tool": web_search_mode,
                    "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                    "debug": "benchmark_web_search"
                },
                config={"callbacks": [langfuse_handler], "recursion_limit": 100},
            )
            #TODO: extract from web search file the values needed to compute stats
            

        except Exception as e:
            print(f"Workflow invocation failed: {e}.")


def test_workflow():
    try:
        result = compiled_workflow.invoke(
            input={
                "cve_id": "CVE-2021-28164",#    CVE-2021-28164    CVE-2022-46169    CVE-2024-23897  #NOTE: to test GT update use CVE-2017-7525
                "web_search_tool": "openai",#   custom  custom_no_tool  openai  skip        #NOTE: if 'skip' is used, initialize "web_search_result" with valid data
                #"web_search_result": WebSearchResult(description="", attack_type="", services=[], service_type=[], service_description=[]),
                #"code": CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
                "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                "debug": "benchmark_web_search"#        (DEFAULT="")    skip_to_test    benchmark_web_search
            },
            config={"callbacks": [langfuse_handler], "recursion_limit": 100},
        )

    except Exception as e:
        print(f"Workflow invocation failed: {e}.")
        
        
def run_agent():
    # draw_graph()
    # test_workflow()
    # benchmark_web_search("custom")
    # benchmark_web_search("openai")
    return

run_agent()    
