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

# Test the workflow
try:
    result = compiled_workflow.invoke(
        input={
            "cve_id": "CVE-2021-28164",#    CVE-2021-28164    CVE-2022-46169    CVE-2024-23897
            "web_search_tool": "openai",#   custom  custom_no_tool  openai  skip
            #"web_search_result": WebSearchResult(description="", attack_type="", services=[], service_description=[]),
            #"code": CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
        },
        config={"callbacks": [langfuse_handler]},
    )

    # Review conversation history
    print()
    for message in result["messages"]:
        print("=" * 20 + f" {message.type.upper()} " + "=" * 20)
        print(f"{message.content}\n")

except Exception as e:
    print(f"Workflow invocation failed: {e}.")

try:
    print(f"description='{result['web_search_result'].description},'")
    print(f"attack_type='{result['web_search_result'].attack_type},'")
    print(f"services={result['web_search_result'].services},")
    print(f"service_type={result['web_search_result'].service_type},")
    print(f"service_description={result['web_search_result'].service_description},")
except:
    print("NO DATA RECOVERED FROM THE WEB")
  