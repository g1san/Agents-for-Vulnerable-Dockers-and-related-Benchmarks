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
            "cve_id": "CVE-2021-28164",
            "web_search_tool": "skip",
            #"web_search_result": WebSearchResult(description="", attack_type="", services=[], service_description=[]),
            "web_search_result": WebSearchResult(
                description='CVE-2021-28164 is an information disclosure vulnerability in the Eclipse Jetty web server, allowing unauthorized access to sensitive files in the WEB-INF directory through crafted URIs with encoded characters.', 
                attack_type='Information Disclosure', 
                services=['eclipse/jetty:9.4.42.v20210604'],
                service_description=['Jetty 9.4.42.v20210604 is vulnerable to CVE-2021-28164, allowing access to protected files in the WEB-INF directory through crafted URIs.'],),
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

# for field in result['web_search_result']:
#     print(f"'{field[0]}': {field[1]}")