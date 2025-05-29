"""Run the agent by providing it with a CVE ID."""

from langchain_core.messages import SystemMessage

# My modules
from configuration import langfuse_handler
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
            "web_search_tool": "custom",
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
    print(f"Workflow invocation failed with code {e}.")
