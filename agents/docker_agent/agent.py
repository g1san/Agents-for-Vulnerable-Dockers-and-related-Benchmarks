"""Run the agent by providing it with a CVE ID."""

from graph import compiled_workflow
from configuration import langfuse_handler
from IPython.display import Image, display

# Display the image of the compiled graph
try:
    display(
        Image(
            compiled_workflow.get_graph().draw_mermaid_png(
                output_file_path="graph_image.png"
            )
        )
    )
except Exception as e:
    print(f"Rendering failed with code {e}.\nHere's the Mermaid source:")
    print(compiled_workflow.get_graph().draw_mermaid())

# Test the workflow
result = compiled_workflow.invoke(
    input={
        "cve_id": "CVE-2021-28164",
        "is_cve": True,
        "web_search_result": "",
        "docker_code": "",
        "code_ok": True,
        "feedback": "",
        "messages": [],
    },
    config={"callbacks": [langfuse_handler]},
)
print(result)
for field,_ in result.items():
    print(f"{field}: {result[field]}")
