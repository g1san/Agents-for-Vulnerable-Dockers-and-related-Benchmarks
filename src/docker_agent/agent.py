"""Run the agent by providing it with a CVE ID."""

from graph import compiled_workflow
from configuration import langfuse_handler
from prompts import SYSTEM_PROMPT
from langchain_core.messages import SystemMessage

from IPython.display import Image, display

# Display the image of the compiled graph
# try:
#     display(
#         Image(
#             compiled_workflow.get_graph().draw_mermaid_png(
#                 output_file_path="Mermaid Chart.png"
#             )
#         )
#     )
# except Exception as e:
#     print(f"Rendering failed with code {e}.\nHere's the Mermaid source:")
#     print(compiled_workflow.get_graph().draw_mermaid())

# Test the workflow
result = compiled_workflow.invoke(
    input={
        "cve_id": "CVE-2021-28164",
        "messages": [SystemMessage(content=SYSTEM_PROMPT)],
    },
    config={"callbacks": [langfuse_handler]},
)

# Review conversation history
print()
for message in result["messages"]:
    print("=" * 20 + f" {message.type.upper()} " + "=" * 20)
    print(f"{message.content}\n")

# print(f"{result['web_search_result'].content[0]['text']}\n\nSources:")
# source_set = set()
# for source in result["web_search_result"].content[0]["annotations"]:
#     source_set.add(f"{source['title']} ({source['url']})")
#
# for i, source in enumerate(source_set):
#     print(f"{i + 1}) {source}")

# print(result["code"].directory_tree)
# for name, code in zip(result["code"].file_name, result["code"].file_code):
#     print("-"*10 + f" {name} " + "-"*10)
#     print(f"\n{code}\n")

# print(f"Checking tool usage: {result["web_search_result"].additional_kwargs["tool_outputs"]}")
