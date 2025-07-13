"""Define the agent graph.
Its tasks are:
    - use the web_search tool to retrieve relevant information from the web about a given CVE
    - using the retrieved information, generate the code to reproduce the CVE through docker
    - test the docker image to check if the services work correctly
    - generate or use a predefined PoC to exploit the CVE
    - report the testing and exploitation results
"""

from langgraph.graph import StateGraph, START, END

# My modules
from state import OverallState
import nodes

workflow = StateGraph(OverallState)

# Add nodes to the workflow
workflow.add_node("get_cve_id", nodes.get_cve_id)
workflow.add_node("assess_cve_id", nodes.assess_cve_id)
workflow.add_node("get_services", nodes.get_services)
workflow.add_node("assess_services", nodes.assess_services)
workflow.add_node("generate_code", nodes.generate_code)
workflow.add_node("save_code", nodes.save_code)
workflow.add_node("test_code", nodes.test_code)

# Add edges to the workflow
workflow.add_edge(START, "get_cve_id")
workflow.add_edge("get_cve_id", "assess_cve_id")
workflow.add_conditional_edges(
    "assess_cve_id",
    nodes.route_cve,
    {
        "Found": "get_services",
        "Not Found": END,
    },
)
workflow.add_edge("get_services", "assess_services")
workflow.add_conditional_edges(
    "assess_services",
    nodes.route_services,
    {
        "Ok": "generate_code",
        "Not Ok": END,
    },
)
workflow.add_edge("generate_code", "save_code")
workflow.add_edge("save_code", "test_code")
workflow.add_conditional_edges(
    "test_code",
    nodes.route_code,
    {
        "Stop Testing": END,
        "Keep Testing": "save_code",
    },
)

# Compile the graph
compiled_workflow = workflow.compile()
