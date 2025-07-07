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
workflow.add_node("get_docker_services", nodes.get_docker_services)
workflow.add_node("assess_docker_services", nodes.assess_docker_services)
workflow.add_node("generate_docker_code", nodes.generate_docker_code)
workflow.add_node("save_code", nodes.save_code)
workflow.add_node("test_docker_code", nodes.test_docker_code)

# Add edges to the workflow
workflow.add_edge(START, "get_cve_id")
workflow.add_edge("get_cve_id", "assess_cve_id")
workflow.add_conditional_edges(
    "assess_cve_id",
    nodes.route_cve,
    {
        "Found": "get_docker_services",
        "Not Found": END,
    },
)
workflow.add_edge("get_docker_services", "assess_docker_services")
workflow.add_conditional_edges(
    "assess_docker_services",
    nodes.route_docker_services,
    {
        "Ok": "generate_docker_code",
        "Not Ok": END,
    },
)
workflow.add_edge("generate_docker_code", "save_code")
workflow.add_edge("save_code", "test_docker_code")
workflow.add_conditional_edges(
    "test_docker_code",
    nodes.route_code,
    {
        "Stop Testing": END,
        "Keep Testing": "save_code",
    },
)

# Compile the graph
compiled_workflow = workflow.compile()
