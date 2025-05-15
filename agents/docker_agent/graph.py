"""Define the agent graph.
Its tasks are:
    - use the web_search tool to retrieve relevant information from the web about a given CVE
    - using the retrieved information, generate the code to reproduce the CVE through docker
    - test the docker image to check if the services work correctly
    - generate or use a predefined PoC to exploit the CVE
    - report the testing and exploitation results
"""

from langgraph.graph import StateGraph, START, END
from state import OverallState
import nodes

workflow = StateGraph(OverallState)

workflow.add_node("get_cve_id", nodes.get_cve_id)
workflow.add_node("web_search", nodes.web_search)
workflow.add_node("generate_docker_code", nodes.generate_docker_code)
workflow.add_node("test_docker_code", nodes.test_docker_code)
workflow.add_node(
    "save_results", nodes.save_results
)  # TODO: continue with exploiter agent

workflow.add_edge(START, "get_cve_id")
workflow.add_edge("get_cve_id", "web_search")
workflow.add_edge("web_search", "generate_docker_code")
workflow.add_edge("generate_docker_code", "test_docker_code")
workflow.add_conditional_edges(
    "test_docker_code",
    nodes.route_code,
    {
        "Ok": "save_results",  # TODO: continue with exploiter agent
        "Reject + Feedback": "generate_docker_code",
    },
)
workflow.add_edge("save_results", END)

# Compile the graph
compiled_workflow = workflow.compile()
