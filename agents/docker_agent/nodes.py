from typing import Literal
from state import OverallState
from prompts import WEB_SEARCH_PROMPT
from configuration import llm_web_search_tool, langfuse_handler
from langchain_core.messages import HumanMessage, AIMessage


def get_cve_id(state: OverallState):
    """The CVE ID is retrieved from user input"""
    print(f"The CVE ID provided is {state.cve_id}")
    return {}


def web_search(state: OverallState):
    """The agent performs a web search to gather relevant information about the CVE"""
    print("Performing web search...")
    web_query = WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)

    # Invoking the LLM with the web search tool
    web_search_result = llm_web_search_tool.invoke(
        web_query,
        config={"callbacks": [langfuse_handler]},
    )

    # Format the web search result to include the sources
    source_set = set()
    for source in web_search_result.content[0]["annotations"]:
        source_set.add(f"{source['title']} ({source['url']})")

    response = web_search_result.content[0]["text"] + "\n\nSources:"
    for i, source in enumerate(source_set):
        response += f"\n{i + 1}) {source}"

    # Create message list
    new_messages = [
        HumanMessage(content=web_query),
        AIMessage(content=response),
    ]
    # Return state updates
    return {
        "web_search_result": web_search_result,
        "messages": state.messages + new_messages,
    }


def generate_docker_code(state: OverallState):
    """The agent generates/fixes the docker code to reproduce the CVE"""
    if state.feedback != "":
        print("Fixing the code...")
    else:
        print("Generating the code...")
    return {}


def test_docker_code(state: OverallState):
    """The agent tests the docker to check if it work correctly"""
    print("Testing code...")
    return {}


def route_code(state: OverallState) -> Literal["Ok", "Reject + Feedback"]:
    """Route back to the code generator or go to the next step"""
    print(f"Routing code (code_ok = {state.code_ok})...")
    if state.code_ok:
        return "Ok"
    else:
        return "Reject + Feedback"


def save_results(state: OverallState):
    """The agent saves the generated code in a local directory"""
    print("Code saved!")
    return {}
