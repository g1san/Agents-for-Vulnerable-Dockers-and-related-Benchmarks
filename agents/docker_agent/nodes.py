from typing import Literal
from state import OverallState


def get_cve_id(state: OverallState):
    """The CVE ID is retrieved from user input"""
    print(f"The CVE ID provided is {state.cve_id}")
    return {}


def web_search(state: OverallState):
    """The agent performs a web search to gather relevant information about the CVE"""
    print("\n" * 3 + "Performing web search:")
    return {}


def generate_docker_code(state: OverallState):
    """The agent generates/fixes the docker code to reproduce the CVE"""
    if state.feedback != "":
        print("\n" * 3 + "Fixing the code:")
    else:
        print("\n" * 3 + "Generating the code:")
    return {}


def test_docker_code(state: OverallState):
    """The agent tests the docker to check if it work correctly"""
    print("\n" * 3 + "Testing code:")
    return {}


def route_code(state: OverallState) -> Literal["Ok", "Reject + Feedback"]:
    """Route back to the code generator or go to the next step"""
    print("\n" * 3 + f"Routing code (code_ok = {state.code_ok}):")
    if state.code_ok:
        return "Ok"
    else:
        return "Reject + Feedback"


def save_results(state: OverallState):
    """The agent saves the generated code in a local directory"""
    print("\n" * 3 + "Code saved")
    return {}
