import os
import requests
from typing import Literal
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage

# My modules
from state import OverallState
from tools.openai_tools import openai_web_search
from tools.custom_tools import web_search
from prompts import (
    OPENAI_WEB_SEARCH_PROMPT, 
    CODING_PROMPT, 
    CUSTOM_WEB_SEARCH_PROMPT,
    WEB_SEARCH_FORMAT_PROMPT,
)
from configuration import (
    CodeGenerationResult,
    WebSearchResult,
    langfuse_handler,
    dockerServices,
)

# Initialize the LLM with OpenAI's GPT-4o model
llm_model = ChatOpenAI(model="gpt-4o", temperature=0, max_retries=2)

# Bind the LLM with OpenAI's predefined web search tool
llm_openai_web_search_tool = llm_model.bind_tools([openai_web_search])

# Bind the LLM with the custom web search tool
llm_custom_web_search_tool = llm_model.bind_tools([web_search])

# Set the LLM to return a structured output from web search
docker_services_llm = llm_model.with_structured_output(WebSearchResult)

# Set the LLM to return a structured output from code generation
code_generation_llm = llm_model.with_structured_output(CodeGenerationResult)


def get_cve_id(state: OverallState):
    """Checks if the CVE ID is correctly retrieved from the initialized state"""
    print(f"The provided CVE ID is {state.cve_id}!")
    return {}


def assess_cve_id(state: OverallState):
    """The agent checks if the CVE ID exists in the MITRE CVE database"""
    print("Checking if the CVE ID exists...")
    response = requests.get(f"https://cveawg.mitre.org/api/cve/{state.cve_id.upper()}")

    if response.status_code == 200:
        print(f"{state.cve_id} exists!")
        return {"is_cve": True}

    elif response.status_code == 404:
        print(f"The record for {state.cve_id} does not exist.")
        return {"is_cve": False}

    else:
        print(f"Failed to fetch CVE: {response.status_code}")
        return {"is_cve": False}


def route_cve(state: OverallState) -> Literal["Found", "Not Found"]:
    """Terminate the graph or go to the next step"""
    print(f"Routing CVE (is_cve = {state.is_cve})")
    if state.is_cve:
        return "Found"
    else:
        return "Not Found"


def get_docker_services(state: OverallState):
    """The agent performs a web search to gather relevant information 
        about the services needed to generate the vulnerable Docker code"""
    print("Searching the web...")
    
    messages = state.messages

    # Invoking the LLM with the custom web search tool
    if state.web_search_tool == "custom":
        # Format the web search query
        web_query = CUSTOM_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        # Update message list
        messages += [HumanMessage(content=web_query)]
        # Invoke the LLM to perform the web search. NOTE: here 'web_search_result' is already formatted as WebSearchResult Pydantic class
        web_search_result, in_token, out_token = llm_custom_web_search_tool.invoke(messages, config={"callbacks": [langfuse_handler]})
        print(f"This custom web search used {in_token} input tokens and {out_token} output tokens")
    
    # Invoking the LLM with OpenAI's predefined web search tool  
    elif state.web_search_tool == "openai":
        # Format the web search query
        web_query = OPENAI_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        # Update message list
        messages += [HumanMessage(content=web_query)]
        # Invoke the LLM to perform the web search
        web_search_result = llm_openai_web_search_tool.invoke(messages, config={"callbacks": [langfuse_handler]})
        # Invoke the LLM to format 'web_search_result' into a WebSearchResult Pydantic class
        web_search_result = docker_services_llm.invoke(WEB_SEARCH_FORMAT_PROMPT.format(web_search_result=web_search_result), config={"callbacks": [langfuse_handler]})
    else:
        raise ValueError("Invalid web search tool specified. Use 'custom' or 'openai'.")

    # TODO: check if the following code works!
    # Format the web search result to include the sources (if any)
    source_set = set()
    for source in web_search_result.content[0]["annotations"]:
        source_set.add(f"{source['title']} ({source['url']})")

    response = web_search_result.content[0]["text"] + "\n\nSources:"
    for i, source in enumerate(source_set):
        response += f"\n{i + 1}) {source}"

    # Update message list
    messages += [AIMessage(content=response)]

    # Return state updates
    return {
        "web_search_result": response,
        "messages": messages,
    }


def assess_docker_services(state: OverallState):
    """Checks if the services needed to generate the vulnerable Docker code are correct against a GROUND TRUTH"""
    print("Checking the Docker services...")
    # Extract the expected services and their versions from the GROUND TRUTH
    expected_services_versions = {}
    for exp_serv_ver in dockerServices[state.cve_id.upper()].values():
        print(f"Expected service: {exp_serv_ver}")
        serv, ver = exp_serv_ver.split(":")
        expected_services_versions[f"{serv}"] += f"{ver},"
        
    # Extract the proposed services from the web search result
    proposed_services_versions = {}
    for serv_ver in state.web_search_result.services:
        print(f"Proposed service: {serv_ver}")
        serv, ver = serv_ver.split(":")
        proposed_services_versions[f"{serv}"] += f"{ver},"
        
    # Check if all the expected services are proposed
    for exp_serv in expected_services_versions:
        if exp_serv not in proposed_services_versions:
            print(f"{exp_serv} was not proposed!")
            return {"docker_services_ok": False}
        
    # Check if all the proposed services have the expected version
    for prop_serv in proposed_services_versions:
        # Report any proposed service that is not expected 
        if (prop_serv not in expected_services_versions):
            print(f"{prop_serv} was not expected!")
            continue
        
        # The same service may be used with different versions
        exp_vers = expected_services_versions[prop_serv].split(",")
        prop_vers = proposed_services_versions[prop_serv].split(",")
        for pv in prop_vers:
            if pv not in exp_vers:
                print(f"The proposed version ({pv}) of {prop_serv} is not an expected one")
    
    return {"docker_services_ok": True}


def route_docker_services(state: OverallState) -> Literal["Ok", "Not Ok"]:
    """Route to the code generator or terminate the graph"""
    print(f"Routing docker services (docker_services_ok = {state.docker_services_ok})")
    if state.docker_services_ok:
        return "Ok"
    else:
        return "Not Ok"


def generate_docker_code(state: OverallState):
    """The agent generates/fixes the docker code to reproduce the CVE"""
    if state.feedback != "":
        print("Fixing the code...")
        return {}

    else:
        print("Generating the code...")
        code_gen_query = CODING_PROMPT.format(
            cve_id=state.cve_id,
            web_search_results=state.web_search_result,
        )

        # Invoking the LLM with the structured output
        #! May need to pass message with web search result + query instead of query with web search result integrated
        generated_code = code_generation_llm.invoke(code_gen_query, config={"callbacks": [langfuse_handler]}) 

        # Format the LLM response
        response = f"Directory tree:\n\n{generated_code.directory_tree}\n\n"
        for name, code in zip(generated_code.file_name, generated_code.file_code):
            response += "-" * 10 + f" {name} " + "-" * 10 + f"\n{code}\n\n"

        # Update message list
        messages = state.messages + [
            HumanMessage(content=code_gen_query),
            AIMessage(content=response),
        ]

        # Return state updates
        return {
            "code": generated_code,
            "messages": messages,
        }


def save_code(state: OverallState):
    """The agent saves the generated code in a local directory"""
    print("Saving code...")

    #* TESTING DIRECTORY CREATION *# 
    # NOTE: this is a WIP
    main_directory_name = f"./Dockers/{state.cve_id.upper()}"
    try:
        os.mkdir(main_directory_name)
        print(f"Directory '{main_directory_name}' created successfully.")
    except FileExistsError:
        raise ValueError(f"Directory '{main_directory_name}' already exists.")
    except PermissionError:
        raise ValueError(f"Permission denied: Unable to create '{main_directory_name}'.")
    except Exception as e:
        raise ValueError(f"An error occurred: {e}")

    print("Code saved!")
    return {}


def test_docker_code(state: OverallState):
    """The agent tests the docker to check if it work correctly"""
    print("Testing code...")
    
    """
    IDEAS: the agent should be a ReACT agent capable of interacting with a Linux OS in order to:
        1. Navigate to the correct folder where the CVE's 'docker-compose.yml' is stored
        2. Launch the Docker by generating the 'docker compose up' command (or similar)
        3. Retrieve any possible error that can involve the Docker setup phase
        4. Report back the error and write a feedback to explain the probable causes
        5. If the Docker works correctly, terminate
    """
    
    return {}


def route_code(state: OverallState) -> Literal["Ok", "Reject + Feedback"]:
    """Route back to the code generator or go to the next step"""
    print(f"Routing code (code_ok = {state.code_ok})")
    if state.code_ok:
        return "Ok"
    else:
        return "Reject + Feedback"
