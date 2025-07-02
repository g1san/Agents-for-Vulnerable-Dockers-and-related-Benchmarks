import os
import json
import requests
from pathlib import Path
from typing import Literal
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage

# My modules
from state import OverallState
from tools.openai_tools import openai_web_search
from tools.custom_web_search import web_search_func
from tools.custom_tool_web_search import web_search, web_search_tool_func
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
        
        # Invoke the LLM to generate the custom tool arguments
        tool_call = llm_custom_web_search_tool.invoke(messages, config={"callbacks": [langfuse_handler]})
        # Extract the tool arguments from the LLM call
        tool_call_args = json.loads(tool_call.additional_kwargs['tool_calls'][0]['function']['arguments'])
        query, cve_id = tool_call_args['query'], tool_call_args['cve_id']
        print(f"The LLM invoked the 'web search' tool with parameters: query={query}, cve_id={cve_id}\n")
        # Invoke the tool 'web_search_tool_func' to perform the web search. NOTE: here 'formatted_response' is already formatted as WebSearchResult Pydantic class
        formatted_response, in_token, out_token = web_search_tool_func(query, cve_id)
        
        # Build 'response' which can be added to messages
        response = f"CVE description: {formatted_response.description}\nAttack Type: {formatted_response.attack_type}\nService list:"
        for service, description in zip(formatted_response.services, formatted_response.service_description):
            response += f"\n[{service}] {description}"
            
        # Print additional information about token usage
        print(f"TOKEN USAGE INFO: this custom web search used {in_token} input tokens and {out_token} output tokens\n")
    
    # Uses the web search function directly, instead of its tool counterpart
    elif state.web_search_tool == "custom_no_tool":
        # Invoke the 'web_search_func' to perform the web search. NOTE: here 'formatted_response' is already formatted as WebSearchResult Pydantic class
        formatted_response, in_token, out_token = web_search_func(state.cve_id)
        
        # Build 'response' which can be added to messages
        response = f"CVE description: {formatted_response.description}\nAttack Type: {formatted_response.attack_type}\nService list:"
        for service, description in zip(formatted_response.services, formatted_response.service_description):
            response += f"\n[{service}] {description}"
            
        # Print additional information about token usage
        print(f"TOKEN USAGE INFO: this custom web search used {in_token} input tokens and {out_token} output tokens\n")
    
    # Invoking the LLM with OpenAI's predefined web search tool  
    elif state.web_search_tool == "openai":
        # Format the web search query
        web_query = OPENAI_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        # Update message list
        messages += [HumanMessage(content=web_query)]
        
        # Invoke the LLM to perform the web search
        web_search_result = llm_openai_web_search_tool.invoke(messages, config={"callbacks": [langfuse_handler]})
        # Extract the source-less response
        response_sourceless = web_search_result.content[0]["text"]
        # Invoke the LLM to format the web search result into a WebSearchResult Pydantic class
        formatted_response = docker_services_llm.invoke(WEB_SEARCH_FORMAT_PROMPT.format(web_search_result=response_sourceless), config={"callbacks": [langfuse_handler]})
        
        # Add the sources to the response
        response = response_sourceless + "\n\nSources:"
        source_set = set()
        for source in web_search_result.content[0]["annotations"]:
            source_set.add(f"{source['title']} ({source['url']})")
        for i, source in enumerate(source_set):
            response += f"\n{i + 1}) {source}"
    
    # Skips the web search phase
    elif state.web_search_tool == "skip":
        return {}
        
    else:
        raise ValueError("Invalid web search tool specified. Use 'custom', 'custom_no_tool', 'openai' or 'skip'.")

    # Return state updates
    return {
        "web_search_result": formatted_response,
        "messages": messages + [AIMessage(content=response)],
    }


def assess_docker_services(state: OverallState):
    """Checks if the services needed to generate the vulnerable Docker code are correct against a GROUND TRUTH"""
    print("Checking the Docker services...")
    filename = 'docker-services.json'
    with open(filename, "r") as f:
        dockerServices = json.load(f)
        
    # If the GROUND TRUTH does not exist for the given CVE ID, update the GT and skip the check
    if not dockerServices.get(state.cve_id.upper()):
        print(f"There is no GT for {state.cve_id.upper()}! Updating GT with the following services:")
        services = []
        for serv_ver, serv_type in zip(state.web_search_result.services, state.web_search_result.service_type):
            new_service = f"{serv_type.upper()}:{serv_ver.lower()}"
            print(f"- {new_service}")
            services.append(new_service)
        dockerServices[state.cve_id.upper()] = services
        with open(filename, "w") as f:
            json.dump(dockerServices, f, indent=4)
        return {"docker_services_ok": True}
    
    # Extract the expected services and their versions from the GROUND TRUTH
    expected_services_types = []
    expected_services_versions = {}
    for exp_serv_ver in dockerServices[state.cve_id.upper()]:
        print(f"Expected service: {exp_serv_ver}")
        serv_type, serv, ver = exp_serv_ver.split(":")
        expected_services_types.append(serv_type.upper())
        serv = serv.lower()
        if not expected_services_versions.get(serv):
            expected_services_versions[serv] = ver
        else:
            expected_services_versions[serv] += f",{ver}"
        
    # Extract the proposed services from the web search result
    proposed_services_types = []
    proposed_services_versions = {}
    for serv_ver, serv_type in zip(state.web_search_result.services, state.web_search_result.service_type):
        print(f"Proposed service: {serv_type}:{serv_ver}")
        proposed_services_types.append(serv_type.upper())
        serv, ver = serv_ver.split(":")
        serv = serv.split("/")[-1].lower()
        if not proposed_services_versions.get(serv):
            proposed_services_versions[serv] = ver
        else:
            proposed_services_versions[serv] += f",{ver}"
        
    # Check if all the MAIN expected services are proposed
    for exp_serv, exp_type in zip(expected_services_versions, expected_services_types):
        if (exp_type == 'MAIN') and (exp_serv not in proposed_services_versions):
            print(f"{exp_type} service '{exp_serv}' was not proposed!")
            #!return {"docker_services_ok": False}
        
    # Check if all the MAIN proposed services have the expected version
    for prop_serv, prop_type in zip(proposed_services_versions, proposed_services_types):
        # Report any MAIN proposed service that is not expected 
        if (prop_serv not in expected_services_versions):
            print(f"{prop_type} service '{prop_serv}' was not expected!")
            continue
        
        # Handles the case where the same service may be used with different versions
        exp_vers = expected_services_versions[prop_serv].split(",")
        prop_vers = proposed_services_versions[prop_serv].split(",")
        for pv in prop_vers:
            if pv not in exp_vers:
                print(f"The proposed version ({pv}) of {prop_serv} is not an expected one!")
    
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
            cve_desc=state.web_search_result.description,
            attack_type=state.web_search_result.attack_type,
            serv=state.web_search_result.services,
            serv_desc=state.web_search_result.service_description,
        )

        # Invoking the LLM with the structured output
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
    """The agent saves the generated code in a local directory and generates a directory tree"""
    print("Saving code...")

    main_directory_path = Path(f"./../../dockers/{state.cve_id.upper()}")

    try:
        main_directory_path.mkdir(parents=True, exist_ok=False)
        print(f"Directory '{main_directory_path}' created successfully.")
    except FileExistsError:
        raise ValueError(f"Directory '{main_directory_path}' already exists.")
    except PermissionError:
        raise ValueError(f"Permission denied: Unable to create '{main_directory_path}'.")
    except Exception as e:
        raise ValueError(f"An error occurred: {e}")

    # Save each file in the appropriate location
    for file_rel_path, file_content in zip(state.code.file_name, state.code.file_code):
        full_path = main_directory_path / file_rel_path
        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
        except FileExistsError:
            raise ValueError(f"Directory '{full_path}' already exists.")
        except PermissionError:
            raise ValueError(f"Permission denied: Unable to create '{full_path}'.")
        except Exception as e:
            raise ValueError(f"An error occurred: {e}")
        
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(file_content)
        print(f"Saved file: {full_path}")

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
