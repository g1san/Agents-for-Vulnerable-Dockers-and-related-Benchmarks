import os
import json
import requests
import subprocess
from pathlib import Path
from typing import Literal
from datetime import datetime
from packaging import version
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

# My modules
from state import OverallState
from tools.openai_tools import openai_web_search
from tools.custom_web_search import web_search_func
from tools.custom_tool_web_search import web_search, web_search_tool_func
from prompts import (
    SYSTEM_PROMPT,
    WEB_SEARCH_FORMAT_PROMPT,
    CUSTOM_WEB_SEARCH_PROMPT,
    OPENAI_WEB_SEARCH_PROMPT,
    MAIN_SERV_VERS_ASSESSMENT_PROMPT, 
    CODING_PROMPT, 
    TEST_CODE_PROMPT,
)
from configuration import (
    langfuse_handler,
    WebSearchResult,
    MAINServiceVersionAssessment,
    CodeGenerationResult,
    TestCodeResult,
)

# Initialize the LLM with OpenAI's GPT-4o model
llm_model = ChatOpenAI(model="gpt-4o", temperature=0, max_retries=2)

# Bind the LLM with OpenAI's predefined web search tool
llm_openai_web_search_tool = llm_model.bind_tools([openai_web_search])

# Bind the LLM with the custom web search tool
llm_custom_web_search_tool = llm_model.bind_tools([web_search])

# Set the LLM to return a structured output from web search
web_search_llm = llm_model.with_structured_output(WebSearchResult)

# Set up LLM-as-a-judge for MAIN service version assessment
ver_ass_llm = llm_model.with_structured_output(MAINServiceVersionAssessment)

# Set the LLM to return a structured output from code generation
code_generation_llm = llm_model.with_structured_output(CodeGenerationResult)

# Set the LLM to return a structured output from code testing
test_code_llm = llm_model.with_structured_output(TestCodeResult)


def get_cve_id(state: OverallState):
    if state.debug == "benchmark_web_search":
        print("[BENCHMARK] Web search benchmark starting!")
    
    """Checks if the CVE ID is correctly retrieved from the initialized state"""
    print(f"The provided CVE ID is {state.cve_id.upper()}!")
    return {"cve_id": state.cve_id.upper()}


def assess_cve_id(state: OverallState):
    """The agent checks if the CVE ID exists in the MITRE CVE database"""
    print("Checking if the CVE ID exists...")
    response = requests.get(f"https://cveawg.mitre.org/api/cve/{state.cve_id}")

    if response.status_code == 200:
        print(f"{state.cve_id} exists!")
        
        docker_dir_path = Path(f"./../../dockers/{state.cve_id}")
        if not docker_dir_path.exists():
            try:
                docker_dir_path.mkdir(parents=True, exist_ok=False)
                print(f"\tDirectory '{docker_dir_path}' created successfully.")
            except PermissionError:
                raise ValueError(f"Permission denied: Unable to create '{docker_dir_path}'.")
            except Exception as e:
                raise ValueError(f"An error occurred: {e}")
            
        updated_milestones = state.milestones
        updated_milestones.cve_id_exists = True
        
        return {
            "milestones": updated_milestones,
            "final_report": state.final_report + "="*10 + f" {state.cve_id} Final Report "  + "="*10 + "\n" + "="*10 + f" Initial Parameters " + "="*10 + f"\n'cve_id': {state.cve_id}\n'web_search_tool': {state.web_search_tool}\n'web_search_result': {state.web_search_result}\n'code': {state.code}\n'messages': {state.messages}\n'debug': {state.debug}\n\n",
        }

    elif response.status_code == 404:
        print(f"The record for {state.cve_id} does not exist.")
        return {}

    else:
        print(f"Failed to fetch CVE: {response.status_code}")
        return {}


def route_cve(state: OverallState) -> Literal["Found", "Not Found"]:
    """DEBUG: route the graph to the 'test_code' node"""
    if state.debug == "skip_to_test":
        print("[DEBUG] Skipping 'route_cve'...")
        return "Found"
    
    """Terminate the graph or go to the next step"""
    print(f"Routing CVE (cve_id_exists = {state.milestones.cve_id_exists})")
    if state.milestones.cve_id_exists:
        return "Found"
    else:
        return "Not Found"
    

def get_services(state: OverallState):
    """DEBUG: route the graph to the 'test_code' node"""
    if state.debug == "skip_to_test" or state.web_search_tool == "skip":
        if state.debug == "skip_to_test":
            print("[DEBUG] Skipping 'get_services'...")
        return {}
    
    """The agent performs a web search to gather relevant information about the services needed to generate the vulnerable Docker code"""
    print("Searching the web...")
    
    docker_dir_path = Path(f"./../../dockers/{state.cve_id}")
    logs_dir_path = docker_dir_path / "logs"
    
    # Create the directory to save logs (if it does not exist)
    if not logs_dir_path.exists():
        try:
            logs_dir_path.mkdir(parents=True, exist_ok=False)
            print(f"\tDirectory '{logs_dir_path}' created successfully.")
        except PermissionError:
            raise ValueError(f"Permission denied: Unable to create '{logs_dir_path}'.")
        except Exception as e:
            raise ValueError(f"An error occurred: {e}")
        
    web_search_file = os.path.join(logs_dir_path, f"{state.cve_id}_web_search_{state.web_search_tool}.json")
    messages = state.messages

    # Invoking the LLM with the chosen web search mode 
    if state.web_search_tool == "custom":
        web_query = CUSTOM_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        messages += [HumanMessage(content=web_query)]
        
        # Invoke the LLM to generate the custom tool arguments
        tool_call = llm_custom_web_search_tool.invoke(messages, config={"callbacks": [langfuse_handler]})
        # Extract the tool arguments from the LLM call
        tool_call_args = json.loads(tool_call.additional_kwargs['tool_calls'][0]['function']['arguments'])
        query, cve_id = tool_call_args['query'], tool_call_args['cve_id']
        print(f"\tThe LLM invoked the 'web search' tool with parameters: query={query}, cve_id={cve_id}\n")
        #NOTE: 'web_search_tool_func' internally formats the response into a WebSearchResult Pydantic class
        formatted_response, in_token, out_token = web_search_tool_func(query=query, cve_id=cve_id, verbose=False)
    
    elif state.web_search_tool == "custom_no_tool":
        #NOTE: 'web_search_func' internally formats the response into a WebSearchResult Pydantic class
        formatted_response, in_token, out_token = web_search_func(state.cve_id, verbose=False)
    
    elif state.web_search_tool == "openai":
        web_query = OPENAI_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        messages += [HumanMessage(content=web_query)]
        
        # Invoke the LLM to perform the web search and extract the token usage
        web_search_result = llm_openai_web_search_tool.invoke(messages, config={"callbacks": [langfuse_handler]})
        in_token, out_token = web_search_result.usage_metadata['input_tokens'], web_search_result.usage_metadata['output_tokens']
        response_sourceless = web_search_result.content[0]["text"]
        formatted_response = web_search_llm.invoke(WEB_SEARCH_FORMAT_PROMPT.format(web_search_result=response_sourceless), config={"callbacks": [langfuse_handler]})
        
    else:
        raise ValueError("Invalid web search tool specified. Use 'custom', 'custom_no_tool', 'openai' or 'skip'.")
    
    
    # Building response to be added to messages 
    if state.web_search_tool == "custom" or state.web_search_tool == "custom_no_tool":
        response = f"CVE description: {formatted_response.desc}\nAttack Type: {formatted_response.attack_type}\nService list:"
        for service, description in zip(formatted_response.services, formatted_response.service_desc):
            response += f"\n[{service}] {description}"
            
    elif state.web_search_tool == "openai":
        response = response_sourceless + "\n\nSources:"
        source_set = set()
        for source in web_search_result.content[0]["annotations"]:
            source_set.add(f"{source['title']} ({source['url']})")
        for i, source in enumerate(source_set):
            response += f"\n{i + 1}) {source}"
            
    if state.debug == "benchmark_web_search":
        print(f"\t[TOKEN USAGE INFO] This web search used {in_token} input tokens and {out_token} output tokens")
    
    # Saving web search log
    web_search_dict = dict(formatted_response)
    web_search_dict["input_tokens"] = in_token
    web_search_dict["output_tokens"] = out_token
    if state.web_search_tool == "custom":
        web_search_dict["query"] = query
    with open(web_search_file, 'w') as fp:
        json.dump(web_search_dict, fp, indent=4)
    print(f"\tWeb search result saved to: {web_search_file}")

    return {
        "final_report": state.final_report + "="*10 + f" Web Search Result " + "="*10 + f"\n{formatted_response}\n\n",
        "web_search_result": formatted_response,
        "messages": messages + [AIMessage(content=response)],
    }


def is_version_in_range(serv: str, pred_ver: str, start: str, end: str) -> bool:
    try:
        return version.parse(start) <= version.parse(pred_ver) <= version.parse(end)
    except:
        print("\tUsing LLM-as-a-judge to assess MAIN service version...")
        # Format the version assessment query
        ver_ass_query = MAIN_SERV_VERS_ASSESSMENT_PROMPT.format(
            range="[start, end]",
            vers=pred_ver,
            service=serv,
        )

        # Invoking the LLM with the structured output
        response = ver_ass_llm.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=ver_ass_query)], 
            config={"callbacks": [langfuse_handler]}
        )
        print(f"\tResult: main_service_version={response.main_service_version}")
        return response.main_service_version
    

def assess_services(state: OverallState):
    """DEBUG: route the graph to the 'test_code' node"""
    if state.debug == "skip_to_test":
        print("[DEBUG] Skipping 'assess_services'...")
        updated_milestones = state.milestones
        updated_milestones.main_service_identified = True
        updated_milestones.main_service_version = True
        return {"milestones": updated_milestones}
    
    """Checks if the services needed to generate the vulnerable Docker code are correct by using the ones of Vulhub as GT"""
    print("Checking the Docker services...")
    filename = 'services.json'
    with open(filename, "r") as f:
        jsonServices = json.load(f)
    
    # If the services of CVE do not exist in 'services.json', update 'services.json' and skip the check
    if not jsonServices.get(state.cve_id) and state.debug != "benchmark_web_search":
        print(f"\t{state.cve_id} is not in 'services.json'! Updating 'services.json' with the following services:")
        services = []
        for serv, serv_type, serv_ver in zip(state.web_search_result.services, state.web_search_result.service_type, state.web_search_result.service_vers):
            new_service = f"{serv_type.upper()}:{serv.split("/")[-1].lower()}:{serv_ver.split("---")[0]}"
            print(f"\t- {new_service}")
            services.append(new_service)
            
        jsonServices[state.cve_id] = services
        with open(filename, "w") as f:
            json.dump(jsonServices, f, indent=4)
            
        updated_milestones = state.milestones
        updated_milestones.main_service_identified = True
        updated_milestones.main_service_version = True
        return {"milestones": updated_milestones}
    
    # Else, proceed with the check
    updated_milestones = state.milestones

    expected_services = jsonServices.get(state.cve_id)
    expected_aux_roles = set()
    for temp in expected_services:
        exp_type, exp_serv, exp_ver = temp.split(":")
        if exp_type.upper() == "MAIN":
            exp_main_serv, exp_main_ver = exp_serv.split("/")[-1], exp_ver
        if exp_type.upper() != "AUX":
            expected_aux_roles.add(exp_type.upper())
            
    # Check if the MAIN service is identified correctly
    for serv, serv_ver, serv_type in zip(state.web_search_result.services, state.web_search_result.service_vers, state.web_search_result.service_type):
        if serv_type.upper() == "MAIN":
            prop_main_serv, prop_main_ver = serv.split("/")[-1], serv_ver.split("---")
        
    if exp_main_serv.lower() == prop_main_serv.lower(): 
        updated_milestones.main_service_identified = True

    # If the LLM returned a range of vulnerable versions...
    if len(prop_main_ver) > 1:
        prop_main_ver_min, prop_main_ver_max = prop_main_ver[0], prop_main_ver[1]
        print(f"\tExpected MAIN --> {exp_main_serv}:{exp_main_ver}\tProposed MAIN --> {prop_main_serv}:[{prop_main_ver_min}, {prop_main_ver_max}]")
        if is_version_in_range(exp_main_serv, exp_main_ver, prop_main_ver_min, prop_main_ver_max):
            updated_milestones.main_service_version = True
    
    # Else, if the LLM returned a specific vulnerable version...
    elif len(prop_main_ver) == 1:
        prop_main_ver = prop_main_ver[0]
        print(f"\tExpected MAIN --> {exp_main_serv}:{exp_main_ver}\tProposed MAIN --> {prop_main_serv}:{prop_main_ver}")
        if exp_main_ver.lower() == prop_main_ver.lower():
            updated_milestones.main_service_version = True
    
    else:
        raise ValueError(f"An error occurred while extracting the versions of the proposed MAIN service")
    
    # Check if at least one 'AUX' service was proposed for each role
    proposed_aux_roles = set(state.web_search_result.service_type)
    for role in expected_aux_roles:
        if role not in proposed_aux_roles:
            print(f"\t{role} service not proposed!")
            updated_milestones.aux_roles_ok = False
    
    return {"milestones": updated_milestones}


def route_services(state: OverallState) -> Literal["Ok", "Not Ok"]:
    """DEBUG: route the graph to the 'test_code' node"""
    if state.debug == "skip_to_test":
        print("[DEBUG] Skipping 'route_services'...")
        return "Ok"
    
    """Route to the code generator or terminate the graph"""
    print(f"Routing services (main_service_identified={state.milestones.main_service_identified}, main_service_version={state.milestones.main_service_version}, aux_roles_ok={state.milestones.aux_roles_ok})")
    if state.milestones.main_service_identified and state.milestones.main_service_version and state.milestones.aux_roles_ok and state.debug != "benchmark_web_search":
        return "Ok"
    else:
        if state.debug == "benchmark_web_search":
            print("[BENCHMARK] Web search benchmark terminated!")
        return "Not Ok"


def generate_code(state: OverallState):
    """DEBUG: route the graph to the 'test_code' node"""
    if state.debug == "skip_to_test":
        print("[DEBUG] Skipping 'generate_code'...")
        return {}
    
    """The agent generates/fixes the docker code to reproduce the CVE"""
    print("Generating the code...")
    # Format the code generation query
    code_gen_query = CODING_PROMPT.format(
        cve_id=state.cve_id,
        desc=state.web_search_result.desc,
        att_type=state.web_search_result.attack_type,
        serv=state.web_search_result.services,
        serv_vers=state.web_search_result.service_vers,
        serv_type=state.web_search_result.service_type,
        serv_desc=state.web_search_result.service_desc,
    )
    
    # Invoking the LLM with the structured output
    generated_code = code_generation_llm.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=code_gen_query)], 
        config={"callbacks": [langfuse_handler]}
    )
    
    # Format the LLM response
    response = f"Directory tree:\n{generated_code.directory_tree}\n\n"
    for name, code in zip(generated_code.file_name, generated_code.file_code):
        response += "-" * 10 + f" {name} " + "-" * 10 + f"\n{code}\n\n"

    print("Code generated!")
    # Return state updates
    return {
        "final_report": state.final_report + "="*10 + f" Generated Code (First Version) " + "="*10 + f"\n{response}\n\n",
        "code": generated_code,
        "messages": state.messages + [
            HumanMessage(content=code_gen_query),
            AIMessage(content=response),
        ],
    }


def save_code(state: OverallState):
    """DEBUG: route the graph to the 'test_code' node"""
    if state.debug == "skip_to_test":
        print("[DEBUG] Skipping 'save_code'...")
        return {"debug": ""}    # Since the next node is 'test_code'
    
    """The agent saves the tested code in a local directory structured as the directory tree"""
    print("Saving code...")
    docker_dir_path = Path(f"./../../dockers/{state.cve_id}")
    if not docker_dir_path.exists():
        try:
            docker_dir_path.mkdir(parents=True, exist_ok=False)
            print(f"\tDirectory '{docker_dir_path}' created successfully.")
        except PermissionError:
            raise ValueError(f"Permission denied: Unable to create '{docker_dir_path}'.")
        except Exception as e:
            raise ValueError(f"An error occurred: {e}")

    # Save each file in the appropriate location
    for file_rel_path, file_content in zip(state.code.file_name, state.code.file_code):
        full_path = docker_dir_path / file_rel_path
        if not full_path.exists():
            try:
                full_path.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise ValueError(f"Permission denied: Unable to create '{full_path}'.")
            except Exception as e:
                raise ValueError(f"An error occurred: {e}")
        
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(file_content)
        print(f"\tSaved file: {full_path}")

    print("Code saved!")
    return {}


def test_code(state: OverallState):
    """The agent tests the docker to check if it work correctly"""    
    print("Testing code...")
    if state.test_iteration >= 10:     #TODO: decide the maximum number of iterations
        print("\tMax Iterations Reached!")
        return {"feedback": TestCodeResult(code_ok=True, error="", fix="", fixed_code=state.code)}
    
    docker_dir_path = Path(f"./../../dockers/{state.cve_id}")
    logs_dir_path = docker_dir_path / "logs"
    
    # Create the directory to save logs (if it does not exist)
    if not logs_dir_path.exists():
        try:
            logs_dir_path.mkdir(parents=True, exist_ok=False)
            print(f"\tDirectory '{logs_dir_path}' created successfully.")
        except PermissionError:
            raise ValueError(f"Permission denied: Unable to create '{logs_dir_path}'.")
        except Exception as e:
            raise ValueError(f"An error occurred: {e}")
        
    # Create the log file in the 'logs' subdirectory
    log_file = os.path.join(logs_dir_path, f"{state.cve_id}_log{state.test_iteration}.txt")

    # Launch the docker and save the output in the log file
    with open(log_file, "w") as log:
        process = subprocess.Popen(
            ["sudo", "docker", "compose", "up"],
            cwd=docker_dir_path,
            stdout=log,
            stderr=subprocess.STDOUT
        )
        process.communicate()

    print(f"\tTest logs saved to: {log_file}")
    # Extract the log content
    with open(log_file, "r") as f:
        log_content = f.read()
    
    # Format the current code into a string
    code = ""
    for name, content in zip(state.code.file_name, state.code.file_code):
        code += "-" * 10 + f" {name} " + "-" * 10 + f"\n{content}\n\n"
        
    # Saving the Pydantic object that stores the code into a JSON file
    formatted_code = f"'code': CodeGenerationResult(\nfile_name={state.code.file_name},\nfile_code={state.code.file_code},\ndirectory_tree='{state.code.directory_tree}',\n),"
    code_file = os.path.join(logs_dir_path, f"{state.cve_id}_code.txt")
    with open(code_file, "w") as log:
        log.write(formatted_code)
        
    # Format the test code query
    test_code_query = TEST_CODE_PROMPT.format(
        dir_tree=state.code.directory_tree,
        code=code,
        log_content=log_content,
        cve_id=state.cve_id,
        desc=state.web_search_result.desc,
        att_type=state.web_search_result.attack_type,
        serv=state.web_search_result.services,
        serv_vers=state.web_search_result.service_vers,
        serv_type=state.web_search_result.service_type,
        serv_desc=state.web_search_result.service_desc,
    )

    # Invoke the LLM with the structured output to analyse the log content
    test_code_results = test_code_llm.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=test_code_query)],
        config={"callbacks": [langfuse_handler]}
    )

    # Format the LLM response
    if test_code_results.code_ok:
        response = f"Test passed!\n\n"
        print("Test passed!")
        
        # Format the working code into a string
        formatted_code = f"Directory tree:\n{state.code.directory_tree}\n\n"
        for name, code in zip(state.code.file_name, state.code.file_code):
            formatted_code += "-" * 10 + f" {name} " + "-" * 10 + f"\n{code}\n\n"
            
        # Saving the final report
        final_report = state.final_report + "="*10 + f" Test Passed! Generated Code (Final Version) " + "="*10 + f"\n{formatted_code}",
        final_report_file = os.path.join(logs_dir_path, f"{state.cve_id}_final_report.txt")        
        with open(final_report_file, "w") as log:
            log.write(final_report[0])
        
        # Return state updates
        return {
            "final_report": final_report[0],
            "feedback": test_code_results,
            "test_iteration": state.test_iteration + 1,
            "messages": state.messages + [
                HumanMessage(content=test_code_query),
                AIMessage(content=response)
            ],
        }
    else:
        response = "="*10 + f" Test Failed! (iteration={state.test_iteration}) " + "="*10 + f"\n----- Error Description -----\n{test_code_results.error}\n----- Applied Fix -----\n{test_code_results.fix}\n\n"
        print("Test failed!")
        
        # Ensure Docker is stopped and containers and volumes are removed
        subprocess.run(
            ["sudo", "docker", "compose", "down", "--volumes"],
            cwd=docker_dir_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Ensure that the Docker image is removed in order to apply fixes
        subprocess.run(
            ["sudo", "docker", "rmi", "-f"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Return state updates
        return {
            "final_report": state.final_report + response,
            "code": test_code_results.fixed_code,
            "feedback": test_code_results,
            "test_iteration": state.test_iteration + 1,
            "messages": state.messages + [
                HumanMessage(content=test_code_query),
                AIMessage(content=response)
            ],
        }


def route_code(state: OverallState) -> Literal["Stop Testing", "Keep Testing"]:
    """Route back to fix the code or terminate the graph"""
    print(f"Routing test (code_ok = {state.feedback.code_ok}, test_iteration = {state.test_iteration})")
    if state.feedback.code_ok:
        return "Stop Testing"
    else:
        return "Keep Testing"