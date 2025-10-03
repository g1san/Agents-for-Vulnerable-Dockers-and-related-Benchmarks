import os
import time
import json
import requests
import builtins
import subprocess
from pathlib import Path
from typing import Literal
from langchain_openai import ChatOpenAI
from langchain.chat_models import init_chat_model
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
    HARD_SERV_VERS_ASSESSMENT_PROMPT, 
    CODING_PROMPT,
    IMAGE_NOT_BUILT_PROMPT,
    ASSERT_CONTAINER_STATE_PROMPT,
    CONTAINER_NOT_RUN_PROMPT,
    CHECK_SERVICES_PROMPT,
    NOT_VULNERABLE_VERSION_PROMPT,
    WRONG_NETWORK_SETUP_PROMPT,
)
from configuration import (
    langfuse_handler,
    WebSearchResult,
    HARDServiceVersionAssessment,
    CodeGenerationResult,
    TestCodeResult,
    ContainerLogsAssessment,
    CodeMilestonesAssessment,
)

# Initialize the LLM with OpenAI's GPT-4o model
# llm = ChatOpenAI(model="gpt-4o", temperature=0.5, max_retries=2)
# Initialize the LLM with OpenAI's GPT-5 model
llm = ChatOpenAI(
    model="gpt-5", 
    max_retries=2,
    reasoning_effort="low", 
    # use_responses_api=True, 
    # verbosity="low",
)
# Initialize the LLM with SmartData cluster's local model
# llm = ChatOpenAI(
#     model="mistralai/Mistral-7B-Instruct-v0.1",
#     base_url="https://kubernetes.polito.it/vllm/v1",
#     api_key=os.getenv("SDC_API_KEY"),
#     max_tokens=16000,
# )
llm_openai_web_search_tool = llm.bind_tools([openai_web_search])
llm_custom_web_search_tool = llm.bind_tools([web_search])
web_search_llm = llm.with_structured_output(WebSearchResult)
ver_ass_llm = llm.with_structured_output(HARDServiceVersionAssessment)
code_generation_llm = llm.with_structured_output(CodeGenerationResult)
code_ass_llm = llm.with_structured_output(CodeMilestonesAssessment)
container_ass_llm = llm.with_structured_output(ContainerLogsAssessment)
revise_code_llm = llm.with_structured_output(TestCodeResult)


def create_dir(dir_path):
    try:
        dir_path.mkdir(parents=True, exist_ok=False)
        print(f"\tDirectory '{dir_path}' created successfully.")
    except PermissionError:
        raise ValueError(f"Permission denied: Unable to create '{dir_path}'.")
    except Exception as e:
        raise ValueError(f"An error occurred: {e}")


def get_cve_id(state: OverallState):
    """Checks if the CVE ID is correctly retrieved from the initialized state"""
    print(f"The provided CVE ID is {state.cve_id.upper()}!")
    
    logs_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/logs")
    if not logs_dir_path.exists():
        create_dir(dir_path=logs_dir_path)
        
    updated_final_report = "="*10 + f" {state.cve_id} Final Report "  + "="*10
    updated_final_report += "\n\n" + "-"*10 + f" Initial Parameters " + "-"*10 
    updated_final_report += f"\n'model': {state.model}\n'cve_id': {state.cve_id}\n'web_search_tool': {state.web_search_tool}\n'verbose_web_search': {state.verbose_web_search}\n'web_search_result': {state.web_search_result}"
    updated_final_report += f"\n'code': {state.code}\n'messages': {state.messages}\n'milestones': {state.milestones}\n'debug': {state.debug}\n"
    updated_final_report += "-"*40 + "\n\n"
    
    final_report_file = logs_dir_path / "final_report.txt"
    with builtins.open(final_report_file, "w") as f:
        f.write(updated_final_report)
    
    return {"cve_id": state.cve_id.upper()}


def assess_cve_id(state: OverallState):    
    """The agent checks if the CVE ID exists in the MITRE CVE database"""
    print("\nChecking if the CVE ID exists...")
    response = requests.get(f"https://cveawg.mitre.org/api/cve/{state.cve_id}")
    
    logs_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/logs")
    final_report_file = logs_dir_path / "final_report.txt"

    if response.status_code == 200:
        print(f"\t{state.cve_id} exists!")
        
        if not logs_dir_path.exists():
            create_dir(dir_path=logs_dir_path)
        
        state.milestones.cve_id_ok = True        
        return {"milestones": state.milestones}

    elif response.status_code == 404:
        output_string = f"The record for {state.cve_id} does not exist."
        print(output_string)
        
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
            
        return {}

    else:
        output_string = f"Failed to fetch CVE: {response.status_code}"
        print(output_string)
        
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
            
        return {}


def route_cve(state: OverallState) -> Literal["Found", "Not Found"]:
    """Terminate the graph or go to the next step"""
    print(f"\nRouting CVE (cve_id_ok = {state.milestones.cve_id_ok})")
    if state.milestones.cve_id_ok:
        return "Found"
    else:
        milestone_file = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/logs/milestones.json")
        with builtins.open(milestone_file, "w") as f:
            json.dump(state.milestones.model_dump(), f, indent=4)

        print("\nExecution Terminated!\n\n\n")
        return "Not Found"
    

def get_services(state: OverallState):
    """The agent performs a web search to gather relevant information about the services needed to generate the vulnerable Docker code"""
    print("\nSearching the web...")
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    logs_dir_path = code_dir_path / "logs"
    
    if state.web_search_result.desc != "":
        print("\tWeb search results already provided!")
        response = f"CVE description: {state.web_search_result.desc}\nAttack Type: {state.web_search_result.attack_type}\nServices (format: [SERVICE-DEPENDENCY-TYPE][SERVICE-NAME][SERVICE-VERSIONS] SERVICE-DESCRIPTION):"
        for service in state.web_search_result.services:
            response += f"\n- [{service.dependency_type}][{service.name}][{service.version}] {service.description}"
        
        final_report_file = logs_dir_path / "final_report.txt"
        with builtins.open(final_report_file, "a") as f:
            f.write(response)
            
        return {"messages": state.messages + [AIMessage(content=response)]}
    
    # Create the directory to save logs (if it does not exist)
    if not logs_dir_path.exists():
        create_dir(dir_path=logs_dir_path)
        
    # Invoking the LLM with the chosen web search mode 
    if state.web_search_tool == "custom":
        web_query = CUSTOM_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        
        # Invoke the LLM to generate the custom tool arguments
        tool_call = llm_custom_web_search_tool.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=web_query)],
            config={"callbacks": [langfuse_handler]}
        )
        # Extract the tool arguments from the LLM call
        tool_call_args = json.loads(tool_call.additional_kwargs['tool_calls'][0]['function']['arguments'])
        query, cve_id = tool_call_args['query'], tool_call_args['cve_id']
        print(f"\tThe LLM invoked the 'web search' tool with parameters: query={query}, cve_id={cve_id}")
        #NOTE: 'web_search_tool_func' internally formats the response into a WebSearchResult Pydantic class
        formatted_response, in_token, out_token = web_search_tool_func(query=query, cve_id=cve_id, n_documents=5, verbose=state.verbose_web_search, model=state.model)
    
    elif state.web_search_tool == "custom_no_tool":
        #NOTE: 'web_search_func' internally formats the response into a WebSearchResult Pydantic class
        formatted_response, in_token, out_token = web_search_func(cve_id=state.cve_id, n_documents=5, verbose=state.verbose_web_search, model=state.model)
    
    elif state.web_search_tool == "openai":
        web_query = OPENAI_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        
        # Invoke the LLM to perform the web search and extract the token usage
        web_search_result = llm_openai_web_search_tool.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=web_query)],
            config={"callbacks": [langfuse_handler]}
        )
        in_token, out_token = web_search_result.usage_metadata['input_tokens'], web_search_result.usage_metadata['output_tokens']
        response_sourceless = web_search_result.content[0]["text"]
        
        # Invoke the LLM to convert the web search results into a structured output
        formatted_response = web_search_llm.invoke(
            WEB_SEARCH_FORMAT_PROMPT.format(web_search_result=response_sourceless), 
            config={"callbacks": [langfuse_handler]}
        )
        
    else:
        raise ValueError("Invalid web search tool specified. Use 'custom', 'custom_no_tool' or 'openai'.")
    
    
    # Building response to be added to messages 
    response = f"\nCVE description: {formatted_response.desc}\nAttack Type: {formatted_response.attack_type}\nServices (format: [SERVICE-DEPENDENCY-TYPE][SERVICE-NAME][SERVICE-VERSIONS] SERVICE-DESCRIPTION):\n"
    for service in formatted_response.services:
        response += f"- [{service.dependency_type}][{service.name}][{service.version}] {service.description}\n"
        
    final_report_file = logs_dir_path / "final_report.txt"
    with builtins.open(final_report_file, "a") as f:
        f.write(response)
            
    print(f"\t[TOKEN USAGE INFO] This web search used {in_token} input tokens and {out_token} output tokens")
    
    # Saving web search log
    web_search_dict = formatted_response.model_dump()
    web_search_dict["input_tokens"] = in_token
    web_search_dict["output_tokens"] = out_token
    if state.web_search_tool == "custom":
        web_search_dict["query"] = query
    
    web_search_file = logs_dir_path / f"web_search_results.json"
    with builtins.open(web_search_file, 'w') as fp:
        json.dump(web_search_dict, fp, indent=4)
    print(f"\tWeb search result saved to: {web_search_file}")

    return {
        "web_search_result": formatted_response,
        "messages": state.messages + [AIMessage(content=response)],
    }
    

def assess_services(state: OverallState):
    """Checks if the services needed to generate the vulnerable Docker code are correct by using the ones of Vulhub as GT"""
    print("\nChecking the Docker services...")
    filename = 'services.json'
    with builtins.open(filename, "r") as f:
        jsonServices = json.load(f)
    
    #! Check again this approach !#
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    logs_dir_path = code_dir_path / "logs"
    final_report_file = logs_dir_path / "final_report.txt"
        
    if not jsonServices.get(state.cve_id):
        state.milestones.hard_service = True
        state.milestones.hard_version = True
        state.milestones.soft_services = True
        
        output_string = f"{state.cve_id} is not in 'services.json'! Skipping the 'hard_service', 'hard_version' and 'soft_services' milestones checks."
        print(f"\t{output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
        
        return {"milestones": state.milestones}
    
    # Else, proceed with the milestone checks
    expected_services = jsonServices.get(state.cve_id)
    expected_hard = {}
    expected_soft_roles = set()
    for service in expected_services:
        dep_type, serv, ver = service.split(":")
        if dep_type == "HARD":
            if serv.split("/")[-1] not in expected_hard.keys():
                expected_hard[serv.split("/")[-1].lower()] = ver
            else:
                expected_hard[serv.split("/")[-1].lower()] += ver
        elif dep_type != "SOFT":
            expected_soft_roles.add(dep_type)
            
    proposed_hard = {}
    proposed_soft_roles = set()
    for service in state.web_search_result.services:
        if service.dependency_type == "HARD":
            if service.name.split("/")[-1].lower() not in proposed_hard.keys():
                proposed_hard[service.name.split("/")[-1].lower()] = service.version
            else:
                proposed_hard[service.name.split("/")[-1].lower()] += service.version
        elif service.dependency_type != "SOFT":
            proposed_soft_roles.add(service.dependency_type)
    
    # Check if all expected 'HARD' services were proposed
    if set(expected_hard.keys()).issubset(set(proposed_hard.keys())):
        state.milestones.hard_service = True
        print("\t- 'hard_service'=True")
    else:
        output_string = "Expected 'HARD' dependencies service not proposed!"
        print(f"\t{output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
        

    # Check if the vulnerable version of all expected 'HARD' services was proposed
    response_list = []
    for service, version_list, version in zip(proposed_hard.keys(), proposed_hard.values(), expected_hard.values()):
        ver_ass_query = HARD_SERV_VERS_ASSESSMENT_PROMPT.format(
            version=version,
            service=service,
            version_list=version_list,
        )

        response = ver_ass_llm.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=ver_ass_query)], 
            config={"callbacks": [langfuse_handler]}
        )
        response_list.append(response.hard_version)
        
    if False not in response_list:
        state.milestones.hard_version = True
        print("\t- 'hard_version'=True")
        
    else:
        output_string = "Expected 'HARD' dependencies version not proposed!"
        print(f"\t{output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
            
    # Check if all expected 'SOFT' roles were proposed
    if set(expected_soft_roles).issubset(set(proposed_soft_roles)):
        state.milestones.soft_services = True
        print("\t- 'soft_services'=True")
    else:
        output_string = "Expected 'SOFT' role(s) not proposed!"
        print(f"\t{output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
    
    return {"milestones": state.milestones}


def route_services(state: OverallState) -> Literal["Ok", "Not Ok"]:    
    """Route to the code generator or terminate the graph"""
    print(f"\nRouting services (hard_service={state.milestones.hard_service}, hard_version={state.milestones.hard_version}, soft_services={state.milestones.soft_services})")
    if state.milestones.hard_service and state.milestones.hard_version and state.milestones.soft_services:
        return "Ok"
    else:
        milestone_file = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/logs/milestones.json")
        with builtins.open(milestone_file, "w") as f:
            json.dump(state.milestones.model_dump(), f, indent=4)

        print("\nExecution Terminated!\n\n\n")
        return "Not Ok"


def generate_code(state: OverallState):
    """The agent generates/fixes the docker code to reproduce the CVE"""
    print("\nGenerating the code...")
    if state.code.directory_tree != "":
        print("\tCode already provided!")        
        return {}
    
    final_report_file = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/logs/final_report.txt")
    
    code_gen_query = CODING_PROMPT.format(
        cve_id=state.cve_id,
        mode=state.web_search_tool,
    )
    
    generated_code = code_generation_llm.invoke(
        state.messages + [HumanMessage(content=code_gen_query)], 
        config={"callbacks": [langfuse_handler]}
    )
    
    response = f"Directory tree:\n{generated_code.directory_tree}\n\n"
    for name, code in zip(generated_code.file_name, generated_code.file_code):
        response += "-" * 10 + f" {name} " + "-" * 10 + f"\n{code}\n\n"
        
    output_string = f"\nThis is the first version of the generated code:\n\n{response}\n\n"
    with builtins.open(final_report_file, "a") as f:
        f.write(output_string)
        
    print("\tCode generated!")
    return {"code": generated_code}


def save_code(state: OverallState):
    """The agent saves the tested code in a local directory structured as the directory tree"""
    print("\nSaving code...")
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    if not code_dir_path.exists():
        create_dir(dir_path=code_dir_path)
        
    code_file = code_dir_path / "logs/code.json"
    with builtins.open(code_file, "w") as f:
        json.dump(state.code.model_dump(), f, indent=4)
    
    for file_path, file_content in zip(state.code.file_name, state.code.file_code):
        file_path = Path(file_path)
        if not file_path.exists():
            # Different from create_dir()
            try:
                file_path.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise ValueError(f"Permission denied: Unable to create '{file_path}'.")
            except Exception as e:
                raise ValueError(f"An error occurred: {e}")

        with builtins.open(file_path, "w", encoding="utf-8") as f:
            f.write(file_content)
        print(f"\tSaved file: {file_path}")

    print("\tCode saved!")
    return {}


#* Support Functions for the 'test_code' node *#
def launch_docker(code_dir_path, log_file):
    result = subprocess.run(
        ["sudo", "docker", "compose", "up", "--build", "--detach"],
        cwd=code_dir_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    logs = result.stdout
    with builtins.open(log_file, "w") as f:
        f.write(logs)
    
    success = (result.returncode == 0)
    return success, logs


def get_container_ids(code_dir_path):
    result = subprocess.run(
        ["sudo", "docker", "compose", "ps", "-a", "--quiet"],
        cwd=code_dir_path,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().splitlines()


def assert_container_state(code_dir_path, log_file):
    container_ids = get_container_ids(code_dir_path=code_dir_path)
    time.sleep(10)
    for cid in container_ids:
        result = subprocess.run(
            ["sudo", "docker", "logs", cid, "--details"],
            capture_output=True,
            text=True
        )
        
        logs = f"\n\nsudo docker logs {cid} --details\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}\n\n"
        with builtins.open(log_file, "a") as f:
            f.write(logs)
        
        query = ASSERT_CONTAINER_STATE_PROMPT.format(logs=logs)
        result = container_ass_llm.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)], 
            config={"callbacks": [langfuse_handler]}
        )
        
        if not result.container_ok:
            return logs, result.fail_explanation, False
    
    return "", "", True


def check_services(code, services, hard_service_versions, code_dir_path, log_file):
    container_ids = get_container_ids(code_dir_path=code_dir_path)

    inspect_logs = []
    for cid in container_ids:
        result = subprocess.run(
            ["sudo", "docker", "inspect", cid],
            capture_output=True,
            text=True
        )
        
        try:
            data = json.loads(result.stdout)
            inspect_logs.append(data)            
            with builtins.open(log_file, "a") as f:
                f.write(f"\n\nsudo docker inspect {cid}")
                json.dump(data, f, indent=4)
                
        except json.JSONDecodeError:
            raise ValueError(f"Failed to parse JSON for container {cid}")
    
    query = CHECK_SERVICES_PROMPT.format(
        inspect_logs=inspect_logs,
        service_list=services,
        hard_service_versions=hard_service_versions,
    )
    
    return inspect_logs, len(container_ids), code_ass_llm.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=code), HumanMessage(content=query)], 
        config={"callbacks": [langfuse_handler]}
    )
    

def get_cve_list(code_dir_path):
    with builtins.open(f"{code_dir_path}/logs/cves.json", "w") as f:
        subprocess.run(
            ["docker", "scout", "cves", "--format", "gitlab"],
            cwd=code_dir_path,
            stdout=f,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        print(f"\tCVE List file saved to: {code_dir_path}/logs/cves.json")


def down_docker(code_dir_path):
    # Ensure Docker is down and containers and volumes are removed
    subprocess.run(
        ["sudo", "docker", "compose", "down", "--volumes"],
        cwd=code_dir_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def remove_all_images():
    image_ids = subprocess.check_output(["docker", "images", "-aq"]).decode().split()

    if image_ids:
        subprocess.run(
            ["docker", "rmi", "-f"] + image_ids,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )


def test_code(state: OverallState):
    """The agent tests the docker to check if it work correctly"""    
    print("\nTesting code...")
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    logs_dir_path = code_dir_path / "logs"
    log_file = logs_dir_path / f"log{state.stats.test_iteration}.txt"
    final_report_file = logs_dir_path / "final_report.txt"
    if not logs_dir_path.exists():
        create_dir(dir_path=logs_dir_path)
    
    test_fail_output_string = f"\n\nTest iteration #{state.stats.test_iteration} failed! See 'log{state.stats.test_iteration}.txt' for details."
    
    success, logs = launch_docker(
        code_dir_path=code_dir_path, 
        log_file=log_file
    )  
    if not success:
        state.stats.image_build_failures += 1
        if state.stats.test_iteration == 0:
            state.stats.starting_image_builds = False
            state.stats.starting_container_runs = False
        
        test_fail_output_string += f"\n\t- IMAGE BUILDING FAILURE"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
            
        return {
            "stats": state.stats,
            "logs": logs,
            "fail_explanation": "",
            "revision_type": "Image Not Built",
        }
        
    logs, fail_explanation, assessment = assert_container_state(
        code_dir_path=code_dir_path, 
        log_file=log_file
    )
    if not assessment:
        state.stats.container_run_failures += 1
        if state.stats.test_iteration == 0:
            state.stats.starting_container_runs = False
        
        test_fail_output_string += f"\n\t- CONTAINER FAILURE: {fail_explanation}"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
            
        return {
            "stats": state.stats,
            "logs": logs,
            "fail_explanation": fail_explanation,
            "revision_type": "Container Not Running",
        }
    
    service_list = []
    hard_service_versions = ""
    for service in state.web_search_result.services:
        service_list.append(service.name)
        if service.dependency_type == "HARD":
            hard_service_versions += f"\n\t\t- {service.name}: {service.version}"
    
    code = "This is the Docker code:\n"
    for name, content in zip(state.code.file_name, state.code.file_code):
        code += "-" * 10 + f" {name} " + "-" * 10 + f"\n{content}\n\n"
    
    inspect_logs, num_containers, result = check_services(
        code=code,
        services=service_list, 
        hard_service_versions=hard_service_versions,
        code_dir_path=code_dir_path,
        log_file=log_file,
    )
    llm_aaj = f"\tLLM-as-a-Judge Milestone Check Values:"
    llm_aaj += f"\n\t- docker_builds={result.docker_builds}"
    llm_aaj += f"\n\t- docker_runs={result.docker_runs}"
    llm_aaj += f"\n\t- code_hard_version={result.code_hard_version}"
    llm_aaj += f"\n\t- network_setup={result.network_setup}"
    llm_aaj += f"\n\t- services_ok={result.services_ok}"
    print(llm_aaj)
            
    if not result.docker_builds:
        state.stats.image_build_failures += 1
        if state.stats.test_iteration == 0:
            state.stats.starting_image_builds = False
            state.stats.starting_container_runs = False
        
        test_fail_output_string += f"\n\t- MILESTONE CHECK FAILURE (IMAGE BUILDING FAILURE): {result.fail_explanation}"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
            
        return {
            "stats": state.stats,
            "logs": '\n'.join(str(log) for log in inspect_logs),
            "fail_explanation": result.fail_explanation,
            "revision_type": "Image Not Built",
        }
    
    if not result.docker_runs:
        state.stats.container_run_failures += 1
        if state.stats.test_iteration == 0:
            state.stats.starting_container_runs = False
        
        test_fail_output_string += f"\n\t- MILESTONE CHECK FAILURE (CONTAINER FAILURE): {result.fail_explanation}"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
            
        return {
            "stats": state.stats,
            "logs": '\n'.join(str(log) for log in inspect_logs),
            "fail_explanation": result.fail_explanation,
            "revision_type": "Container Not Running",
        }
        
    if not result.code_hard_version:
        state.stats.not_vuln_version_fail += 1
        
        test_fail_output_string += f"\n\t- MILESTONE CHECK FAILURE (NOT VULNERABLE VERSION): {result.fail_explanation}"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
            
        return {
            "stats": state.stats,
            "logs": "",
            "fail_explanation": result.fail_explanation,
            "revision_type": "Not Vulnerable Version",
        }
        
    if not result.network_setup:
        state.stats.docker_misconfigured += 1
        
        test_fail_output_string += f"\n\t- MILESTONE CHECK FAILURE (WRONG NETWORK SETUP): {result.fail_explanation}"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
            
        return {
            "stats": state.stats,
            "logs": '\n'.join(str(log) for log in inspect_logs),
            "fail_explanation": result.fail_explanation,
            "revision_type": "Wrong Network Setup",
        }

    print(f"\tDocker is running correctly with {num_containers} containers!")
    state.milestones.docker_builds = result.docker_builds
    state.milestones.docker_runs = result.docker_runs
    state.milestones.code_hard_version = result.code_hard_version
    state.milestones.network_setup = result.network_setup
    state.milestones.services_ok = result.services_ok
    
    formatted_code = f"Directory tree:\n{state.code.directory_tree}\n\n"
    for name, code in zip(state.code.file_name, state.code.file_code):
        formatted_code += "-" * 10 + f" {name} " + "-" * 10 + f"\n{code}\n\n"
        
    output_string = f"\n\nDocker is running correctly with {num_containers} containers!\n\nThis is the final version of the generated code:\n\n{formatted_code}\n\n"
    with builtins.open(final_report_file, "a") as f:
        f.write(f"{output_string}")

    state.stats.num_containers = num_containers
    return {
        "stats": state.stats,
        "milestones": state.milestones,
    }


def route_test(state: OverallState) -> Literal["Stop Testing", "Revise Code"]:
    """Route back to fix the code or stop testing"""
    output_string = "\nRouting test:\n"
    output_string += f"\t- docker_builds={state.milestones.docker_builds}\n"
    output_string += f"\t- docker_runs={state.milestones.docker_runs}\n"
    output_string += f"\t- code_hard_version={state.milestones.code_hard_version}\n"
    output_string += f"\t- network_setup={state.milestones.network_setup}\n"
    output_string += f"\t- test_iteration={state.stats.test_iteration}"
    print(output_string)
    
    if state.milestones.docker_builds and state.milestones.docker_runs and state.milestones.code_hard_version and state.milestones.network_setup:        
        return "Stop Testing"
    elif state.stats.test_iteration + 1 >= 10:
        print("\tMax Iterations Reached!")
        return "Stop Testing"
    else:            
        return "Revise Code"
    
    
def revise_code(state: OverallState):
    """The agent is tasked with revising the Docker's code to fix the errors"""
    print("\nRevising code...")
    # state.milestones.docker_builds = False
    # state.milestones.docker_runs = False
    # state.milestones.code_hard_version = False
    # state.milestones.services_ok = False
    
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    final_report_file = code_dir_path / "logs/final_report.txt"
    down_docker(code_dir_path=code_dir_path)
    
    if state.revision_type == "Image Not Built":
        query = IMAGE_NOT_BUILT_PROMPT.format(
            fail_explanation=state.fail_explanation,
            # Passing just the last 100 lines of logs to mitigate ContextWindow saturation
            logs="\n".join(state.logs.splitlines()[-100:]),
            fixes=state.fixes,
            cve_id=state.cve_id,
            mode=state.web_search_tool,
        )
        
    elif state.revision_type == "Container Not Running":
        query = CONTAINER_NOT_RUN_PROMPT.format(
            fail_explanation=state.fail_explanation,
            # Passing just the last 100 lines of logs to mitigate ContextWindow saturation
            logs="\n".join(state.logs.splitlines()[-100:]),
            fixes=state.fixes,
            cve_id=state.cve_id,
            mode=state.web_search_tool,
        )
    
    elif state.revision_type == "Not Vulnerable Version":
        query = NOT_VULNERABLE_VERSION_PROMPT.format(
            fail_explanation=state.fail_explanation,
            logs="",
            cve_id=state.cve_id,
            mode=state.web_search_tool,
        )
        
    elif state.revision_type == "Wrong Network Setup":
        query = WRONG_NETWORK_SETUP_PROMPT.format(
            fail_explanation=state.fail_explanation,
            # Passing just the last 100 lines of logs to mitigate ContextWindow saturation
            logs="\n".join(state.logs.splitlines()[-100:]),
            cve_id=state.cve_id,
            mode=state.web_search_tool,
        )
        
    code = "This is the code you have to revise:\n"
    for name, content in zip(state.code.file_name, state.code.file_code):
        code += "-" * 10 + f" {name} " + "-" * 10 + f"\n{content}\n\n"
    
    revise_code_results = revise_code_llm.invoke(
        state.messages + [HumanMessage(content=code), HumanMessage(content=query)],
        config={"callbacks": [langfuse_handler]}
    )

    output_string = f"\t- ERROR: {revise_code_results.error}"
    output_string += f"\n\t- FIX: {revise_code_results.fix}"
    print(output_string)
    with builtins.open(final_report_file, "a") as f:
        f.write(f"\n{output_string}\n")

    state.stats.test_iteration += 1
    return {
        "stats": state.stats,
        "milestones": state.milestones,
        "code": revise_code_results.fixed_code,
        "fixes": state.fixes + [revise_code_results.fix],
    }


#TODO: define this function
def run_exploit(state: OverallState):
    """A PoC is used to exploit the CVE and check if the Docker is vulnerable (but only if the Docker runs)"""
    
    if state.milestones.docker_builds and state.milestones.docker_runs:
        print("\nExploiting Docker vulnerability...")
    #     code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    #     final_report_file = code_dir_path / "logs/final_report.txt"        
    #     exploit_file_path = Path(f"./../../exploits/{state.cve_id}")
    #     
    #     result = subprocess.run(
    #         ["sudo", "docker", "logs", cid, "--details"],
    #         cwd=exploit_file_path,
    #         capture_output=True,
    #         text=True
    #     )
    #     logs = f"\n\nsudo docker logs {cid} --details\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}\n\n"
    #     
    #     if check_docker_vulnerability(cve_id=state.cve_id, code_dir_path=code_dir_path):
    #         output_string = f"The Docker is vulnerable to {state.cve_id}!"
    #         print(f"\t{output_string}")
    #         state.milestones.docker_vulnerable = True
    #         with builtins.open(final_report_file, "a") as f:
    #             f.write(output_string)
        
    return {"stats": state.stats}


def route_exploit(state: OverallState) -> Literal["Assess Vuln", "Revise Code"]:
    """Route back to fix the code or assess the vulnerability"""
    output_string = "\nRouting exploit:\n"
    output_string += f"\t- docker_builds={state.milestones.docker_builds}\n"
    output_string += f"\t- docker_runs={state.milestones.docker_runs}\n"
    output_string += f"\t- code_hard_version={state.milestones.code_hard_version}\n"
    output_string += f"\t- network_setup={state.milestones.network_setup}\n"
    output_string += f"\t- test_iteration={state.stats.test_iteration}"
    print(output_string)
    
    if state.milestones.docker_builds and state.milestones.docker_runs and state.milestones.code_hard_version and state.milestones.network_setup:        
        return "Assess Vuln"
    elif state.stats.test_iteration + 1 >= 10:
        print("\tMax Iterations Reached!")
        return "Assess Vuln"
    else:            
        return "Revise Code"


def check_docker_vulnerability(cve_id, code_dir_path):
    get_cve_list(code_dir_path=code_dir_path)
    cves_file_path = code_dir_path / "logs/cves.json"
    with builtins.open(cves_file_path, "r") as f:
        cve_list = json.load(f)
    cve_list = cve_list["vulnerabilities"]
    for cve in cve_list:
        if cve["cve"] == cve_id:
            return True
    return False


def assess_vuln(state: OverallState):
    """The Docker is checked for the presence of the CVE with Docker Scout (but only if the Docker runs)"""
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    final_report_file = code_dir_path / "logs/final_report.txt"        
    
    if state.milestones.docker_builds and state.milestones.docker_runs:
        print("\nAssessing Docker vulnerability...")
        if check_docker_vulnerability(cve_id=state.cve_id, code_dir_path=code_dir_path):
            output_string = f"Docker Scout says that the Docker is vulnerable to {state.cve_id}!"
            print(f"\t{output_string}")
            state.stats.docker_scout_vulnerable = True
            with builtins.open(final_report_file, "a") as f:
                f.write(output_string)
                
    down_docker(code_dir_path=code_dir_path)
    remove_all_images()
    
    state.stats.test_iteration += 1     # Just to adjust the stats counter   
    stats_file = code_dir_path / "logs/stats.json"
    with builtins.open(stats_file, "w") as f:
        json.dump(state.stats.model_dump(), f, indent=4)
                
    milestone_file = code_dir_path / "logs/milestones.json"
    with builtins.open(milestone_file, "w") as f:
        json.dump(state.milestones.model_dump(), f, indent=4)
    
    print("\nExecution Terminated!\n\n\n")
    return {"stats": state.stats}