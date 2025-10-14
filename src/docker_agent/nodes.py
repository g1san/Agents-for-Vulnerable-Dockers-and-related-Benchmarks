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
    CHECK_CONTAINER_PROMPT,
    CONTAINER_NOT_RUN_PROMPT,
    CHECK_SERVICES_VERSIONS_PROMPT,
    CHECK_NETWORK_PROMPT,
    TEST_FAIL_PROMPT,
    NOT_VULNERABLE_VERSION_PROMPT,
    WRONG_NETWORK_SETUP_PROMPT,
)
from configuration import (
    langfuse_handler,
    WebSearch,
    HARDServiceVersionAssessment,
    Code,
    CodeRevision,
    ContainerLogsAssessment,
    ServiceAssessment,
    NetworkAssessment,
)

# Initialize the LLM with OpenAI's GPT-4o model
llm = ChatOpenAI(model="gpt-4o", temperature=0.5, max_retries=2)
# Initialize the LLM with OpenAI's GPT-5 model
# llm = ChatOpenAI(
#     model="gpt-5", 
#     max_retries=2,
#     reasoning_effort="low", 
#     # use_responses_api=True, 
#     # verbosity="low",
# )
# Initialize the LLM with SmartData cluster's local model
# llm = ChatOpenAI(
#     model="mistralai/Mistral-7B-Instruct-v0.1",
#     base_url="https://kubernetes.polito.it/vllm/v1",
#     api_key=os.getenv("SDC_API_KEY"),
#     max_tokens=16000,
# )
llm_openai_web_search_tool = llm.bind_tools([openai_web_search])
llm_custom_web_search_tool = llm.bind_tools([web_search])
web_search_llm = llm.with_structured_output(WebSearch)
ver_ass_llm = llm.with_structured_output(HARDServiceVersionAssessment)
code_generation_llm = llm.with_structured_output(Code)
container_ass_llm = llm.with_structured_output(ContainerLogsAssessment)
serv_ver_ass_llm = llm.with_structured_output(ServiceAssessment)
network_ass_llm = llm.with_structured_output(NetworkAssessment)
revise_code_llm = llm.with_structured_output(CodeRevision)


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
        #NOTE: 'web_search_tool_func' internally formats the response into a WebSearch Pydantic class
        formatted_response, in_token, out_token = web_search_tool_func(query=query, cve_id=cve_id, n_documents=5, verbose=state.verbose_web_search, model=state.model)
    
    elif state.web_search_tool == "custom_no_tool":
        #NOTE: 'web_search_func' internally formats the response into a WebSearch Pydantic class
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
    print("\tChecking if all 'HARD' services were proposed...")
    if set(expected_hard.keys()).issubset(set(proposed_hard.keys())):
        state.milestones.hard_service = True
        print("\t- 'hard_service'=True")
    else:
        output_string = "Expected 'HARD' dependencies service not proposed!"
        print(f"\t{output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
            
        return {"milestones": state.milestones}
        

    # Check if the vulnerable version of all expected 'HARD' services was proposed
    response_list = {}
    for service, version in expected_hard.items():
        print(f"\tChecking if version {version} of service '{service}' was proposed...")
        response_list[service] = False
        version_list = proposed_hard[service]
        for ver in version_list:
            if ver == version:
                response_list[service] = True
                break
        
        if not response_list[service]:   
            print(f"\tManual check failed! Switching to LLM-as-a-Judge...")
            ver_ass_query = HARD_SERV_VERS_ASSESSMENT_PROMPT.format(
                version=version,
                service=service,
                version_list=version_list,
            )

            response = ver_ass_llm.invoke(
                [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=ver_ass_query)], 
                config={"callbacks": [langfuse_handler]}
            )
            response_list[service] = response.hard_version
        
    if False not in response_list:
        state.milestones.hard_version = True
        print("\t- 'hard_version'=True")
        
    else:
        output_string = "Expected 'HARD' dependencies version not proposed!"
        print(f"\t{output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
            
    # Check if all expected 'SOFT' roles were proposed
    print("\tChecking if all 'SOFT' dependencies were proposed...")
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
    for f in generated_code.files:
        response += "-" * 10 + f" {f.location} " + "-" * 10 + f"\n{f.content}\n\n"
        
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
    
    for f in state.code.files:
        file_path = Path(f.location)
        if not file_path.exists():
            # Different from create_dir()
            try:
                file_path.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise ValueError(f"Permission denied: Unable to create '{file_path}'.")
            except Exception as e:
                raise ValueError(f"An error occurred: {e}")

        with builtins.open(file_path, "w", encoding="utf-8") as fp:
            fp.write(f.content)
        print(f"\tSaved file: {file_path}")

    print("\tCode saved!")
    return {}


#* Support Functions for the 'test_code' node *#
def launch_docker(code_dir_path, log_file):
    try: 
        result = subprocess.run(
            ["sudo", "docker", "compose", "up", "--build", "--detach"],
            cwd=code_dir_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600,  # Timeout in seconds
        )
        logs = result.stdout
        success = (result.returncode == 0)
        with builtins.open(log_file, "w") as f:
            f.write(logs)
            
        return success, logs

    except subprocess.TimeoutExpired as e:
        print(f"\t{e}")
        return False, e


def get_image_ids():
    result = subprocess.run(
        ["sudo", "docker", "images", "-q"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.splitlines()


def get_container_ids(code_dir_path):
    result = subprocess.run(
        ["sudo", "docker", "compose", "ps", "-a", "--quiet"],
        cwd=code_dir_path,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().splitlines()


def get_container_logs(cid, log_file):
    result = subprocess.run(
        ["sudo", "docker", "logs", cid, "--details"],
        capture_output=True,
        text=True
    )
    
    log = f"\n\nsudo docker logs {cid} --details\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}\n\n"
    with builtins.open(log_file, "a") as f:
        f.write(log)
    
    log = f"\n\nsudo docker logs {cid} --details\nSTDOUT: {result.stdout.splitlines()[-100:]}\nSTDERR: {result.stderr.splitlines()[-100:]}\n\n"
    return log


def inspect_image(iid, log_file):
    result = subprocess.run(
        ["sudo", "docker", "inspect", iid],
        capture_output=True,
        text=True
    )
    
    try:
        log = json.loads(result.stdout)        
        with builtins.open(log_file, "a") as f:
            f.write(f"\n\nsudo docker inspect {iid}")
            json.dump(log, f, indent=4)
            
    except json.JSONDecodeError:
        raise ValueError(f"Failed to parse JSON for container {iid}")
        
    return log[0]


def inspect_container(cid, log_file):
    result = subprocess.run(
        ["sudo", "docker", "inspect", cid],
        capture_output=True,
        text=True
    )
    
    try:
        log = json.loads(result.stdout)        
        with builtins.open(log_file, "a") as f:
            f.write(f"\n\nsudo docker inspect {cid}")
            json.dump(log, f, indent=4)
            
    except json.JSONDecodeError:
        raise ValueError(f"Failed to parse JSON for container {cid}")
        
    return log[0]


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
    
    
    #* IMAGE ASSESSMENT *#
    print("\tLaunching Docker...")
    success, logs = launch_docker(code_dir_path=code_dir_path, log_file=log_file)  
    if not success:
        state.stats.image_build_failures += 1
        if state.stats.test_iteration == 0:
            state.stats.starting_image_builds = False
            state.stats.starting_container_runs = False
        
        test_fail_output_string += f"\n\t- IMAGE BUILDING FAILURE (Manual Check)"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
        
        fail_explanation = "my Docker systems terminates its execution because of an error while building one of its images."
        revision_goal = "fix the Docker system by modifying its code (which is available in my previous message).\n"
        revision_goal += f"To understand what is wrong, analyse the last 100 lines of the logs generated by the 'sudo docker compose up --build --detach' command:\n{logs.splitlines()[-100:]}"
        return {
            "stats": state.stats,
            "fail_explanation": fail_explanation,
            "revision_goal": revision_goal,
            "revision_type": "Image Not Built",
        }
    state.milestones.docker_builds = True
    print("\tImages built! Waiting 30 seconds for containers to setup...")
    
    
    #* CONTAINER(s) ASSESSMENT *#
    time.sleep(30)      # Waiting 30 seconds (arbitrary) to allow container to launch, setup and produce logs
    image_ids = get_image_ids()
    container_ids = get_container_ids(code_dir_path=code_dir_path)    
    num_containers = len(container_ids)
    for index, cid in enumerate(container_ids):
        print(f"\tTesting container ({index + 1}/{num_containers})...")
        container_log = get_container_logs(cid=cid, log_file=log_file)
        inspect_container_log = inspect_container(cid=cid, log_file=log_file)
            
        #* Manual Check *#
        if not inspect_container_log["State"]["Running"] or inspect_container_log["State"]["Status"] != "running":
            state.stats.container_run_failures += 1
            if state.stats.test_iteration == 0:
                state.stats.starting_container_runs = False

            test_fail_output_string += f"\n\t- CONTAINER FAILURE (Manual Check):"
            print(f"{test_fail_output_string}")
            with builtins.open(final_report_file, "a") as f:
                f.write(test_fail_output_string)
                
            fail_explanation = "one of the containers of my Docker system is not running correctly."
            revision_goal = "fix the Docker system by modifying its code (which is available in my previous message).\n"
            revision_goal += f"To understand what is wrong, analyse the output logs of the container:\n{container_log}"
            return {
                "stats": state.stats,
                "fail_explanation": fail_explanation,
                "revision_goal": revision_goal,
                "revision_type": "Container Not Running",
            }
    
        #* LLM-as-a-Judge Check *#
        query = CHECK_CONTAINER_PROMPT.format(
            container_log=container_log,
            inspect_container_log=inspect_container_log,
        )
        result = container_ass_llm.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)], 
            config={"callbacks": [langfuse_handler]}
        )
    
        if not result.container_ok:
            state.stats.container_run_failures += 1
            if state.stats.test_iteration == 0:
                state.stats.starting_container_runs = False

            test_fail_output_string += f"\n\t- CONTAINER FAILURE (LLM-as-a-Judge Check): {result.fail_explanation}"
            print(f"{test_fail_output_string}")
            with builtins.open(final_report_file, "a") as f:
                f.write(test_fail_output_string)

            revision_goal = "fix the Docker system by modifying its code (which is available in my previous message)."
            return {
                "stats": state.stats,
                "fail_explanation": result.fail_explanation,
                "revision_goal": revision_goal,
                "revision_type": "Container Not Running",
            }
    state.milestones.docker_runs = True
    print("\tContainers are running! Checking services and versions...")
    
    
    #* SERVICE(s) and VERSION ASSESSMENT *#
    service_list = []
    hard_service_versions = ""
    for service in state.web_search_result.services:
        service_list.append(service.name)
        if service.dependency_type == "HARD":
            hard_service_versions += f"\n\t\t- {service.name}: {service.version}"
    
    code = "This is the Docker code:\n"
    for f in state.code.files:
        code += "-" * 10 + f" {f.location} " + "-" * 10 + f"\n{f.content}\n\n"
    
    image_inspect_logs = "These are the output of the 'docker inspect' command of each Docker Image:\n"
    for iid in image_ids:
        image_inspect_logs += f"{inspect_image(iid=iid, log_file=log_file)}\n\n"
    
    query = CHECK_SERVICES_VERSIONS_PROMPT.format(
        hard_service_versions=hard_service_versions,
        service_list=service_list,
    )
    
    result = serv_ver_ass_llm.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), 
         HumanMessage(content=image_inspect_logs),
         # HumanMessage(content=container_inspect_logs),
         HumanMessage(content=code),
         HumanMessage(content=query)], 
        config={"callbacks": [langfuse_handler]}
    )
    state.stats.services_ok = result.services_ok
    
    if not result.code_hard_version:
        state.stats.not_vuln_version_fail += 1
        
        test_fail_output_string += f"\n\t- NOT VULNERABLE VERSION (LLM-as-a-Judge Check): {result.fail_explanation}"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
            
        hard_service_versions = ""
        for service in state.web_search_result.services:
            if service.dependency_type == "HARD":
                hard_service_versions += f"\n\t\t- {service.name}: {service.version}"
        revision_goal = f"fix this by modifying the Docker's code (which is available in my previous message) to ensure that the 'HARD' service uses one of the vulnerable versions listed here:{hard_service_versions}"
            
        return {
            "stats": state.stats,
            "fail_explanation": result.fail_explanation,
            "revision_goal": revision_goal,
            "revision_type": "Not Vulnerable Version",
        }    
    state.milestones.code_hard_version = True
    print("\tVulnerable version is used! Checking network setup...")
    
    
    #* LLM-as-a-Judge: NETWORK SETUP ASSESSMENT *#
    container_inspect_logs = "These are the output of the 'docker inspect' command of each Docker Container:\n"
    for cid in container_ids:
        container_inspect_logs += f"{inspect_container(cid=cid, log_file=log_file)}\n\n"
    
    query = CHECK_NETWORK_PROMPT.format()
    
    result = network_ass_llm.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), 
         # HumanMessage(content=image_inspect_logs),
         HumanMessage(content=container_inspect_logs),
         HumanMessage(content=code),
         HumanMessage(content=query)], 
        config={"callbacks": [langfuse_handler]}
    )
        
    if not result.network_setup:
        state.stats.docker_misconfigured += 1
        
        test_fail_output_string += f"\n\t- WRONG NETWORK SETUP (LLM-as-a-Judge Check): {result.fail_explanation}"
        print(f"{test_fail_output_string}")
        with builtins.open(final_report_file, "a") as f:
            f.write(test_fail_output_string)
        
        revision_goal = "fix the Docker system by ensuring its network configuration is setup correctly and that all services are available on their respective default network ports"
        return {
            "stats": state.stats,
            "fail_explanation": result.fail_explanation,
            "revision_goal": revision_goal,
            "revision_type": "Wrong Network Setup",
        }
    state.milestones.network_setup = True
    print(f"\tNetwork setup is ok! Docker is running correctly with {num_containers} containers!")
    
    formatted_code = f"Directory tree:\n{state.code.directory_tree}\n\n"
    for f in state.code.files:
        formatted_code += "-" * 10 + f" {f.location} " + "-" * 10 + f"\n{f.content}\n\n"
        
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
    state.milestones.docker_builds = False
    state.milestones.docker_runs = False
    state.milestones.code_hard_version = False
    state.milestones.network_setup = False
    state.stats.services_ok = False
    
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    final_report_file = code_dir_path / "logs/final_report.txt"
    down_docker(code_dir_path=code_dir_path)
    if state.revision_type == "Not Vulnerable Version":
        remove_all_images()
    
    code = "This is the code you have to revise:\n"
    for f in state.code.files:
        code += "-" * 10 + f" {f.location} " + "-" * 10 + f"\n{f.content}\n\n"
    
    query = TEST_FAIL_PROMPT.format(
        fail_explanation=state.fail_explanation,
        revision_goal=state.revision_goal,
        cve_id=state.cve_id,
        mode=state.web_search_tool,
        fixes=state.fixes,
    )
        
    result = revise_code_llm.invoke(
        state.messages + [HumanMessage(content=code), HumanMessage(content=query)],
        config={"callbacks": [langfuse_handler]}
    )

    output_string = f"\t- ERROR: {result.error}"
    output_string += f"\n\t- FIX: {result.fix}"
    print(output_string)
    with builtins.open(final_report_file, "a") as f:
        f.write(f"\n{output_string}\n")

    state.stats.test_iteration += 1
    return {
        "stats": state.stats,
        "milestones": state.milestones,
        "code": result.fixed_code,
        "fixes": state.fixes + [result.fix],
    }


def run_docker_scout(code_dir_path, index, iid):
    try:
        with builtins.open(f"{code_dir_path}/logs/cves{index}.json", "w") as f:
            subprocess.run(
                ["docker", "scout", "cves", iid, "--format", "gitlab"],
                cwd=code_dir_path,
                stdout=f,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=60,
            )
            print(f"\tCVE List file saved to: {code_dir_path}/logs/cves{index}.json")
            return True
    except subprocess.TimeoutExpired:
        print(f"\tDocker Scout timed out after 60 seconds for image {iid}")
        return False
        

def check_docker_vulnerability(cve_id, code_dir_path):
    image_ids = get_image_ids()
    for index, iid in enumerate(image_ids):
        if run_docker_scout(code_dir_path=code_dir_path, index=index, iid=iid):
            cves_file_path = code_dir_path / f"logs/cves{index}.json"
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
    
    down_docker(code_dir_path=code_dir_path)
    if state.milestones.docker_builds and state.milestones.docker_runs:
        print("\nAssessing Docker vulnerability...")
        if check_docker_vulnerability(cve_id=state.cve_id, code_dir_path=code_dir_path):
            output_string = f"Docker Scout says that the Docker is vulnerable to {state.cve_id}!"
            print(f"\t{output_string}")
            state.stats.docker_scout_vulnerable = True
            with builtins.open(final_report_file, "a") as f:
                f.write(output_string)
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