import os
import json
import requests
import builtins
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
    NOT_SUCCESS_PROMPT,
    NOT_DOCKER_RUNS,
    TEST_CODE_PROMPT,
    CODE_MILESTONE_PROMPT,
)
from configuration import (
    langfuse_handler,
    WebSearchResult,
    MAINServiceVersionAssessment,
    CodeGenerationResult,
    TestCodeResult,
    CodeMilestonesAssessment,
)

llm_web_search = ChatOpenAI(model="gpt-4o", temperature=0, max_retries=2)
llm_openai_web_search_tool = llm_web_search.bind_tools([openai_web_search])
llm_custom_web_search_tool = llm_web_search.bind_tools([web_search])
web_search_llm = llm_web_search.with_structured_output(WebSearchResult)
ver_ass_llm = llm_web_search.with_structured_output(MAINServiceVersionAssessment)

llm_code = ChatOpenAI(model="gpt-4o", temperature=0.5, max_retries=2, max_completion_tokens=5000)
code_generation_llm = llm_code.with_structured_output(CodeGenerationResult)
code_ass_llm = llm_code.with_structured_output(CodeMilestonesAssessment)
test_code_llm = llm_code.with_structured_output(TestCodeResult)


def create_dir(dir_path):
    try:
        dir_path.mkdir(parents=True, exist_ok=False)
        print(f"\tDirectory '{dir_path}' created successfully.")
    except PermissionError:
        raise ValueError(f"Permission denied: Unable to create '{dir_path}'.")
    except Exception as e:
        raise ValueError(f"An error occurred: {e}")


def get_cve_id(state: OverallState):
    if state.debug == "benchmark_web_search":
        print("[BENCHMARK] Web search benchmark starting!")
    elif state.debug == "benchmark_code":
        print("[BENCHMARK] Code benchmark starting!")
    
    """Checks if the CVE ID is correctly retrieved from the initialized state"""
    print(f"The provided CVE ID is {state.cve_id.upper()}!")
    return {"cve_id": state.cve_id.upper()}


def assess_cve_id(state: OverallState):
    if state.debug == "benchmark_code":
        return {}
    
    """The agent checks if the CVE ID exists in the MITRE CVE database"""
    print("Checking if the CVE ID exists...")
    response = requests.get(f"https://cveawg.mitre.org/api/cve/{state.cve_id}")

    if response.status_code == 200:
        print(f"{state.cve_id} exists!")
        
        docker_dir_path = Path(f"./../../dockers/{state.cve_id}")
        if not docker_dir_path.exists():
            create_dir(dir_path=docker_dir_path)
            
        updated_milestones = state.milestones
        updated_milestones.cve_id_ok = True
        
        updated_final_report = state.final_report + "="*10 + f" {state.cve_id} Final Report "  + "="*10
        updated_final_report += "\n" + "="*10 + f" Initial Parameters " + "="*10 
        updated_final_report += f"\n'cve_id': {state.cve_id}\n'web_search_tool': {state.web_search_tool}\n'web_search_result': {state.web_search_result}"
        updated_final_report += f"\n'code': {state.code}\n'messages': {state.messages}\n'debug': {state.debug}\n\n"
        return {
            "milestones": updated_milestones,
            "final_report": updated_final_report,
        }

    elif response.status_code == 404:
        print(f"The record for {state.cve_id} does not exist.")
        return {}

    else:
        print(f"Failed to fetch CVE: {response.status_code}")
        return {}


def route_cve(state: OverallState) -> Literal["Found", "Not Found"]:
    if state.debug == "benchmark_code":
        return "Found"
    
    """Terminate the graph or go to the next step"""
    print(f"Routing CVE (cve_id_ok = {state.milestones.cve_id_ok})")
    if state.milestones.cve_id_ok:
        return "Found"
    else:
        return "Not Found"
    

def get_services(state: OverallState):
    if state.debug == "benchmark_code":
        return {}
    
    """The agent performs a web search to gather relevant information about the services needed to generate the vulnerable Docker code"""
    print("Searching the web...")
    
    docker_dir_path = Path(f"./../../dockers/{state.cve_id}")
    logs_dir_path = docker_dir_path / "logs"
    
    # Create the directory to save logs (if it does not exist)
    if not logs_dir_path.exists():
        create_dir(dir_path=logs_dir_path)
        
    web_search_file = logs_dir_path / f"{state.cve_id}_web_search_{state.web_search_tool}.json"
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
        formatted_response, in_token, out_token = web_search_tool_func(query=query, cve_id=cve_id, n_documents=5, verbose=False)
    
    elif state.web_search_tool == "custom_no_tool":
        #NOTE: 'web_search_func' internally formats the response into a WebSearchResult Pydantic class
        formatted_response, in_token, out_token = web_search_func(state.cve_id, n_documents=5, verbose=False)
    
    elif state.web_search_tool == "openai":
        web_query = OPENAI_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        messages += [HumanMessage(content=web_query)]
        
        # Invoke the LLM to perform the web search and extract the token usage
        web_search_result = llm_openai_web_search_tool.invoke(messages, config={"callbacks": [langfuse_handler]})
        in_token, out_token = web_search_result.usage_metadata['input_tokens'], web_search_result.usage_metadata['output_tokens']
        response_sourceless = web_search_result.content[0]["text"]
        formatted_response = web_search_llm.invoke(WEB_SEARCH_FORMAT_PROMPT.format(web_search_result=response_sourceless), config={"callbacks": [langfuse_handler]})
        
    else:
        raise ValueError("Invalid web search tool specified. Use 'custom', 'custom_no_tool' or 'openai'.")
    
    
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
    with builtins.open(web_search_file, 'w') as fp:
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
        ver_ass_query = MAIN_SERV_VERS_ASSESSMENT_PROMPT.format(
            range="[start, end]",
            vers=pred_ver,
            service=serv,
        )

        response = ver_ass_llm.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=ver_ass_query)], 
            config={"callbacks": [langfuse_handler]}
        )
        print(f"\tResult: main_version={response.main_version}")
        return response.main_version
    

def assess_services(state: OverallState):
    if state.debug == "benchmark_code":
        return {}
    
    """Checks if the services needed to generate the vulnerable Docker code are correct by using the ones of Vulhub as GT"""
    print("Checking the Docker services...")
    filename = 'services.json'
    with builtins.open(filename, "r") as f:
        jsonServices = json.load(f)
        
    updated_milestones = state.milestones
    
    # If the services of CVE do not exist in 'services.json', update 'services.json' and skip the check
    if not jsonServices.get(state.cve_id) and state.debug != "benchmark_web_search":
        print(f"\t{state.cve_id} is not in 'services.json'! Updating 'services.json' with the following services:")
        services = []
        for serv, serv_type, serv_ver in zip(state.web_search_result.services, state.web_search_result.service_type, state.web_search_result.service_vers):
            new_service = f"{serv_type.upper()}:{serv.split("/")[-1].lower()}:{serv_ver.split(",")[0].split("---")[0]}"
            print(f"\t- {new_service}")
            services.append(new_service)
            
        jsonServices[state.cve_id] = services
        with builtins.open(filename, "w") as f:
            json.dump(jsonServices, f, indent=4)
            
        updated_milestones.main_service = True
        updated_milestones.main_version = True
        return {"milestones": updated_milestones}
    
    # Else, proceed with the check
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
            print(f"\tExpected MAIN --> {exp_main_serv}:{exp_main_ver}\tProposed MAIN --> {serv}:[{serv_ver}]")
            prop_main_serv, prop_main_ver = serv.split("/")[-1], serv_ver.split(",")
        
    if exp_main_serv.lower() == prop_main_serv.lower(): 
        updated_milestones.main_service = True

    for ver in prop_main_ver:
        ver = ver.split("---")
        # If the LLM returned a range of vulnerable versions...
        if len(ver) > 1:
            ver_min, ver_max = ver[0], ver[1]
            if is_version_in_range(exp_main_serv, exp_main_ver, ver_min, ver_max):
                updated_milestones.main_version = True
                break

        # Else, if the LLM returned a specific vulnerable version...
        elif len(ver) == 1:
            if exp_main_ver.lower() == ver[0].lower():
                updated_milestones.main_version = True
                break
    
        else:
            raise ValueError(f"An error occurred while extracting the versions of the proposed MAIN service")
    
    # Check if at least one 'AUX' service was proposed for each role
    proposed_aux_roles = set(state.web_search_result.service_type)
    for role in expected_aux_roles:
        if role not in proposed_aux_roles:
            print(f"\t{role} service not proposed!")
            updated_milestones.aux_services = False
    
    return {"milestones": updated_milestones}


def route_services(state: OverallState) -> Literal["Ok", "Not Ok"]:
    if state.debug == "benchmark_code":
        return "Ok"
    
    """Route to the code generator or terminate the graph"""
    print(f"Routing services (main_service={state.milestones.main_service}, main_version={state.milestones.main_version}, aux_services={state.milestones.aux_services})")
    if state.milestones.main_service and state.milestones.main_version and state.milestones.aux_services and state.debug != "benchmark_web_search":
        return "Ok"
    else:
        if state.debug == "benchmark_web_search":
            print("[BENCHMARK] Web search benchmark terminated!")
        return "Not Ok"


def generate_code(state: OverallState):    
    """The agent generates/fixes the docker code to reproduce the CVE"""
    print("Generating the code...")
    code_gen_query = CODING_PROMPT.format(
        cve_id=state.cve_id,
        desc=state.web_search_result.desc,
        serv=state.web_search_result.services,
        serv_vers=state.web_search_result.service_vers,
        mode=state.web_search_tool,
    )
    
    generated_code = code_generation_llm.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=code_gen_query)], 
        config={"callbacks": [langfuse_handler]}
    )
    
    response = f"Directory tree:\n{generated_code.directory_tree}\n\n"
    for name, code in zip(generated_code.file_name, generated_code.file_code):
        response += "-" * 10 + f" {name} " + "-" * 10 + f"\n{code}\n\n"
        
    print("Code generated!")
    return {
        "final_report": state.final_report + "="*10 + f" Generated Code (First Version) " + "="*10 + f"\n{response}\n\n",
        "code": generated_code,
        "messages": state.messages + [
            HumanMessage(content=code_gen_query),
            AIMessage(content=response),
        ],
    }


def save_code(state: OverallState):
    """The agent saves the tested code in a local directory structured as the directory tree"""
    print("Saving code...")
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    if not code_dir_path.exists():
        create_dir(dir_path=code_dir_path)

    for file_rel_path, file_content in zip(state.code.file_name, state.code.file_code):
        full_path = code_dir_path / file_rel_path
        if not full_path.exists():
            # Different from create_dir()
            try:
                full_path.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise ValueError(f"Permission denied: Unable to create '{full_path}'.")
            except Exception as e:
                raise ValueError(f"An error occurred: {e}")
        
        with builtins.open(full_path, "w", encoding="utf-8") as f:
            f.write(file_content)
        print(f"\tSaved file: {full_path}")

    print("Code saved!")
    return {}


def launch_docker(code_dir_path):
    result = subprocess.run(
        ["sudo", "docker", "compose", "up", "--build", "--detach"],
        cwd=code_dir_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    logs = result.stdout
    success = (result.returncode == 0)
    return success, logs


def check_services(services, main_serv, main_serv_ver, code_dir_path):
    result = subprocess.run(
        ["sudo", "docker", "compose", "ps", "--quiet"],
        cwd=code_dir_path,
        capture_output=True,
        text=True,
    )
    container_ids = result.stdout.strip().splitlines()

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
        except json.JSONDecodeError:
            raise ValueError(f"Failed to parse JSON for container {cid}")
        
    query = CODE_MILESTONE_PROMPT.format(
        service_list=services,
        main_service=main_serv,
        main_version=main_serv_ver,
        inspect_logs=inspect_logs,
    )
    
    return len(container_ids), code_ass_llm.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)], 
        config={"callbacks": [langfuse_handler]}
    )


def down_docker(code_dir_path):
    # Ensure Docker is down and containers and volumes are removed
    subprocess.run(
        ["sudo", "docker", "compose", "down", "--volumes"],
        cwd=code_dir_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def test_code(state: OverallState):
    """The agent tests the docker to check if it work correctly"""    
    print("Testing code...")
    updated_milestones = state.milestones
    code_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/")
    logs_dir_path = code_dir_path / "logs"
    if not logs_dir_path.exists():
        create_dir(dir_path=logs_dir_path)
    
    success, logs = launch_docker(code_dir_path=code_dir_path)

    log_file = logs_dir_path / f"{state.cve_id}_{state.web_search_tool}_log{state.test_iteration}.txt"
    with builtins.open(log_file, "w") as f:
        f.write(logs)
    print(f"\tTest logs saved to: {log_file}")
    
    code = ""
    for name, content in zip(state.code.file_name, state.code.file_code):
        code += "-" * 10 + f" {name} " + "-" * 10 + f"\n{content}\n\n"
    
    if not success:
        if state.debug == "benchmark_code":
            print("\t[DEBUG] NOT_SUCCESS")
        down_docker(code_dir_path=code_dir_path)
        
        query = NOT_SUCCESS_PROMPT.format(
            # Passing just the last 100 lines of logs to mitigate ContextWindow saturation
            logs="\n".join(logs.splitlines()[-100:]),
            code=code,
            serv=state.web_search_result.services,
            serv_vers=state.web_search_result.service_vers,
            serv_type=state.web_search_result.service_type,
            serv_desc=state.web_search_result.service_desc,
            cve_id=state.cve_id,
            mode=state.web_search_tool,
            fixes=state.fixes,
        )
        
        test_code_results = test_code_llm.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)],
            config={"callbacks": [langfuse_handler]}
        )
        
        updated_milestones.docker_runs = False
        updated_milestones.services_ok = False
        updated_milestones.code_main_version = False
        
        response = f"Test iteration #{state.test_iteration} failed!"
        response += f"\n\tError: {test_code_results.error}\n\tFix: {test_code_results.fix}"
        print(response)
        
        return {
            "milestones": updated_milestones,
            "final_report": state.final_report + f"\n{response}",
            "code": test_code_results.fixed_code,
            "feedback": test_code_results,
            "test_iteration": state.test_iteration + 1,
            "fixes": state.fixes + [test_code_results.fix],
            "messages": state.messages + [
                HumanMessage(content=query),
                AIMessage(content=response)
            ],
        }
        
    else:
        for serv_type, serv, ver in zip(state.web_search_result.service_type, state.web_search_result.services, state.web_search_result.service_vers):
            if serv_type == "MAIN":
                main_serv, main_serv_ver = serv, ver
        
        num_containers, result = check_services(
            services=state.web_search_result.services, 
            main_serv=main_serv, 
            main_serv_ver=main_serv_ver, 
            code_dir_path=code_dir_path,
        )
        print(f"\n\tResult: {result.fail_explanation if result.fail_explanation else ""}")
        print(f"\t- docker_runs={result.docker_runs}")
        print(f"\t- services_ok={result.services_ok}")
        print(f"\t- code_main_version={result.code_main_version}\n")
        down_docker(code_dir_path=code_dir_path)
        
        if not result.docker_runs:
            # Different query w.r.t. the one above
            query = NOT_DOCKER_RUNS.format(
                fail_explanation=result.fail_explanation,
                code=code,
                serv=state.web_search_result.services,
                serv_vers=state.web_search_result.service_vers,
                serv_type=state.web_search_result.service_type,
                serv_desc=state.web_search_result.service_desc,
                cve_id=state.cve_id,
                mode=state.web_search_tool,
                fixes=state.fixes,
            )

            test_code_results = test_code_llm.invoke(
                [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)],
                config={"callbacks": [langfuse_handler]}
            )
            
            updated_milestones.docker_runs = False
            updated_milestones.services_ok = False
            updated_milestones.code_main_version = False

            response = f"Test iteration #{state.test_iteration} failed!"
            if result.fail_explanation:
                response += f"\n\tFail Explanation: {result.fail_explanation}"
            response += f"\n\tError: {test_code_results.error}"
            response += f"\n\tFix: {test_code_results.fix}"
            print(response)

            return {
                "milestones": updated_milestones,
                "final_report": state.final_report + f"\n{response}",
                "code": test_code_results.fixed_code,
                "feedback": test_code_results,
                "test_iteration": state.test_iteration + 1,
                "num_containers": num_containers,
                "fixes": state.fixes + [test_code_results.fix],
                "messages": state.messages + [
                    HumanMessage(content=query),
                    AIMessage(content=response)
                ],
            }
        
        else:
            print(f"Docker is running correctly with {num_containers} containers")
            updated_milestones.docker_runs = result.docker_runs
            updated_milestones.services_ok = result.services_ok
            updated_milestones.code_main_version = result.code_main_version
            
            formatted_code = f"Directory tree:\n{state.code.directory_tree}\n\n"
            for name, code in zip(state.code.file_name, state.code.file_code):
                formatted_code += "-" * 10 + f" {name} " + "-" * 10 + f"\n{code}\n\n"

            return {
                "milestones": updated_milestones,
                "num_containers": num_containers,
                "final_report": state.final_report + "="*10 + f" Test Passed! Generated Code (Final Version) " + "="*10 + f"\n{formatted_code}",
                "messages": state.messages + [AIMessage(content="Test Passed!")],
            }


def route_code(state: OverallState) -> Literal["Stop Testing", "Keep Testing"]:
    """Route back to fix the code or terminate the graph"""
    print(f"Routing test (docker_runs = {state.milestones.docker_runs}, test_iteration = {state.test_iteration})")
    if state.milestones.docker_runs or state.test_iteration >= 10:
        if state.test_iteration >= 10:
            print("\tMax Iterations Reached!")
        if state.debug == "benchmark_code":
            print("[BENCHMARK] Code benchmark terminated!")
            
        logs_dir_path = Path(f"./../../dockers/{state.cve_id}/{state.web_search_tool}/logs")
        final_report_file = logs_dir_path / f"{state.cve_id}_{state.web_search_tool}_final_report.txt"
        with builtins.open(final_report_file, "w") as f:
            f.write(state.final_report)
        
        code_stats = {
            "test_iterations": state.test_iteration,
            "num_containers": state.num_containers,
        } 
        code_stats_file = logs_dir_path / f"{state.cve_id}_{state.web_search_tool}_code_stats.json"
        with builtins.open(code_stats_file, "w") as f:
            json.dump(code_stats, f, indent=4)
            
        milestone_file = logs_dir_path / f"{state.cve_id}_{state.web_search_tool}_milestones.json"
        with builtins.open(milestone_file, "w") as f:
            json.dump(dict(state.milestones), f, indent=4)
        
        print("Execution Terminated!")
        return "Stop Testing"
    else:
        return "Keep Testing"