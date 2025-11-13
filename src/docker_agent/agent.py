"""Run the agent by providing it with a CVE ID."""
import time
import json
import builtins
import subprocess
from pathlib import Path
from IPython.display import Image, display
from langchain_core.messages import SystemMessage

# My modules
from configuration import langfuse_handler
from prompts import SYSTEM_PROMPT
from graph import compiled_workflow


def down_docker(code_dir_path):
    # Ensure Docker is down and containers and volumes are removed
    subprocess.run(
        ["sudo", "docker", "compose", "down", "--volumes"],
        cwd=code_dir_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(10)


def remove_all_images():
    image_ids = subprocess.check_output(["docker", "images", "-aq"]).decode().split()

    if image_ids:
        subprocess.run(
            ["docker", "rmi", "-f"] + image_ids,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )


#* DRAW AGENTIC WORKFLOW GRAPH USING MERMAID CHART *#
def draw_graph():
    try:
        print(compiled_workflow.get_graph().draw_mermaid())
        display(Image(compiled_workflow.get_graph().draw_mermaid_png(output_file_path="Mermaid Chart.png")))
        
    except Exception as e:
        print(f"Rendering failed with code {e}.\nHere's the Mermaid source:\n{compiled_workflow.get_graph().draw_mermaid()}")
# draw_graph()


#* TEST THE DOCKERS IN THE 'docker' FOLDER *#
def assess_dockers(cve_list: list[str], model_name: str, model_docker_name: str, logs_set: str, web_search_mode: str):
    if web_search_mode == "all": web_search_mode = ["custom", "custom_no_tool", "openai"]
    else: web_search_mode = [f"{web_search_mode}"]
    
    for wsm in web_search_mode:
        for cve in cve_list: 
            logs_path = Path(f"./../../benchmark_logs/{model_docker_name}/{logs_set}-benchmark-session/{cve}/{wsm}/logs/")
            with builtins.open(logs_path / 'milestones.json', 'r') as f:
                milestones = json.load(f)

            with builtins.open(logs_path / 'web_search_results.json', 'r') as f:
                web_search_data = json.load(f)
                
            if milestones["docker_builds"] and milestones["docker_runs"] and milestones["code_hard_version"]:
                with builtins.open(logs_path / 'code.json', 'r') as f:
                    code_data = json.load(f)

                with builtins.open(logs_path / 'stats.json', 'r') as f:
                    stats = json.load(f)

                try:
                    result = compiled_workflow.invoke(
                        input={
                            "model_name": model_name,
                            "cve_id": cve,
                            "web_search_tool": wsm,
                            "verbose_web_search": False,
                            "web_search_result": web_search_data,
                            "code": code_data,
                            "messages": [SystemMessage(content=SYSTEM_PROMPT)]
                        },
                        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                    )

                    if stats["docker_scout_vulnerable"] != result["stats"].docker_scout_vulnerable:
                        print(f"{cve} 'docker_scout_vulnerable' {stats["docker_scout_vulnerable"]} --> {result["stats"].docker_scout_vulnerable}")

                except Exception as e:
                    code_dir_path = Path(f"./../../dockers/{cve}/{wsm}/")
                    down_docker(code_dir_path=code_dir_path)
                    remove_all_images()
                    print(f"\n\n===== [AGENTIC WORKFLOW FAILED] =====\n{e}\n"+"="*37+"\n\n")
                    continue          
            else:
                continue

            for m, val in result["milestones"]:
                if val != milestones[m]:
                    print(f"{cve} '{m}' {milestones[m]} --> {val}")
            print("\n\n\n")
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# print(len(cve_list), cve_list)
# df = assess_dockers(
#     cve_list=cve_list,
#     model_name="gpt-4o",
#     model_docker_name="GPT-4o",
#     logs_set="5th",
#     web_search_mode="all",
# )


#* RUN AGENT *#
def run_agent(cve_list: list[str], web_search_mode: str, model_name: str, verbose_web_search: bool, reuse_web_search: bool, reuse_web_search_and_code: bool, relax_web_search_constraints: bool):
    if web_search_mode == "all": web_search_mode = ["custom", "custom_no_tool", "openai"]
    elif web_search_mode == "all-openai": web_search_mode = ["custom", "custom_no_tool"]
    else: web_search_mode = [f"{web_search_mode}"]
    
    for wsm in web_search_mode:        
        for cve in cve_list:                
            if reuse_web_search or reuse_web_search_and_code:
                with builtins.open(f'./../../dockers/{cve}/{wsm}/logs/web_search_results.json', 'r') as f:
                    web_search_data = json.load(f)
                if reuse_web_search_and_code:
                    with builtins.open(f'./../../dockers/{cve}/{wsm}/logs/code.json', 'r') as f:
                        code_data = json.load(f)
            
            #! Uncomment this to reuse the web_search_results file from the 'benchmark_logs' folder !#
            # with builtins.open(f'./../../benchmark_logs/GPT-4o/5th-benchmark-session/{cve}/{wsm}/logs/web_search_results.json', 'r') as f:   
            #     web_search_data = json.load(f)
            # logs_dir_path = Path(f"./../../dockers/{cve}/{wsm}/logs")
            # logs_dir_path.mkdir(parents=True, exist_ok=True)
            # web_search_file = logs_dir_path / 'web_search_results.json'
            # with builtins.open(web_search_file, 'w') as fp:
            #     json.dump(web_search_data, fp, indent=4)    

            try:
                if reuse_web_search:
                    result = compiled_workflow.invoke(
                        input={              
                            "model_name": model_name,
                            "cve_id": cve,
                            "web_search_tool": wsm,
                            "verbose_web_search": verbose_web_search,
                            "web_search_result": web_search_data,
                            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                            "debug": "relax-web-search-constraints" if relax_web_search_constraints else "",
                        },
                        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                    )
                elif reuse_web_search_and_code:
                    result = compiled_workflow.invoke(
                        input={             
                            "model_name": model_name,
                            "cve_id": cve,
                            "web_search_tool": wsm,
                            "verbose_web_search": verbose_web_search,
                            "web_search_result": web_search_data,
                            "code": code_data,
                            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                            "debug": "relax-web-search-constraints" if relax_web_search_constraints else "",
                        },
                        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                    )
                else:
                    result = compiled_workflow.invoke(
                        input={             
                            "model_name": model_name,
                            "cve_id": cve,
                            "web_search_tool": wsm,
                            "verbose_web_search": verbose_web_search,
                            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                            "debug": "relax-web-search-constraints" if relax_web_search_constraints else "",
                        },
                        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                    )

                if len(cve_list) == 1 and len(web_search_mode) == 1:
                    return result
                
            except Exception as e:
                print(f"\n\n===== [AGENTIC WORKFLOW FAILED] =====\n{e}\n"+"="*37+"\n\n")
                code_dir_path = Path(f"./../../dockers/{cve}/{wsm}/")
                down_docker(code_dir_path=code_dir_path)
                remove_all_images()                
                continue      
with builtins.open('services.json', "r") as f:
    jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20] # The first 20 are the validation set
# cve_list = list(jsonServices.keys())[20:] # From the 20th onward is the test set
cve_list = ['CVE-2020-14144', 'CVE-2021-22205']
print(len(cve_list), cve_list)
result = run_agent(
    cve_list=cve_list,
    web_search_mode="custom_no_tool",
    model_name="gpt-4o",                #* Models supported: 'gpt-4o','gpt-5','mistralai/Mistral-7B-Instruct-v0.1', 'gpt-oss-20b', 'gpt-oss-120b' *#
    verbose_web_search=False,
    reuse_web_search=False,
    reuse_web_search_and_code=False,
    relax_web_search_constraints=True,
)


#* TRY TO CREATE DOCKERS WITH A WRONG WEB SEARCH *#
def test_wrong_web_search(cve_list: list[str], model_name: str, model_docker_name: str, logs_set: str, web_search_mode: str):
    if web_search_mode == "all": web_search_mode = ["custom", "custom_no_tool", "openai"]
    else: web_search_mode = [f"{web_search_mode}"]
    ok_dockers, new_ok_dockers = 0, 0
    
    for wsm in web_search_mode:
        for cve in cve_list: 
            logs_path = Path(f"./../../benchmark_logs/{model_docker_name}/{logs_set}-benchmark-session/{cve}/{wsm}/logs/")
            with builtins.open(logs_path / 'milestones.json', 'r') as f:
                milestones = json.load(f)

            with builtins.open(logs_path / 'web_search_results.json', 'r') as f:
                web_search_data = json.load(f)
                
            if milestones["docker_builds"] and milestones["docker_runs"] and milestones["code_hard_version"] and milestones["network_setup"]: ok_dockers += 1
            
            elif not milestones["hard_service"] or not milestones["hard_version"] or not milestones["soft_services"]:
                try:
                    result = compiled_workflow.invoke(
                        input={
                            "model_name": model_name,
                            "cve_id": cve,
                            "web_search_tool": wsm,
                            "verbose_web_search": False,
                            "web_search_result": web_search_data,
                            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                            "debug": "relax-web-search-constraints"
                        },
                        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                    )
                    if result["milestones"].docker_builds and result["milestones"].docker_runs and result["milestones"].code_hard_version and result["milestones"].network_setup: new_ok_dockers += 1
                        
                except Exception as e:
                    code_dir_path = Path(f"./../../dockers/{cve}/{wsm}/")
                    down_docker(code_dir_path=code_dir_path)
                    remove_all_images()
                    print(f"\n\n===== [AGENTIC WORKFLOW FAILED] =====\n{e}\n"+"="*37+"\n\n")
                    continue 
            
            else:
                continue
    print(f"Docker already ok: {ok_dockers}\nNew Dockers ok: {new_ok_dockers}\n\n\n\n\n")
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
# cve_list = list(jsonServices.keys())[:20]
# print(len(cve_list), cve_list)
# df = test_wrong_web_search(
#     cve_list=cve_list,
#     model_name="gpt-4o",
#     model_docker_name="GPT-4o",
#     logs_set="7th",
#     web_search_mode="all",
# )


#* GENERATE THE '{wsm}-milestones.json' FILE OUT OF ALL DOCKERS IN THE 'docker' FOLDER *#
def milestone_file(cve_list: list, web_search_mode: str):
    missing_cves = []
    milestones = {}
    for cve in cve_list:
        try:            
            with builtins.open(f'./../../dockers/{cve}/{web_search_mode}/logs/milestones.json', 'r') as f:
                milestone_data = json.load(f)
            milestones[cve] = milestone_data

        except:
            print(f"Missing {cve} milestone file")
            missing_cves.append(cve)
            continue
    
    if len(missing_cves) == 0:
        with builtins.open(f'./../../dockers/{web_search_mode}-milestones.json', 'w') as f:
            json.dump(milestones, f, indent=4)
        return milestones   
    else: print(len(missing_cves), missing_cves)
     
with builtins.open('services.json', "r") as f:
    jsonServices = json.load(f)
cve_list = list(jsonServices.keys())[20:]
milestones = milestone_file(cve_list=cve_list, web_search_mode="custom_no_tool")


#! US THIS CODE TO REWRITE SOME DATA !#
# with builtins.open('services.json', "r") as f:
#     jsonServices = json.load(f)
#         
# cve_list = list(jsonServices.keys())[:19]
# print(len(cve_list), cve_list)
# web_search_mode = "custom_no_tool"
#         
# for cve in cve_list:            
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/milestones.json', 'r') as f:
#         milestones = json.load(f)
#     
#     if not milestones["soft_services"] or not milestones["hard_service"] or not milestones["hard_version"]:
#         print("SKIP", cve, web_search_mode)
#         continue
# 
#     #! Uncomment this to reuse the web_search_results file from the 'docker' folder !#
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/web_search_results.json', 'r') as f:
#         web_search_data = json.load(f)
#     #! Uncomment this to reuse the web_search_results file from the 'benchmark_logs' folder !#
#     # with builtins.open(f'./../../benchmark_logs/GPT-5/1st-benchmark-session/{cve}/{web_search_mode}/logs/web_search_results.json', 'r') as f:   
#     #     web_search_data = json.load(f)
#     # logs_dir_path = Path(f"./../../dockers/{cve}/{web_search_mode}/logs")
#     # logs_dir_path.mkdir(parents=True, exist_ok=True)
#     # web_search_file = logs_dir_path / 'web_search_results.json'
#     # with builtins.open(web_search_file, 'w') as fp:
#     #     json.dump(web_search_data, fp, indent=4)    
# 
#     #! Uncomment this to reuse the code files from the 'docker' folder !#
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/code.json', 'r') as f:
#         code_data = json.load(f)
# 
#     for index, fn in enumerate(code_data["file_name"]):
#         if f"./../../dockers/{cve}/{web_search_mode}" not in code_data["file_name"][index]:
#             code_data["file_name"][index] = f"./../../dockers/{cve}/{web_search_mode}/{fn}"
#     
#     with builtins.open(f'./../../benchmark_logs/GPT-5/2nd-benchmark-session/{cve}/{web_search_mode}/logs/code.json', "w") as f:
#         json.dump(code_data, f, indent=4)
#     
#     print(cve, web_search_mode)
