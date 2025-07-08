"""Run the agent by providing it with a CVE ID."""

from langchain_core.messages import SystemMessage

# My modules
from configuration import langfuse_handler, WebSearchResult, CodeGenerationResult
from prompts import SYSTEM_PROMPT
from graph import compiled_workflow

def draw_graph():
    """Display the image of the compiled graph"""
    from IPython.display import Image, display
    
    try:
        display(Image(compiled_workflow.get_graph().draw_mermaid_png(output_file_path="Mermaid Chart.png")))
        
    except Exception as e:
        print(f"Rendering failed with code {e}.\nHere's the Mermaid source:\n{compiled_workflow.get_graph().draw_mermaid()}")
        
# Test the workflow
try:
    result = compiled_workflow.invoke(
        input={
            "cve_id": "CVE-2022-46169",#    CVE-2021-28164    CVE-2022-46169    CVE-2024-23897  #NOTE: to test GT update use CVE-2017-7525
            "web_search_tool": "skip",#   custom  custom_no_tool  openai  skip        #NOTE: if 'skip' is used, initialize "web_search_result" with valid data
            #"web_search_result": WebSearchResult(description="", attack_type="", services=[], service_type=[], service_description=[]),
            "web_search_result": WebSearchResult(
                description="CVE-2022-46169 is a critical command injection vulnerability in Cacti, affecting versions up to 1.2.22. It allows unauthenticated remote code execution (RCE) by exploiting an authentication bypass and command injection in the `remote_agent.php` file. The vulnerability is due to improper sanitization of query arguments, allowing attackers to execute arbitrary commands on the server. The issue is patched in versions 1.2.23 and 1.3.0.", 
                attack_type="Remote Code Execution (RCE)", 
                services=['cacti:1.2.22', 'mysql:5.7', 'php:7.4-apache'], 
                service_type=['MAIN', 'AUX', 'AUX'], 
                service_description=['Cacti is the main service vulnerable to CVE-2022-46169, allowing RCE through command injection.', 'MySQL is required as the database service for Cacti to store monitoring data.', 'PHP with Apache is needed to serve the Cacti application and process PHP scripts.'],
            ),
            #"code": CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
            "debug": ""#        skip_to_test
        },
        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
    )

    # Review conversation history
    print()
    for message in result["messages"]:
        print("=" * 20 + f" {message.type.upper()} " + "=" * 20)
        print(f"{message.content}\n")

except Exception as e:
    print(f"Workflow invocation failed: {e}.")
# To check web search results
# try:
#     print(f"description='{result['web_search_result'].description}',")
#     print(f"attack_type='{result['web_search_result'].attack_type}',")
#     print(f"services={result['web_search_result'].services},")
#     print(f"service_type={result['web_search_result'].service_type},")
#     print(f"service_description={result['web_search_result'].service_description},")
# except:
#     print("NO DATA RECOVERED FROM THE WEB")

# To check code generation results
# try:
#     print(f"file_name='{result['code'].file_name}'")
#     print(f"file_code='{result['code'].file_code}'")
#     print(f"directory_tree={result['code'].directory_tree}")
# except:
#     print("NO CODE GENERATED and STORED")