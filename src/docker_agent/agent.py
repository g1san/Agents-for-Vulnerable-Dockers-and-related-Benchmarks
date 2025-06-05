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
            "cve_id": "CVE-2024-23897",#    CVE-2021-28164    CVE-2022-46169    CVE-2024-23897
            "web_search_tool": "custom_no_tool",#   custom  custom_no_tool  openai  skip
            #"web_search_result": WebSearchResult(description="", attack_type="", services=[], service_description=[]),
            #"code": CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
        },
        config={"callbacks": [langfuse_handler]},
    )

    # Review conversation history
    print()
    for message in result["messages"]:
        print("=" * 20 + f" {message.type.upper()} " + "=" * 20)
        print(f"{message.content}\n")

except Exception as e:
    print(f"Workflow invocation failed: {e}.")

print(f"description='{result['web_search_result'].description},'")
print(f"attack_type='{result['web_search_result'].attack_type},'")
print(f"services={result['web_search_result'].services},")
print(f"service_description={result['web_search_result'].service_description},")
    
#* OBTAINED WITH 'custom'
# "web_search_result": WebSearchResult(
#     description='CVE-2021-28164 is an information disclosure vulnerability in the Eclipse Jetty web server, allowing unauthorized access to sensitive files in the WEB-INF directory due to improper URI parsing.,'
#     attack_type='Information Disclosure,'
#     services=['jetty:9.4.42.v20210604'],
#     service_description=['Jetty 9.4.42.v20210604 is a version of the Jetty web server that is vulnerable to CVE-2021-28164, allowing access to protected files in the WEB-INF directory through specially crafted URIs.'],),
# "web_search_result": WebSearchResult(
#     description='CVE-2022-46169 is a critical command injection vulnerability in Cacti version 1.2.22, allowing unauthenticated remote code execution (RCE) by exploiting improper sanitization of query arguments in HTTP requests.,'
#     attack_type='Remote Code Execution (RCE),'
#     services=['cacti:1.2.22', 'php:7.4-apache', 'mysql:5.7'],
#     service_description=['Cacti 1.2.22 is the vulnerable version of the network monitoring tool where the command injection vulnerability exists.', 'PHP 7.4 with Apache is required to run Cacti, as it is a PHP-based application.', 'MySQL 5.7 is used as the database backend for Cacti to store monitoring data and configurations.'],),
# "web_search_result": WebSearchResult(
#     description='CVE-2024-23897 is a critical vulnerability in Jenkins affecting its CLI, allowing unauthorized file read and potential RCE due to args4j library misuse.,'
#     attack_type='Remote Code Execution (RCE),'
#     services=['jenkins:2.441', 'openjdk:8-jdk'],
#     service_description=['Jenkins 2.441 is required as it is vulnerable to CVE-2024-23897 due to the CLI command parser flaw.', 'OpenJDK 8 is needed to run Jenkins, as Jenkins is a Java-based application.'],),
#* OBTAINED WITH 'custom_no_tool'
# "web_search_result": WebSearchResult(
#     description='CVE-2021-28164 is an information disclosure vulnerability in the Eclipse Jetty web server, allowing unauthorized access to sensitive files in the WEB-INF directory through crafted URIs with encoded characters.', 
#     attack_type='Information Disclosure', 
#     services=['eclipse/jetty:9.4.42.v20210604'],
#     service_description=['Jetty 9.4.42.v20210604 is vulnerable to CVE-2021-28164, allowing access to protected files in the WEB-INF directory through crafted URIs.'],),
# "web_search_result": WebSearchResult(
#     description='CVE-2022-46169 is a critical command injection vulnerability in Cacti version 1.2.22, allowing unauthenticated remote code execution (RCE) by exploiting improper sanitization in HTTP requests.', 
#     attack_type='Remote Code Execution (RCE)',
#     services=['cacti:1.2.22', 'php:7.4-apache', 'mysql:5.7'],
#     service_description=['Cacti 1.2.22 is the vulnerable version of the network monitoring tool where the command injection vulnerability exists.', 'PHP 7.4 with Apache is required to run Cacti, as it is a PHP-based application.', 'MySQL 5.7 is used as the database backend for Cacti to store monitoring data and configurations.'],),
# "web_search_result": WebSearchResult(
#     description='CVE-2024-23897 is a critical vulnerability in Jenkins' CLI, allowing unauthorized file reads and potential RCE due to a flaw in the args4j library.',
#     attack_type='Remote Code Execution (RCE)',
#     services=['jenkins:2.441', 'openjdk:11-jre-slim'],
#     service_description=['Jenkins:2.441 - This version of Jenkins is vulnerable to CVE-2024-23897 due to the args4j library flaw in its CLI, allowing unauthorized file reads and potential RCE.', 'OpenJDK:11-jre-slim - Required to run Jenkins, as Jenkins is a Java-based application.'],),
#* OBTAINED WITH 'openai'
# "web_search_result": WebSearchResult(
#     description='Eclipse Jetty versions 9.4.37.v20210219 through 9.4.38.v20210224 allow requests with URIs containing `%2e` or `%2e%2e` segments to access protected resources within the `WEB-INF` directory, potentially exposing sensitive information.',
#     attack_type='Information Disclosure',
#     services=['eclipse/jetty:9.4.38.v20210224'],
#     service_description=['Eclipse Jetty is a widely used web server and servlet container that is vulnerable to the CVE-2021-28164, allowing unauthorized access to protected resources.'],),
# "web_search_result": WebSearchResult(
#     description='CVE-2022-46169 is a critical command injection vulnerability in Cacti versions up to and including 1.2.22. It allows unauthenticated users to execute arbitrary code on servers running the affected versions. The flaw resides in the `remote_agent.php` file, which can be accessed without authentication. By manipulating HTTP headers, an attacker can bypass authorization checks and exploit the `poll_for_data` function to execute commands on the server. ([nvd.nist.gov](https://nvd.nist.gov/vuln/detail/cve-2022-46169?utm_source=openai))',
#     attack_type='Remote Code Execution (RCE)',
#     services=['Cacti:1.2.22', 'Apache:2.4.54', 'MariaDB:10.5.16', 'PHP:7.4.30'],
#     service_description=['This version is directly affected by CVE-2022-46169. Docker Image: `cacti/cacti:1.2.22`', 'A compatible web server for hosting Cacti. Docker Image: `httpd:2.4.54`', 'A compatible database server for Cacti. Docker Image: `mariadb:10.5.16`', 'A compatible PHP version required by Cacti 1.2.22. Docker Image: `php:7.4.30-apache`'],),
# "web_search_result": WebSearchResult(
#     description='CVE-2024-23897 is a critical vulnerability in Jenkins versions 2.441 and earlier, as well as LTS versions 2.426.2 and earlier. This flaw allows unauthenticated attackers to read arbitrary files on the Jenkins controller file system by exploiting a feature in the CLI command parser that replaces an '@' character followed by a file path with the file's contents. ([nvd.nist.gov](https://nvd.nist.gov/vuln/detail/cve-2024-23897?utm_source=openai))',
#     attack_type='Arbitrary File Read',
#     services=['jenkins:2.441'],
#     service_description=['This Docker image corresponds to Jenkins version 2.441, which is susceptible to CVE-2024-23897.'],),


  