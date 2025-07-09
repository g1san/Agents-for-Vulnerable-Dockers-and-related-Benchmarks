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
            "cve_id": "CVE-2021-28164",#    CVE-2021-28164    CVE-2022-46169    CVE-2024-23897  #NOTE: to test GT update use CVE-2017-7525
            "web_search_tool": "skip",#   custom  custom_no_tool  openai  skip        #NOTE: if 'skip' is used, initialize "web_search_result" with valid data
            #"web_search_result": WebSearchResult(description="", attack_type="", services=[], service_type=[], service_description=[]),
            "web_search_result": WebSearchResult(
                description='CVE-2021-28164 is a vulnerability in Eclipse Jetty, affecting versions 9.4.37.v20210219 to 9.4.42, 10.0.1 to 10.0.5, and 11.0.1 to 11.0.5. The vulnerability arises from improper handling of URIs containing encoded segments like %2e or %2e%2e, allowing unauthorized access to protected resources within the WEB-INF directory, such as the web.xml file. This can lead to information disclosure and potential further exploitation.',
                attack_type='Information Disclosure',
                services=['jetty:9.4.37', 'openjdk:8-jdk'],
                service_type=['MAIN', 'AUX'],
                service_description=['Jetty is the main service vulnerable to CVE-2021-28164, allowing unauthorized access to sensitive files through improperly handled URIs.', 'OpenJDK is required to run Jetty, as it is a Java-based web server.'],
            ),
            'code': CodeGenerationResult(
                file_name=['docker-compose.yml', 'Dockerfile', 'webapps/WEB-INF/web.xml', 'webapps/index.html'],
                file_code=['version: \'3.8\'\nservices:\n  jetty:\n    build: .\n    ports:\n      - "8080:8080"\n    volumes:\n      - ./webapps:/var/lib/jetty/webapps\n', 'FROM jetty:9.4.38-jre8\n\nCOPY ./webapps /var/lib/jetty/webapps\n', '<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"\n         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee \n         http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"\n         version="3.1">\n\n    <servlet>\n        <servlet-name>default</servlet-name>\n        <servlet-class>org.eclipse.jetty.servlet.DefaultServlet</servlet-class>\n    </servlet>\n\n    <servlet-mapping>\n        <servlet-name>default</servlet-name>\n        <url-pattern>/</url-pattern>\n    </servlet-mapping>\n\n</web-app>\n', '<html>\n<head>\n    <title>Jetty Vulnerable App</title>\n</head>\n<body>\n    <h1>Welcome to the Jetty Vulnerable Application</h1>\n    <p>This application is vulnerable to CVE-2021-28164.</p>\n</body>\n</html>\n'],
                directory_tree='CVE-2021-28164/\n├── docker-compose.yml\n├── Dockerfile\n└── webapps\n    ├── WEB-INF\n    │   └── web.xml\n    └── index.html\n',
            ),
            #"code": CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
            "debug": "skip_to_test"#        (DEFAULT="")    skip_to_test
        },
        config={"callbacks": [langfuse_handler], "recursion_limit": 100},
    )

    # Review conversation history
    # print()
    # for message in result["messages"]:
    #     print("=" * 20 + f" {message.type.upper()} " + "=" * 20)
    #     print(f"{message.content}\n")

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