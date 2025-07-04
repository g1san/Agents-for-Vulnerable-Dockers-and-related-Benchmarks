"""Define the Langfuse handler, the agent's graph state and the various LLM configurations and bindings"""

import os
from langfuse.callback import CallbackHandler
from pydantic import BaseModel, Field

# Initialize Langfuse CallbackHandler for LangGraph/Langchain (tracing)
langfuse_handler = CallbackHandler(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_HOST"),
)

# Define the list of expected services for each replicable CVE, works as a GROUND TRUTH
# dockerServices = {
#     "CVE-2012-1823": ["MAIN:php:5.4.1-cgi", "AUX:php:5.4.1"],
#     "CVE-2016-5734": ["MAIN:phpmyadmin:4.4.15.6", "AUX:php:5.3-apache", "AUX:mysql:5.5"],
#     "CVE-2018-12613": ["MAIN:phpmyadmin:4.8.1", "AUX:php:7.2-apache", "AUX:mysql:5.5"],
#     "CVE-2020-7247": ["MAIN:opensmtpd:6.6.1p1"],
#     "CVE-2020-11651": ["MAIN:saltstack:2019.2.3"],
#     "CVE-2020-11652": ["MAIN:saltstack:2019.2.3"],
#     "CVE-2021-3129": ["MAIN:laravel:8.4.2", "AUX:php:7.4-apache"],
#     "CVE-2021-28164": ["MAIN:jetty:9.4.37"],
#     "CVE-2021-34429": ["MAIN:jetty:9.4.40"],
#     "CVE-2021-41773": ["MAIN:apache", "AUX:httpd:2.4.49"],
#     "CVE-2021-42013": ["MAIN:apache", "AUX:httpd:2.4.50"],
#     "CVE-2021-43798": ["MAIN:grafana:8.2.6"],
#     "CVE-2021-44228": ["MAIN:solr:8.11.0"],
#     "CVE-2022-22947": ["MAIN:spring-cloud-gateway:3.1.0"],
#     "CVE-2022-22963": ["MAIN:spring-cloud-function:3.2.2"],
#     "CVE-2022-24706": ["MAIN:couchdb:3.2.1"],
#     "CVE-2022-46169": ["MAIN:cacti:1.2.22", "AUX:php:7.4-apache", "AUX:mysql:5.7"],
#     "CVE-2023-23752": ["MAIN:joomla:4.2.7", "AUX:php:7.4.33-apache", "AUX:mysql:5.7"],
#     "CVE-2023-42793": ["MAIN:teamcity:2023.05.3", "AUX:jetbrains/teamcity-server:2023.05.3"],
#     "CVE-2024-23897": ["MAIN:jenkins:2.441"],
# }


class WebSearchResult(BaseModel):
    """Pydantic object for web search result"""

    description: str = Field(description="Short description of the CVE")

    attack_type: str = Field(description="Type of attack (e.g. DoS, RCE, etc.)")

    services: list[str] = Field(description="List of services to be included in a Docker-based system vulnerable to the given CVE-ID")
    
    service_type: list[str] = Field(description="List containing the type associated to the service ('MAIN' or 'AUX')")

    service_description: list[str] = Field(description="List of descriptions for each service, each explaining briefly why the service is necessary in the Docker")


class CodeGenerationResult(BaseModel):
    """Pydantic object for code generation result"""

    file_name: list[str] = Field(description="Name of the files needed to reproduce the CVE")

    file_code: list[str] = Field(description="Name and code of the various files needed to reproduce the CVE")

    directory_tree: str = Field(description="Directory tree where the files will be stored, rooted in the CVE-ID folder")


class TestCodeResult(BaseModel):
    """Pydantic object for test code result"""
    
    code_ok: bool = Field(description="Is the Docker system working correctly?")
    
    error_analysis: str = Field(description="If the Docker system is not working correctly, provide an analysis of the error")
    
    fix_suggestion: str = Field(description="If the Docker system is not working correctly, suggest a fix to the error")
    