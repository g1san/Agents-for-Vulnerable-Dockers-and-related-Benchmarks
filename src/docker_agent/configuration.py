"""Define the Langfuse handler, the agent's graph state and the various LLM configurations and bindings"""

import os
from typing import Optional
from langfuse import Langfuse, get_client
from langfuse.langchain import CallbackHandler
from pydantic import BaseModel, Field
 
# Initialize Langfuse client with constructor arguments
Langfuse(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_HOST"),
)
 
# Get the configured client instance
langfuse = get_client()
# Initialize Langfuse CallbackHandler for LangGraph/Langchain (tracing)
langfuse_handler = CallbackHandler()


class WebSearchResult(BaseModel):
    desc: str = Field(description="Description of the CVE")
    attack_type: str = Field(description="Type of attack (e.g. DoS, RCE, etc.)")
    services: list[str] = Field(description="List of services names to be included in a Docker-based system vulnerable to the given CVE-ID, must not include versions or tags")
    service_type: list[str] = Field(description="List containing the type associated to the service ('MAIN' or 'AUX')")
    service_vers: list[str] = Field(description="List containing the service versions")
    service_desc: list[str] = Field(description="List of descriptions for each service, each explaining briefly why the service is necessary in the Docker")


class MAINServiceVersionAssessment(BaseModel):
    main_service_version: bool = Field("Does the 'MAIN' service version range contain the expected version?")


class CodeGenerationResult(BaseModel):
    file_name: list[str] = Field(description="Name of the files needed to reproduce the CVE")
    file_code: list[str] = Field(description="Name and code of the various files needed to reproduce the CVE")
    directory_tree: str = Field(description="Directory tree where the files will be stored, rooted in the CVE-ID folder")
    
    
class TestCodeResult(BaseModel):
    error: str = Field(description="Detailed description of the error presented by the logs")
    fix: str = Field(description="Detailed description of fix applied to the code to solve the error")
    fixed_code: CodeGenerationResult = Field(description="The fixed file names, code and associated directory tree")

    
class CodeMilestonesAssessment(BaseModel):
    docker_runs: bool = Field(default=False, description="Does the Docker system run correctly?")
    services_ok: bool = Field(description="Does the generated code contain the services provided by the web search?")
    code_main_version: bool = Field(description="Does the generated code use a vulnerable version of the 'MAIN' service?")
    fail_explanation: Optional[str] = Field(description="Detailed explanation of why one or more goals have failed")
    

    
class Milestones(BaseModel):
    # CVE Milestone
    cve_id_ok: bool = Field(default=False, description="Does the provided CVE-ID exist in the MITRE CVE database?")
    # Web Search Milestones
    main_service: bool = Field(default=False, description="Was the 'MAIN' service correctly identified?")
    main_version: bool = Field(default=False, description="Does the 'MAIN' service version range contain the expected version?")
    aux_services: bool = Field(default=True, description="Are all the necessary 'AUX' services proposed?")
    # Code Milestones
    docker_runs: bool = Field(default=False, description="Does the Docker container run correctly?")
    services_ok: bool = Field(default=False, description="Does the generated code contain the services provided by the web search?")
    code_main_version: bool = Field(default=False, description="Does the generated code use a vulnerable version of the 'MAIN' service?")
    # Exploitability Milestones
    docker_vulnerable: bool = Field(default=False, description="Is the Docker environment vulnerable to the specified CVE?")
    exploitable: bool = Field(default=False, description="Does the exploit return the expected result?")