"""Define the Langfuse handler, the agent's graph state and the various LLM configurations and bindings"""

import os
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
    """Pydantic object for web search result"""

    desc: str = Field(description="Description of the CVE")

    attack_type: str = Field(description="Type of attack (e.g. DoS, RCE, etc.)")

    services: list[str] = Field(description="List of services to be included in a Docker-based system vulnerable to the given CVE-ID")
    
    service_type: list[str] = Field(description="List containing the type associated to the service ('MAIN' or 'AUX')")
    
    service_vers: list[str] = Field(description="List containing the service versions")

    service_desc: list[str] = Field(description="List of descriptions for each service, each explaining briefly why the service is necessary in the Docker")


class CodeGenerationResult(BaseModel):
    """Pydantic object for code generation result"""

    file_name: list[str] = Field(description="Name of the files needed to reproduce the CVE")

    file_code: list[str] = Field(description="Name and code of the various files needed to reproduce the CVE")

    directory_tree: str = Field(description="Directory tree where the files will be stored, rooted in the CVE-ID folder")


class TestCodeResult(BaseModel):
    """Pydantic object for test code result"""
    
    code_ok: bool = Field(description="Is the Docker system working correctly?")
    
    error: str = Field(description="Description of the error presented by the 'docker compose up' command")
    
    fix: str = Field(description="Description of fix applied to the code to solve the error")
    
    fixed_code: CodeGenerationResult = Field(description="The fixed file names, code and associated directory tree")
    
    
class Milestones(BaseModel):
    """Pydantic object for workflow milestones"""
    
    # CVE Milestone
    cve_id_exists: bool = Field(default=False, description="Does the provided CVE-ID exist in the MITRE CVE database?")
    # Web Search Milestones
    main_service_identified: bool = Field(default=False, description="Was the 'MAIN' service correctly identified?")
    main_service_version: bool = Field(default=False, description="Does the 'MAIN' service version range contain the expected version?")
    # Code Milestones
    services_implemented_in_code: bool = Field(default=False, description="Does the generated code contain the services provided by the web search?")
    main_service_uses_vulnerable_version: bool = Field(default=False, description="Does the generated code use a vulnerable version of the 'MAIN' service?")
    docker_runs: bool = Field(default=False, description="Does the Docker container run?")
    # Exploitability Milestones
    docker_vulnerable_to_cve: bool = Field(default=False, description="Is the Docker environment vulnerable to the specified CVE?")
    exploit_returns_expected_result: bool = Field(default=False, description="Does the exploit return the expected result?")