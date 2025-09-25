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


class Service(BaseModel):
    name: str = Field(description="Name of the service")
    version: list[str] = Field(description="Versions of the service")
    dependency_type: str = Field(description="Type of the dependency of the service, either 'HARD' or 'SOFT'")
    description: str = Field(description="Brief description of why the service is necessary in the Docker")


class WebSearchResult(BaseModel):
    desc: str = Field(description="Description of the CVE")
    attack_type: str = Field(description="Type of attack (e.g. DoS, RCE, etc.)")
    services: list[Service] = Field(description="List of services to be used in the Docker system vulnerable to the CVE-ID")
    

class HARDServiceVersionAssessment(BaseModel):
    hard_version: bool = Field("Does the 'HARD' service version range contain the expected version?")


class CodeGenerationResult(BaseModel):
    file_name: list[str] = Field(description="Name of the files needed to reproduce the CVE")
    file_code: list[str] = Field(description="Name and code of the various files needed to reproduce the CVE")
    directory_tree: str = Field(description="Directory tree where the files will be stored, rooted in the CVE-ID folder")


class ContainerLogsAssessment(BaseModel):
    container_ok: bool = Field(description="Does the Docker container run correctly?")
    fail_explanation: Optional[str] = Field(description="Detailed explanation of the error presented by the logs")
    
    
class TestCodeResult(BaseModel):
    error: str = Field(description="Detailed description of the error presented by the logs")
    fix: str = Field(description="Detailed description of fix applied to the code to solve the error")
    fixed_code: CodeGenerationResult = Field(description="The fixed file names, code and associated directory tree")

    
class CodeMilestonesAssessment(BaseModel):
    docker_builds: bool = Field(description="Do all Docker images get built correctly?")
    docker_runs: bool = Field(description="Does the Docker system run correctly?")
    services_ok: bool = Field(description="Does the generated code contain the services provided by the web search?")
    code_hard_version: bool = Field(description="Does the generated code use vulnerable version of the 'HARD' services?")
    fail_explanation: Optional[str] = Field(description="Detailed explanation of why one or more milestones have failed")


class Stats(BaseModel):
    num_containers: int = Field(default=0, description="Number of containers created while testing the Docker")
    test_iteration: int = Field(default=0, description="Number of iterations of the test loop")
    starting_image_builds: bool = Field(default=True, description="Checks if the LLM is able to generate a buildable Docker image in the first test iteration")
    image_build_failures: int = Field(default=0, description="Number of times the Docker image fails to build")
    starting_container_runs: bool = Field(default=True, description="Checks if the LLM is able to generate working Docker container in the first test iteration")
    container_run_failures: int = Field(default=0, description="Number of times the Docker container fails to run")
    not_vuln_version_fail: int = Field(default=0, description="Number of times the Docker builds and runs correctly but uses a not vulnerable version of the 'HARD' service")
    
    
class Milestones(BaseModel):
    # CVE Milestone
    cve_id_ok: bool = Field(default=False, description="Does the provided CVE-ID exist in the MITRE CVE database?")
    # Web Search Milestones
    hard_service: bool = Field(default=False, description="Were the 'HARD' services correctly identified?")
    hard_version: bool = Field(default=False, description="Do the 'HARD' services version range contain the expected version?")
    soft_services: bool = Field(default=False, description="Are all the necessary 'SOFT' services proposed?")
    # Code Milestones
    docker_builds: bool = Field(default=False, description="Do all Docker images get built correctly?")
    docker_runs: bool = Field(default=False, description="Do all Docker containers run correctly?")
    code_hard_version: bool = Field(default=False, description="Does the generated code use vulnerable version of the 'HARD' services?")
    services_ok: bool = Field(default=False, description="Does the generated code contain the services provided by the web search?")
    # Exploitability Milestones
    docker_vulnerable: bool = Field(default=False, description="Is the Docker environment vulnerable to the specified CVE?")