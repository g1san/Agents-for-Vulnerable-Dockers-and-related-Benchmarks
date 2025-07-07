from typing import Annotated, Optional
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

# My modules
from configuration import CodeGenerationResult, WebSearchResult, TestCodeResult


class OverallState(BaseModel):
    cve_id: str = Field(
        default="",
        description="The ID of the CVE"
    )

    is_cve: bool = Field(
        default=False, 
        description="Does the ID exists in the MITRE CVE database?"
    )

    web_search_tool: str = Field(
        default="custom", 
        description="The name of the web search tool"
    )

    web_search_result: WebSearchResult = Field(
        default=WebSearchResult(description="", attack_type="", services=[], service_type=[], service_description=[]), 
        description="The result of the web search"
    )
    
    docker_services_ok: bool = Field(
        default=False, 
        description="Are the Docker services needed to reproduce the CVE the expected ones?"
    )

    code: CodeGenerationResult = Field(
        default=CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
        description="The generated file name, code and associated directory tree"
    )

    feedback: TestCodeResult = Field(
        default=TestCodeResult(code_ok=False, error="", fix="", fixed_code=CodeGenerationResult(file_name=[], file_code=[], directory_tree="")),
        description="Feedback about the generated docker code"
    )
    
    test_iteration: int = Field(
        default=0, 
        description="Number of iterations of the test code node"
    )

    messages: Annotated[list[AnyMessage], add_messages] = Field(
        default=[], 
        description="Conversation with LLM, tracked for analysis"
    )
    
    debug: Optional[str] = Field(
        default="", 
        description="String to handle debug and skip nodes"
    )
