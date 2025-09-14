from typing import Annotated, Optional
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

# My modules
from configuration import CodeGenerationResult, WebSearchResult, TestCodeResult, Milestones


class OverallState(BaseModel):
    cve_id: str = Field(
        default="",
        description="The ID of the CVE"
    )

    web_search_tool: str = Field(
        default="custom_no_tool", 
        description="The web search mode"
    )

    web_search_result: WebSearchResult = Field(
        default=WebSearchResult(desc="", attack_type="", services=[]), 
        description="The result of the web search"
    )

    code: CodeGenerationResult = Field(
        default=CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
        description="The generated file name, code and associated directory tree"
    )

    feedback: TestCodeResult = Field(
        default=TestCodeResult(error="", fix="", fixed_code=CodeGenerationResult(file_name=[], file_code=[], directory_tree="")),
        description="Feedback about the generated docker code"
    )
    
    logs: str = Field(
        default="",
        description="Logs obtained while testing the Docker code"
    )
    
    fail_explanation: str = Field(
        default="",
        description="Detailed explanation of why one or more milestones have failed"
    )
    
    revision_type: str = Field(
        default="",
        description="Type of revision to be applied to the Docker code"
    )
    
    fixes: list[str] = Field(
        default=[],
        description="List of attempted fixes to the code"
    )
    
    num_containers: int = Field(
        default=0,
        description="Number of containers created while testing the Docker"
    )
    
    test_iteration: int = Field(
        default=0,
        description="Number of iterations of the test code node"
    )

    messages: Annotated[list[AnyMessage], add_messages] = Field(
        default=[], 
        description="Conversation with LLM, tracked for analysis"
    )
    
    final_report: str = Field(
        default="",
        description="String that summarizes the workflow which will be ave in the 'final_report.txt' file"
    )
    
    milestones: Milestones = Field(
        default=Milestones(),
        description="Milestones of the workflow, used to to track its progress"
    )
    
    debug: Optional[str] = Field(
        default="", 
        description="String to handle debug and skip nodes"
    )
