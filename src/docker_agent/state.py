from typing import Annotated, Optional
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

# My modules
from configuration import Code, WebSearch, Stats, Milestones


class OverallState(BaseModel):
    model: str = Field(
        default="",
        description="Model chosen for this agent run"
    )
    
    cve_id: str = Field(
        default="",
        description="The ID of the CVE"
    )

    web_search_tool: str = Field(
        default="custom_no_tool", 
        description="The web search mode"
    )
    
    verbose_web_search: bool = Field(
        default=False,
        description="Choose if the web search will be verbose or not"
    )

    web_search_result: WebSearch = Field(
        default=WebSearch(desc="", attack_type="", services=[]), 
        description="The result of the web search"
    )

    code: Code = Field(
        default=Code(files=[], directory_tree=""),
        description="The generated file name, code and associated directory tree"
    )
    
    fail_explanation: str = Field(
        default="",
        description="Detailed explanation of why the Docker has failed testing"
    )
    
    revision_type: str = Field(
        default="",
        description="Type of revision to be applied to the Docker code"
    )
    
    fixes: list[str] = Field(
        default=[],
        description="List of attempted fixes to the code"
    )

    messages: Annotated[list[AnyMessage], add_messages] = Field(
        default=[], 
        description="Conversation with LLM, tracked for analysis"
    )
    
    stats: Stats = Field(
        default=Stats(),
        description="Various stats about the current workflow"
    )
    
    milestones: Milestones = Field(
        default=Milestones(),
        description="Milestones of the workflow, used to to track its progress"
    )
    
    debug: Optional[str] = Field(
        default="", 
        description="String to handle debug and skip nodes"
    )
