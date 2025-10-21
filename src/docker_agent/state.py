from typing import Annotated, Optional
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI

# My modules
from configuration import Code, WebSearch, Stats, Milestones


class OverallState(BaseModel):
    model_name: str = Field(
        default="",
        description="Name of the model chosen for this agent run"
    )
    
    llm: ChatOpenAI = Field(
        default=None, 
        description="LLM instance being used"
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
    
    revision_goal: str = Field(
        default="",
        description="Goal of the revision phase"
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
