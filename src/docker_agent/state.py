from typing import Annotated, Optional
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

# My modules
from configuration import CodeGenerationResult, WebSearchResult


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
        default=WebSearchResult(description="", attack_type="", services=[], service_description=[]), 
        description="The result of the web search"
    )
    
    docker_services_ok: bool = Field(
        default=False, 
        description="Are the Docker services needed to reproduce the CVE the expected ones?"
    )

    code: CodeGenerationResult = Field(
        default=CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
        description="The generated file names and code and associated directory tree"
    )

    code_ok: bool = Field(
        default=True, 
        description="Is the docker working?"
    )  # TODO: switch default to False

    feedback: str = Field(
        default="",
        description="Feedback from the user about the generated docker code"
    )

    messages: Annotated[list[AnyMessage], add_messages] = Field(
        default=[], 
        description="Conversation with LLM, tracked for analysis"
    )
