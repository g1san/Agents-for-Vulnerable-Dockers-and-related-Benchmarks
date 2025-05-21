from typing import Annotated, Optional
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from configuration import CodeGenerationResult


class OverallState(BaseModel):
    cve_id: str = Field(description="The ID of the CVE")

    is_cve: bool = Field(
        default=False, description="Does the ID exists in the MITRE CVE database?"
    )

    cve_assessment: Optional[str] = Field(
        default="",
        description="Store the CVE ID assessment result",
    )

    web_search_result: str = Field(
        default="", description="The result of the web search"
    )

    code: CodeGenerationResult = Field(
        default=CodeGenerationResult(file_name=[], file_code=[], directory_tree=""),
        description="The generated file names and code and associated directory tree",
    )

    code_ok: bool = Field(
        default=True, description="Is the docker working?"
    )  # TODO: switch default to False

    feedback: str = Field(
        default="",
        description="Feedback from the user about the generated docker code",
    )  # (e.g. check if the services are running correctly)

    messages: Annotated[list[AnyMessage], add_messages] = Field(
        default=[], description="Conversation with LLM, tracked for analysis"
    )
