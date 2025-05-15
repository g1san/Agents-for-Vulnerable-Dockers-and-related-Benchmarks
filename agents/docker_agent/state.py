from typing import Annotated
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


class OverallState(BaseModel):
    cve_id: str = Field(description="The ID of the CVE")

    is_cve: bool = Field(
        default=True, description="Does the ID exists in the CVE database?"
    )  # (e.g. check https://www.cve.org/CVERecord?id=CVE-YYYY-XXXXX)

    web_search_result: str = Field(
        default="", description="The result of the web search"
    )

    docker_code: str = Field(default="", description="The generated docker code")

    code_ok: bool = Field(
        default=True, description="Is the docker working?"
    )  # TODO: switch default to False

    feedback: str = Field(
        default="",
        description="Feedback from the user about the generated docker code",
    )  # (e.g. check if the services are running correctly)

    messages: Annotated[list[AnyMessage], add_messages] = Field(
        default=[],
        description="Conversation with LLM, tracked for analysis"
    )
