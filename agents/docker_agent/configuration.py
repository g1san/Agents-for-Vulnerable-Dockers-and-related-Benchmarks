"""Define the configurable parameters for the agent and Langfuse handler"""

import os
from langfuse.callback import CallbackHandler
from langchain_openai import ChatOpenAI
from tools import web_search

# Initialize Langfuse CallbackHandler for LangGraph/Langchain (tracing)
langfuse_handler = CallbackHandler(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_HOST"),
)


#! Structured output for the web search
# from pydantic import BaseModel, Field
# class WebSearchResult(BaseModel):
#     """Pydantic object for web search result"""
#
#     description: str = Field(description="Short description of the CVE")
#     attack_type: str = Field(description="Type of attack (e.g. DoS, RCE, etc.)")
#     services: list[str] = Field(
#         description="List of services to be included in a Docker-based system vulnerable to the given CVE-ID. The vulnerable version(s) of each service must be specified."
#     )


# Initialize the LLM with OpenAI's GPT-4o model
llm = ChatOpenAI(model="gpt-4o", temperature=0, max_tokens=750, max_retries=2)

# Bind the LLM with its built-in web_search tool
llm_web_search_tool = llm.bind_tools([web_search])

#! Set the LLM to return a structured output from the web search
# structured_llm = llm.with_structured_output(WebSearchResult)
