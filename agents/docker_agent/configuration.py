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

llm = ChatOpenAI(
    model="gpt-4o", temperature=0, max_tokens=500, max_retries=2
)

llm_web_search_tool = llm.bind_tools([web_search])
