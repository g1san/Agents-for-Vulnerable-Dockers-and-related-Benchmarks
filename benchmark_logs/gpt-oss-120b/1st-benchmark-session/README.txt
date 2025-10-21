# Initialize the LLM with SmartData cluster's local models #* gpt-oss:20b/gpt-oss:120b *#
llm = ChatOpenAI(
    model="gpt-oss:120b",
    max_retries=2, 
    reasoning_effort="medium",      # Set to "low" in the web search 
    base_url="https://kubernetes.polito.it/vllm/v1",
    api_key=os.getenv("SDC_API_KEY"),
)

CVE-2022-24706 ALWAYS FAILS because it keeps producing markdown responses