# TODOLIST
- Implement MCP for Docker Desktop in another branch for future proofing
- Rewrite which messages are passed to the LLM at each step to decrease token consumption
- Rewrite _final\_report_ as a continuous effort to to write on the file from start to beginning
- **Problems discovered with testing**:
    - CVE-2020-7247 and CVE-2021-41773 repeatedly caused this error: Workflow invocation failed: Could not parse response content as the length limit was reached - CompletionUsage(completion_tokens=16384, prompt_tokens=3447, total_tokens=19831, completion_tokens_details=CompletionTokensDetails(accepted_prediction_tokens=0, audio_tokens=0, reasoning_tokens=0, rejected_prediction_tokens=0), prompt_tokens_details=PromptTokensDetails(audio_tokens=0, cached_tokens=0)).
    - [Errno 21] Is a directory: '../../dockers/CVE-2021-34429/openai/nginx.conf'.
        - Always happens with _nginx_ related files