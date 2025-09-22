# TODOLIST

## Useful for Thesis
- **Next up, do the test with GPT-5 and the local model**
- Add % values to the heatmap graph
- Test SmartData LLMs and compute stats about them:
    - Most frequently used services both HARD and SOFT dependencies
    - Most frequent cause of error during testing (linked to specific service or programming language?)
    - Number of lines of code of each file produced as a solution by the LLM (consider only CVEs or which all LLMs produced a working solution)


## Future Works
- Implement MCP for Docker Desktop in another branch for future proofing
- **Problems discovered with testing**:
    - CVE-2020-7247 and CVE-2021-41773 repeatedly caused this error: Workflow invocation failed: Could not parse response content as the length limit was reached - CompletionUsage(completion_tokens=16384, prompt_tokens=3447, total_tokens=19831, completion_tokens_details=CompletionTokensDetails(accepted_prediction_tokens=0, audio_tokens=0, reasoning_tokens=0, rejected_prediction_tokens=0), prompt_tokens_details=PromptTokensDetails(audio_tokens=0, cached_tokens=0)).