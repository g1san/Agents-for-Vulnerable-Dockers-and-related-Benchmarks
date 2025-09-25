# TODOLIST

## Useful for Thesis
- Add % values to the heatmap graph
- **Compute stats about**:
    - Most frequently used services both HARD and SOFT dependencies
    - Most frequent cause of error during testing (linked to specific service or programming language?)
    - Number of lines of code of each file produced as a solution by the LLM (consider only CVEs or which all LLMs produced a working solution)
- Implement ideas with new milestones taken from here https://ploomber.io/blog/docker-gen/
- Read also these articles/papers about evaluation of LLM generated code: 
    - https://www.confident-ai.com/blog/llm-evaluation-metrics-everything-you-need-for-llm-evaluation#model-based-scorers
    - https://www.confident-ai.com/blog/g-eval-the-definitive-guide
    - https://arxiv.org/abs/2410.02184
    - https://arxiv.org/abs/2408.16498v1
    - https://mingwei-liu.github.io/assets/pdf/ICSE2024ClassEval-V2.pdf
- Parameter for GPT-5 and o1, et simila LLMs:
    reasoning={
        "effort": "medium",  # can be "low", "medium", or "high"
        "summary": "auto",  # can be "auto", "concise", or "detailed"
    }

## Future Works
- Implement MCP for Docker Desktop in another branch for future proofing
- **Problems discovered with testing**:
    - CVE-2020-7247 and CVE-2021-41773 repeatedly caused this error: Workflow invocation failed: Could not parse response content as the length limit was reached - CompletionUsage(completion_tokens=16384, prompt_tokens=3447, total_tokens=19831, completion_tokens_details=CompletionTokensDetails(accepted_prediction_tokens=0, audio_tokens=0, reasoning_tokens=0, rejected_prediction_tokens=0), prompt_tokens_details=PromptTokensDetails(audio_tokens=0, cached_tokens=0))