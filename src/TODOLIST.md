# TODOLIST



## Useful for Thesis
_Suggestion_: split CHECKs of test milestones into multiple interactions with the LLM (use list to with all questions to format a single prompt)
**MANDATORY**: check all files of all dockers to assess LLM-as-a-Judge reliability

### Docker Validation with PoC
- Ultimate goal of the **_run\_exploit_** node function is to launch the PoC for the specific CVE, extract the output, pass it to an LLM-as-a-Judge and evaluate if the output is the desired one (might want to pass the code of the exploit) or if there is a problem with either the docker or the exploit code.

### Better graphs
- Add % values to the heatmap graph

### More stats
- Most frequently used services both HARD and SOFT dependencies &rarr; _web\_search\_result.json_ can be used to compute these stats
- Most frequent cause of error during testing (linked to specific service or programming language?) &rarr; _final\_report.txt.json_ can be used to compute these stats
- Number of lines of code of each file produced as a solution by the LLM (consider only CVEs or which all LLMs produced a working solution) &rarr; files can be used to compute these stats

### LLM Generated Code Assessment
- https://www.confident-ai.com/blog/llm-evaluation-metrics-everything-you-need-for-llm-evaluation#model-based-scorers
- https://www.confident-ai.com/blog/g-eval-the-definitive-guide
- https://arxiv.org/abs/2410.02184
- https://arxiv.org/abs/2408.16498v1
- https://mingwei-liu.github.io/assets/pdf/ICSE2024ClassEval-V2.pdf

### Reasoning models
- Check out these for prompting and parameter set up:
    - https://platform.openai.com/docs/guides/reasoning
    - https://platform.openai.com/docs/guides/reasoning-best-practices
    - https://platform.openai.com/docs/guides/latest-model



## Future Works
- Implement MCP for Docker Desktop in another branch for future proofing
- **Problems discovered with testing**:
    - CVE-2020-7247 and CVE-2021-41773 repeatedly caused this error: Workflow invocation failed: Could not parse response content as the length limit was reached - CompletionUsage(completion_tokens=16384, prompt_tokens=3447, total_tokens=19831, completion_tokens_details=CompletionTokensDetails(accepted_prediction_tokens=0, audio_tokens=0, reasoning_tokens=0, rejected_prediction_tokens=0), prompt_tokens_details=PromptTokensDetails(audio_tokens=0, cached_tokens=0))