# TODOLIST
- ***"get_services"***
    - Add manual retrieval of CVE data from Exploit DB (local repository needs to be available)
    - Check if order of URL provided by Google API is the same every time
    - Benchmark how many URLs does the LLM need to check for a given CVE to get the GT services, do it just for one CVE, it is a useful result for the thesis
- ***"test_code"***
    - Assess if it works correctly using the Dockers from VDaaS
    - Implement "scratchpad" from which the LLM can memorise previous fix attempts
    - Use MAVEN to assess if CVE is present in Docker (look at what Docker Desktop can do)
    - Implement MAVEN for vulnerability assessment
    - Implement MCP for Docker Desktop in another branch
- **Expand logging**:
    - Create log for code
    - Create log for conversation history
- **Problems discovered with testing**:
    - Some non-vulnerable service version are reported as vulnerable (e.g. CVE-2021-28164)
    - Launching the docker of CVE-2024-23897 requires root privileges to perform certain commands, might want to check security
    - Manually forcing the Docker to stop (e.g. CVE-2022-46169) is seen as a potential issue by LLM which tries to solve the problem, even though the containers seem to work fine, might be related to having multiple active containers 
- **Implement LLM-as-a-judge**: invoke LLM to check if generated code has the correct versions provided by the web search, may require expanding the **CodeGenerationResult**
- Evaluate if change milestone to _float_ instead of _bool_


- Keep going with the benchmarks using the web search results, before that correct them to account for the BENCHMARK-ANALYSIS.md
- For those CVEs that fail a specific milestone try a making MAX=3 attempts, or try to add a web search to assert if the 'MAIN' service requires some specific 'AUX' services to work.
- Evaluate the use of MCP for future proofing
- Store the results also in **_csv_** format
