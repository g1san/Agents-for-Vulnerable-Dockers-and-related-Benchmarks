# TODOLIST
- ***"get_docker_services"***
    - (***DONE***) Improve it by making the LLM associate a specific tag to the **main service**, i.e., the service that is vulnerable to the CVE.
    - (***DONE***) Add **auxiliary** tag to services added just to make the main service work or to make the docker work
    - (***DONE***) Add manual retrieval of CVE data from NIST website for _custom_web_search_ because of error 502
    - Add manual retrieval of CVE data from Exploit DB (local repository needs to be available)
    - Check if order of URL provided by Google API is the same every time
    - Benchmark how many URLs does the LLM need to check for a given CVE to get the GT services, do it just for one CVE, it is a useful result for the thesis
- ***"assess_docker_services"***
    - (***DONE***) Improve it by having the LLM check if the **main service** version is a vulnerable one
    - (***DONE***) If GT for CVE does not exist, save the result locally in order to improve GT database
- ***"save_code"***
    - (***DONE***) The whole node functionality needs to be assessed
    - (***DONE***) Implemented only partially, *keep coding*
    - (***DONE***) Evaluate if the code fixes should be applied here or in ***generate_docker_code***
- ***"test_docker_code"***
    - (***DONE***) Make it work with WSL
    - (***DONE***) Generate commands needed to launch and dispose of Docker
    - (***DONE***) Retrieve and report back eventual errors from the terminal
    - (***DONE***) Evaluate the errors and provide feedback to ***generate_docker_code***
    - Assess if it works correctly using the Dockers from VDaaS
    - Implement "scratchpad" from which the LLM can memorise previous fix attempts
    - Use MAVEN to assess if CVE is present in Docker (look at what Docker Desktop can do)
    - (***DONE***) Implement function to write final_report file into "logs" directory

- ***IMPORTANT***
    - Solve the problems related to the fact that non-vulnerable service version are reported as vulnerable (e.g. CVE-2021-28164)
    - Launching the docker of CVE-2024-23897 requires root privileges to perform certain commands, might want to check security
    - Manually forcing the Docker to stop (e.g. CVE-2022-46169) is seen as a potential issue by LLM which tries to solve the problem, even though the containers seem to work fine, might be related to having multiple active containers 


**NOTE**: it is not ok to call GT the contents of docker-services.json, since once the thesis project will evolve we will start from an empty file


# WHAT-TO-DO AFTER 10/07/2025 MEETING
- Benchmark with accuracy, precision, recall, f1-score, input/output tokens and costs the results of the 3 web search modes (use 100 CVEs, extract them from VDaaS), actually need to check if query of 'custom' mode is =CVE-ID, then there is no need to perform benchmark with 'custom_no_tool'
- Expand logging
    - Create log for code
    - Create log for web search
    - Create log for conversation history
- (***DONE***) Change names to ***"get_docker_services"*** and ***"assess_docker_services"***
- Use LLM to check if generated code has the correct versions provided by the web search by expanding the **CodeGenerationResult**
- Implement MCP for Docker Desktop in another branch
- Implement MAVEN for vulnerability assessment