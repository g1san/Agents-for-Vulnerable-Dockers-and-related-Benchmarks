# TODOLIST
- ***"get_docker_services"***
    - (***DONE***) Improve it by making the LLM associate a specific tag to the **main service**, i.e., the service that is vulnerable to the CVE.
    - (***DONE***) Add **auxiliary** tag to services added just to make the main service work or to make the docker work
    - (***DONE***) Add manual retrieval of CVE data from NIST website for _custom_web_search_ because of error 502
    - Add manual retrieval of CVE data from Exploit DB (website or local repository)
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
    - Implement function to write final_report file into "logs" directory

- ***IMPORTANT***
    - Solve the problems related to the fact that non-vulnerable service version are reported as vulnerable (e.g. CVE-2021-28164)
    - Launching the docker of CVE-2024-23897 requires root privileges to perform certain commands, might want to check security


**NOTE**: it is not ok to call GT the contents of docker-services.json, since once the thesis project will evolve we will start from an empty file