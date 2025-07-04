# TODOLIST
- ***"get_docker_services"***
    - (***DONE***) Improve it by making the LLM associate a specific tag to the **main service**, i.e., the service that is vulnerable to the CVE.
    - (***DONE***) Add **auxiliary** tag to services added just to make the main service work or to make the docker work
    - (***DONE***) Add manual retrieval of CVE data from NIST website for _custom_web_search_ because of error 502
    - Check if order of URL provided by Google API is the same every time
    - Benchmark how many URLs does the LLM need to check for a given CVE to get the GT services, do it just for one CVE, it is a useful result for the thesis
- ***"assess_docker_services"***
    - (***DONE***) Improve it by having the LLM check if the **main service** version is a vulnerable one
    - (***DONE***) If GT for CVE does not exist, save the result locally in order to improve GT database
- ***"save_code"***
    - (***DONE***) The whole node functionality needs to be assessed
    - (***DONE***) Implemented only partially, *keep coding*
    - Evaluate if the code fixes should be applied here or in ***generate_docker_code***
- ***"test_docker_code"***
    - (***DONE***) Make it work with WSL
    - (***DONE***) Generate commands needed to launch and dispose of Docker
    - (***DONE***) Retrieve and report back eventual errors from the terminal
    - (***DONE***) Evaluate the errors and provide feedback to ***generate_docker_code***
    - Assess if it works correctly using the Dockers from VDaaS
    - Evaluate the need of a "scratchpad" from which the LLM can understand which parts of the docker did not work


**NOTE**: it is not ok to call GT the contents of docker-services.json, since once the thesis project will evolve we will start from an empty file