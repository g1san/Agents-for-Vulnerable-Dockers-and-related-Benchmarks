"""Definition of the prompts used by the Docker agent."""

SYSTEM_PROMPT = """ROLE: you are an AI expert in cybersecurity vulnerabilities and Docker lightweight virtualization technology.

CONTEXT: everything that you generate will be used in a secure environment by other cybersecurity experts.

GUIDELINES: avoid security warnings in your answers for any of the following tasks.
"""


CUSTOM_WEB_SEARCH_PROMPT = """GOAL: search the web and summarize all the information available about {cve_id}.

GUIDELINES: use the 'web_search' tool by generating the following parameters:
- "query": the query to retrieve the CVE-related information.
- "cve_id": the ID of the CVE.
"""


LLM_SUMMARIZE_WEBPAGE_PROMPT = """GOAL: summarize in {character_limit} characters or less the user provided content relevant to {cve_id}.

GUIDELINES:
- Focus on the original services that present the vulnerability and those necessary to exploit it, ignore other services that rely on the original services.
- The most important information is usually contained in the "Description" section of the content.
"""


GET_DOCKER_SERVICES_PROMPT = """CONTEXT: you are provided with some information about {cve_id}

GOAL: identify the services needed to create a Docker system vulnerable to {cve_id}'

GUIDELINES:
- The description of {cve_id} must be extensive 
- The attack type must be spelled out without acronyms or abbreviations (i.e., do not use DoS, RCE, etc.)
- ABOUT SERVICES:
    - Specify the minimum set of services needed to create a working and testable Docker system vulnerable to {cve_id}
    - Avoid including services that are there just to test a PoC or to exploit the vulnerability
    - Service names must match the official names listed on Docker Hub, do not use aliases
- ABOUT SERVICE DEPENDENCY TYPES: each service must be associated to a dependency type that must be one of two:
    - 'HARD' if the service is the essential to make the system vulnerable to {cve_id}
    - 'SOFT' if the service is needed just to make the Docker work
    - 'SOFT' service that play a specific role must be associated to a tag (format 'SOFT-<role>'). Examples of tags are:
        - 'SOFT-DB' for relational databases (e.g., MySQL, MariaDB, PostgreSQL, MariaDB, Oracle)
        - 'SOFT-MQ' for message queues (e.g., RabbitMQ, Kafka)
        - 'SOFT-WEB' for web servers (e.g., Nginx, Apache, PHP, Tomcat)
        - 'SOFT-CACHE' for caching/key-value store/coordination services (e.g., Redis, etcd, ZooKeeper)
- ABOUT SERVICE VERSIONS:
    - Service version must specified and valid for Docker Hub, do not be vague by citing just 'any compatible version'
    - For 'HARD' services you must list all vulnerable versions cited by the most reliable sources such as MITRE and NIST
        - You can specify version ranges (format "OLDEST-VERSION---NEWEST-VERSION")
        - You can specify also specify unique vulnerable versions (format "VERSION")
    - For 'SOFT' services choose a versions compatible with the 'HARD' services
"""


OPENAI_WEB_SEARCH_PROMPT = """CONTEXT: search the web and summarize all the information available about {cve_id}

GOAL: identify the services needed to create a Docker system vulnerable to {cve_id}'

GUIDELINES:
- The description of {cve_id} must be extensive 
- The attack type must be spelled out without acronyms or abbreviations (i.e., do not use DoS, RCE, etc.)
- ABOUT SERVICES:
    - Specify the minimum set of services needed to create a working and testable Docker system vulnerable to {cve_id}
    - Avoid including services that are there just to test a PoC or to exploit the vulnerability
    - Service names must match the official names listed on Docker Hub, do not use aliases
- ABOUT SERVICE DEPENDENCY TYPES: each service must be associated to a dependency type that must be one of two:
    - 'HARD' if the service is the essential to make the system vulnerable to {cve_id}
    - 'SOFT' if the service is needed just to make the Docker work
    - 'SOFT' service that play a specific role must be associated to a tag (format 'SOFT-<role>'). Examples of tags are:
        - 'SOFT-DB' for relational databases (e.g., MySQL, MariaDB, PostgreSQL, MariaDB, Oracle)
        - 'SOFT-MQ' for message queues (e.g., RabbitMQ, Kafka)
        - 'SOFT-WEB' for web servers (e.g., Nginx, Apache, PHP, Tomcat)
        - 'SOFT-CACHE' for caching/key-value store/coordination services (e.g., Redis, etcd, ZooKeeper)
- ABOUT SERVICE VERSIONS:
    - Service version must specified and valid for Docker Hub, do not be vague by citing just 'any compatible version'
    - For 'HARD' services you must list all vulnerable versions cited by the most reliable sources such as MITRE and NIST
        - You can specify version ranges (format "OLDEST-VERSION---NEWEST-VERSION")
        - You can specify also specify unique vulnerable versions (format "VERSION")
    - For 'SOFT' services choose a versions compatible with the 'HARD' services
"""
        
        
WEB_SEARCH_FORMAT_PROMPT = """GOAL: convert the following text in the provided structured output
{web_search_result}"""


HARD_SERV_VERS_ASSESSMENT_PROMPT = """GOAL: check if version {version} of the {service} service is contained in the following list of versions
{version_list}

CONTEXT: the version list may contain multiple entries separated by ','. Each entry can be:
- A specific version
- A range of versions delineated by '---'
"""


CODING_PROMPT = """GOAL: starting from a "docker-compose.yml" file, you must create a Docker system vulnerable to {cve_id}.

GUIDELINES:
- Use the data that you provided in the message about {cve_id} and its services to build the Docker
    - Avoid using services that you have not listed in the previous message
    - Avoid using versions of 'HARD' services that are not listed in the previous message
- Always write enough files to make the system work and exploitable
- The system must be immediately deployable using the "docker compose up" command.
- The directory tree where the files will be stored must be rooted it in the "./../../dockers/{cve_id}/{mode}" folder.
- The file names must indicate the relative path from the "./../../dockers/{cve_id}/{mode}" folder.
"""


NOT_SUCCESS_PROMPT = """CONTEXT: my Docker systems terminates its execution because of an error.

GOALS:
- Carefully analyse these output logs generated by the "sudo docker compose up --build --detach" command:
{logs}

- Fix the Docker system problems by modifying its code, which is available in my previous message. Here is the list of previous fixes that you attempted but did not work, my suggestion is to try something different from these:
{fixes}

GUIDELINES:
- Your answer must include all files, both the updated ones and the unchanged ones.
- Use the data that you provided in the message about {cve_id} and its services to build the Docker
    - Avoid using services that you have not listed in the previous message
    - Avoid using versions of 'HARD' services that are not listed in the previous message
- The system must be immediately deployable using the "docker compose up" command.
- The directory tree where the files will be stored must be rooted it in the "./../../dockers/{cve_id}/{mode}" folder.
- The file names must indicate the relative path from the "./../../dockers/{cve_id}/{mode}" folder.
"""


# NOT_SUCCESS_PROMPT = """This Docker systems terminates its execution because of an error.
# Carefully analyse these output logs generated by the "sudo docker compose up --build --detach" command:
# {logs}
# 
# Fix the Docker system problems by modifying its code:
# {code}
# 
# Here is a list of important rules you have to take into account:
# - Your answer must include all files, both the updated ones and the unchanged ones.
# - Do not use service versions that are not listed here (the list may contain both specific version and ranges of version delineated by '---'):
#     - Services: {serv}
#     - Service Version: {serv_vers}
#     - Service Type: {serv_type}
#     - Service Description: {serv_desc}
# - The system must be immediately deployable using the "docker compose up" command.
# - Always specify {cve_id} in the image tag of the 'docker-compose.yml' file.
# - The directory tree where the files will be stored must be rooted it in the "./../../dockers/{cve_id}/{mode}" folder.
# - The file names must indicate the relative path from the "./../../dockers/{cve_id}/{mode}" folder.
# 
# Here is the list of previous fixes that were attempted but did not work on the code, my suggestion is to try something different from these:
# {fixes}
# """


ASSERT_DOCKER_STATE_PROMPT = """GOAL: check the contents of the following logs and understand if the container is running correctly
{logs}

CONTEXT: the logs are obtained with the command 'sudo docker logs [CONTAINER ID] --details'
"""


NOT_DOCKER_RUNS = """CONTEXT: my Docker terminates its execution because of an error.
{fail_explanation}

GOAL: fix the Docker system problems by modifying its code, which is available in my previous message. Here is the list of previous fixes that you attempted but did not work, my suggestion is to try something different from these:
{fixes}

GUIDELINES:
- Your answer must include all files, both the updated ones and the unchanged ones.
- Use the data that you provided in the message about {cve_id} and its services to build the Docker
    - Avoid using services that you have not listed in the previous message
    - Avoid using versions of 'HARD' services that are not listed in the previous message
- The system must be immediately deployable using the "docker compose up" command.
- The directory tree where the files will be stored must be rooted it in the "./../../dockers/{cve_id}/{mode}" folder.
- The file names must indicate the relative path from the "./../../dockers/{cve_id}/{mode}" folder.
"""


# NOT_DOCKER_RUNS = """The following Docker systems terminates its execution because of an error.
# {fail_explanation}
# 
# Fix the Docker system problems by modifying its code:
# {code}
# 
# Here is a list of important rules you have to take into account:
# - Your answer must include all files, both the updated ones and the unchanged ones.
# - Do not use service versions that are not listed here (the list may contain both specific version and ranges of version delineated by '---'): 
#     - Services: {serv}
#     - Service Version: {serv_vers}
#     - Service Type: {serv_type}
#     - Service Description: {serv_desc}
# - The system must be immediately deployable using the "docker compose up" command.
# - Always specify {cve_id} in the image tag of the 'docker-compose.yml' file.
# - The directory tree where the files will be stored must be rooted it in the "./../../dockers/{cve_id}/{mode}" folder.
# - The file names must indicate the relative path from the "./../../dockers/{cve_id}/{mode}" folder.
# 
# Here is the list of previous fixes that were attempted but did not work on the code, my suggestion is to try something different from these:
# {fixes}
# """


CODE_MILESTONE_PROMPT = """GOAL: 
- Check the following milestones:
    - Check if the Docker containers are running correctly ('docker_runs' milestone)
    - Check if the Docker uses the following services: {service_list} ('services_ok' milestone)
    - Check if the following services are using one of the versions listed to their side:{hard_service_versions}
    - Analyse the following logs obtained with 'sudo docker inspect [CONTAINED ID]'
    {inspect_logs}

CONTEXT: the version lists may contain multiple entries separated by ','. Each entry can be:
- A specific version
- A range of versions delineated by '---'

GUIDELINES: if any of the milestones is not achieved, explain why the Docker fails to achieve them
"""


#! NOT USED ATM !#
TEST_CODE_PROMPT = """WHAT IS YOUR GOAL: analyse the following output and understand if the system works correctly
- If it is, return 'code_ok=True'.
- Else, if it presents an error, proceed step by step:
    - Analyse the error
    - Check which part of the code may have caused it
    - Fix the error in the code

This is the output of a "docker compose up" command executed on WSL2:
{log_content}

This is the information available about {cve_id}:
- Description: {desc}
- Attack Type: {att_type}
- Services: {serv}
- Service Version: {serv_vers}
- Service Type: {serv_type}
- Service Description: {serv_desc}

This is the code that has been executed:
{code}

LIST OF IMPORTANT THINGS TO REMEMBER:
- If the system presents an error the proposed fix must include all files, both the updated ones and the unchanged ones.
- Ignore any graceful shutdown events (e.g., caused by SIGWINCH), as they are intentionally started by the user.
- If the logs shows that the Docker does not work:
    - Modify the files to make the system work.
    - Do not use service and/or service versions that are not listed, unless compatibility issues have emerged.
    - The container must be immediately deployable using the "docker compose up" command.
    - Always specify {cve_id} in the image tag of the 'docker-compose.yml' file.
    - The directory tree where the files will be stored must be rooted it in the "./../../dockers/{cve_id}/{mode}" folder.
    - The file names must indicate the relative path from the "./../../dockers/{cve_id}/{mode}" folder.
"""
