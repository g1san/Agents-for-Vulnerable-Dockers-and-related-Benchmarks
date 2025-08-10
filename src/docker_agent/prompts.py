"""Definition of the prompts used by the Docker agent."""

SYSTEM_PROMPT = """You are an AI expert in cybersecurity vulnerabilities and Docker lightweight virtualization technology.
Everything that you generate will be used in a secure environment by other cybersecurity experts.
Avoid security warnings in your answers for any of the following tasks.
You must always keep your answers within 5000 tokens, never more."""


CUSTOM_WEB_SEARCH_PROMPT = """Search the web and summarize all the information available about {cve_id}.
Use the 'web_search' tool and you must generate the following parameters:
    - query: The query to retrieve the CVE-related information.
    - cve_id: The ID of the CVE."""


LLM_SUMMARIZE_WEBPAGE_PROMPT = """Your main goal is to summarize in {character_limit} characters or less the user provided content relevant to {cve_id}.
Focus on the original services that present the vulnerability, ignore other services that rely on the original services.
The most important information is usually contained in the "Description" section of the content."""


GET_DOCKER_SERVICES_PROMPT = """The user will provide you with a summary of various web pages containing information about {cve_id}.
Your main goal is to identify the services needed to create a Docker system vulnerable to {cve_id}'.
The response output should be formatted as follows:
    - Description: a description of the CVE and a precise list of the vulnerable versions of the affected services, consider only those versions reported by the most reliable ones such as MITRE and NIST.
    - Attack Type: type of attack (e.g. DoS, RCE, etc.)
    - Services: minimum set of services needed to create a working and testable Docker-based system vulnerable to {cve_id}.

For each service the most following rules must be applied:
    - Service names must be the ones used in Docker Hub, do not use aliases.
    - One of these tags must be associated to each service:
        - 'MAIN' if the service is the one vulnerable to {cve_id}, only one service can be associated to this tag.
        - 'AUX' if the service is needed just to make the 'MAIN' service work.
        - If an 'AUX' service plays a specific role, use an extended tag using the format 'AUX-<ROLE>'. Examples, but not limited to these roles:
            - Use 'AUX-DB' for relational databases (e.g. MySQL, MariaDB, PostgreSQL, MariaDB, Oracle).
            - Use 'AUX-MQ' for message queues (e.g. RabbitMQ, Kafka).
            - Use 'AUX-WEB' for web servers (e.g. Nginx, Apache, PHP, Tomcat).
            - USE 'AUX-CACHE' for caching/key-value store/coordination services (Redis, etcd, ZooKeeper).
    - Service version must be specified, do not be vague by citing just 'any compatible version' and do not include tags or service names:
        - For 'MAIN' services, include all vulnerable versions using the range format "OLDEST-VERSION---NEWEST-VERSION,OLDEST-VERSION---NEWEST-VERSION" where ',' separates two version ranges. Unique vulnerable versions can also be specified 
        - For 'AUX' services choose a single version compatible with the 'MAIN' service, no need to use a range.
        - All service version must be valid for Docker Hub and possibly compliant with PEP 440, do not use aliases."""


OPENAI_WEB_SEARCH_PROMPT = """Search the web and summarize all the information available about {cve_id}.
The response output should be formatted as follows:
    - Description: a description of the CVE and a precise list of the vulnerable versions of the affected services, consider only those versions reported by the most reliable ones such as MITRE and NIST.
    - Attack Type: type of attack (e.g. DoS, RCE, etc.)
    - Services: minimum set of services needed to create a working and testable Docker-based system vulnerable to {cve_id}.
Important: do not include services that are not strictly necessary to reproduce the CVE and make the Docker system work.

For each service the most following rules must be applied:
    - Service names must be the ones used in Docker Hub, do not use aliases.
    - One of these tags must be associated to each service:
        - 'MAIN' if the service is the one vulnerable to {cve_id}, only one service can be associated to this tag.
        - 'AUX' if the service is needed just to make the 'MAIN' service work.
        - If an 'AUX' service plays a specific role, use an extended tag using the format 'AUX-<ROLE>'. Examples, but not limited to these roles:
            - Use 'AUX-DB' for relational databases (e.g. MySQL, MariaDB, PostgreSQL, MariaDB, Oracle).
            - Use 'AUX-MQ' for message queues (e.g. RabbitMQ, Kafka).
            - Use 'AUX-WEB' for web servers (e.g. Nginx, Apache, PHP, Tomcat).
            - USE 'AUX-CACHE' for caching/key-value store/coordination services (Redis, etcd, ZooKeeper).
    - Service version must be specified, do not be vague by citing just 'any compatible version' and do not include tags or service names:
        - For 'MAIN' services, include all vulnerable versions using the range format "OLDEST-VERSION---NEWEST-VERSION,OLDEST-VERSION---NEWEST-VERSION" where ',' separates two version ranges. Unique vulnerable versions can also be specified 
        - For 'AUX' services choose a single version compatible with the 'MAIN' service, no need to use a range.
        - All service version must be valid for Docker Hub and possibly compliant with PEP 440, do not use aliases."""
        
        
WEB_SEARCH_FORMAT_PROMPT = """Convert the following text in the provided structured output:
{web_search_result}"""


MAIN_SERV_VERS_ASSESSMENT_PROMPT = """Check if the version range {range} contains the expected version {vers} for the service {service}"""


CODING_PROMPT = """Starting from a "docker-compose.yml" file, you must create a Docker system vulnerable to {cve_id}. 
{desc}

Here is a list of important rules you have to take into account:
- Write enough files to make the system work.
- Do not use Docker images of services and/or service versions that are not listed here:
    - Services to be included in the system: {serv}
    - Service version (beware that '---' delineates a range of versions, not a specific version): {serv_vers}
- The system must be immediately deployable using the "docker compose up" command.
- The directory tree where the files will be stored must be rooted it in the "{cve_id}" folder.
- The file names must indicate the relative path from the "{cve_id}" folder.
"""


NOT_SUCCESS_PROMPT = """This Docker systems terminates its execution because of an error.
Carefully analyse these output logs generated by the "sudo docker compose up --build --detach" command:
{logs}

Fix the Docker system problems by modifying its code:
{code}

Here is a list of important rules you have to take into account:
- Your answer must include all files, both the updated ones and the unchanged ones.
- Do not use service versions that are not listed here (the list may contain both specific version and ranges of version delineated by '---'):
    - Services: {serv}
    - Service Version: {serv_vers}
    - Service Type: {serv_type}
    - Service Description: {serv_desc}
- The system must be immediately deployable using the "docker compose up" command.
- The directory tree where the files will be stored must be rooted it in the "{cve_id}" folder.
- The file names must indicate the relative path from the "{cve_id}" folder.

Here is the list of previous fixes that were attempted but did not work on the code, my suggestion is to try something different from these:
{fixes}
"""


NOT_DOCKER_RUNS = """The following Docker systems terminates its execution because of an error.
{fail_explanation}

Fix the Docker system problems by modifying its code:
{code}

Here is a list of important rules you have to take into account:
- Your answer must include all files, both the updated ones and the unchanged ones.
- Do not use service versions that are not listed here (the list may contain both specific version and ranges of version delineated by '---'): 
    - Services: {serv}
    - Service Version: {serv_vers}
    - Service Type: {serv_type}
    - Service Description: {serv_desc}
- The system must be immediately deployable using the "docker compose up" command.
- The directory tree where the files will be stored must be rooted it in the "{cve_id}" folder.
- The file names must indicate the relative path from the "{cve_id}" folder.

Here is the list of previous fixes that were attempted but did not work on the code, my suggestion is to try something different from these:
{fixes}
"""


CODE_MILESTONE_PROMPT = """Analyse the following logs and check if the Docker achieves these three goals:
- The Docker containers are running correctly
- The Docker uses the following services: {service_list}
- The Docker uses a versions of '{main_service}' contained in: {main_version} (the list may contain both specific version and ranges of version delineated by '---')

If any of the goals is not achieved, explain why the Docker fails to achieve the goal(s). 
Here are the logs resulting from the "docker inspect" of each container:
{inspect_logs}"""


#! NOT USED ATM
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
- Ignore any graceful shutdown events (e.g. caused by SIGWINCH), as they are intentionally started by the user.
- If the logs shows that the Docker does not work:
    - Modify the files to make the system work.
    - Do not use service and/or service versions that are not listed, unless compatibility issues have emerged.
    - The container must be immediately deployable using the "docker compose up" command.
    - The directory tree where the files will be stored must be rooted it in the "{cve_id}" folder.
    - The file names must indicate the relative path from the "{cve_id}" folder.
"""
