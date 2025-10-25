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

GOAL: identify the services needed to create a Docker system vulnerable to {cve_id}

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
    - 'SOFT' service that play a specific role must be associated to a role (format 'SOFT-<role>'). Examples of 'SOFT-<role>' are:
        - 'SOFT-DB' for relational databases (e.g., MySQL, MariaDB, PostgreSQL, MariaDB, Oracle)
        - 'SOFT-MQ' for message queues (e.g., RabbitMQ, Kafka)
        - 'SOFT-WEB' for web servers (e.g., Nginx, Apache, PHP, Tomcat)
        - 'SOFT-CACHE' for caching/key-value store/coordination services (e.g., Redis, etcd, ZooKeeper)
- ABOUT SERVICE VERSIONS:
    - Service version must specified and valid for Docker Hub, do not be vague by citing just 'any compatible version'
    - For 'HARD' services you must list all vulnerable versions cited by the most reliable sources such as MITRE and NIST. Do not use ranges, you must be very specific with version name and list all versions vulnerable to {cve_id}
    - For 'SOFT' services choose a versions compatible with the 'HARD' services
"""


OPENAI_WEB_SEARCH_PROMPT = """CONTEXT: search the web and summarize all the information available about {cve_id}

GOAL: identify the services needed to create a Docker system vulnerable to {cve_id}

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
    - 'SOFT' service that play a specific role must be associated to a role (format 'SOFT-<role>'). Examples of 'SOFT-<role>' are:
        - 'SOFT-DB' for relational databases (e.g., MySQL, MariaDB, PostgreSQL, MariaDB, Oracle)
        - 'SOFT-MQ' for message queues (e.g., RabbitMQ, Kafka)
        - 'SOFT-WEB' for web servers (e.g., Nginx, Apache, PHP, Tomcat)
        - 'SOFT-CACHE' for caching/key-value store/coordination services (e.g., Redis, etcd, ZooKeeper)
- ABOUT SERVICE VERSIONS:
    - Service version must specified and valid for Docker Hub, do not be vague by citing just 'any compatible version'
    - For 'HARD' services you must list all vulnerable versions cited by the most reliable sources such as MITRE and NIST. Do not use ranges, you must be very specific with version name and list all versions vulnerable to {cve_id}
    - For 'SOFT' services choose a versions compatible with the 'HARD' services
"""
        
        
WEB_SEARCH_FORMAT_PROMPT = """GOAL: convert the following text in the provided structured output
{web_search_result}"""


HARD_SERV_VERS_ASSESSMENT_PROMPT = """GOAL: check if version '{version}' of the '{service}' service is contained in the following list of versions
{version_list}

CONTEXT: the version lists of each service may contain multiple entries separated by ','
"""


CODING_PROMPT = """GOAL: starting from a "docker-compose.yml" file, you must create a Docker system vulnerable to {cve_id}.

GUIDELINES:
- Use the data that you provided in the message about {cve_id} and its services to build the Docker
    - You must use all and only the services that are listed in the message that describes {cve_id}
    - If a service requires a dedicated container write the code for it
    - You must not use versions of 'HARD' services that are not listed in the message about {cve_id} and its services
- If a DB is needed, it must be properly setup and populated with some test data
- The system must be immediately deployable using the "docker compose up" command
- Ensure that no service has to be setup manually by the user
- All services and related containers must be properly configured on order to be immediately accessible from the service's default network ports
- Always write enough files to make the all services work and to ensure that {cve_id} is exploitable for testing purposes
- All file names must indicate the file path which must start with "./../../dockers/{cve_id}/{mode}"
- There is no need to specify the file name in the file content
"""


CHECK_CONTAINER_PROMPT = """GOAL: check the following outputs and tell me if it the Docker container is running correctly ('container_ok' milestone)

- Output of the 'sudo docker logs [CONTAINER ID] --details' command:
{container_log}

- Output of the 'sudo docker inspect [CONTAINED-ID]' command:
{inspect_container_log}
"""


CHECK_SERVICES_VERSIONS_PROMPT = """GOALS: analyse the output of the command 'sudo docker inspect [IMAGE-ID]' and the Docker's code (all contained in the previous messages) to assert if
- the following services are using one of the versions listed to their side ('code_hard_version' milestone):{hard_service_versions}
- the Docker uses the following services: {service_list} ('services_ok' milestone)

CONTEXT: the version lists of each service may contain multiple entries separated by ','

GUIDELINES: if any of the milestones is not achieved, you must explain why the Docker fails to achieve them and set to false the corresponding flag
"""


CHECK_NETWORK_PROMPT = """GOALS: analyse the output of the command 'sudo docker inspect [CONTAINED-ID]' and the Docker's code (all contained in the previous messages) to assert if all services are using their default network port ('network_setup' milestone)

GUIDELINES: if the milestones is not achieved, you must explain why the Docker fails to achieve them and set to false the corresponding flag
"""


TEST_FAIL_PROMPT = """CONTEXT: {fail_explanation}

GOALS: {revision_goal}.

GUIDELINES:
- Any DB must are properly setup and populated with some test data
- The system must be immediately deployable using the "docker compose up" command
- Ensure that no service has to be setup manually by the user
- All services and related containers must be properly configured on order to be immediately accessible from the service's default network ports
- Your answer must include all files (updated ones, unchanged ones and new ones)
- All file names must indicate the file path which must start with "./../../dockers/{cve_id}/{mode}"
- There is no need to specify the file name in the file content
- The Docker code was generated using the data in the message about {cve_id} and its services
    - You must use all and only the services that are listed in the message that describes {cve_id}
    - If a service requires a dedicated container write the code for it
    - You must not use versions of 'HARD' services that are not listed in the message about {cve_id} and its services
- Here is the list of previous fixes that you attempted but did not work, my suggestion is to try something different from these:
{fixes}
"""


REVISION_PROMPT = """CONTEXT: {fail_explanation}

GOALS: explain how you would fix this problem by modifying the code in a few sentences, do not use bullet points.
"""


CODE_CORRECTION_PROMPT = """CONTEXT: {fail_explanation}

GOALS: {revision_goal}. {fix}.

GUIDELINES:
- Any DB must are properly setup and populated with some test data
- The system must be immediately deployable using the "docker compose up" command
- Ensure that no service has to be setup manually by the user
- All services and related containers must be properly configured on order to be immediately accessible from the service's default network ports
- Your answer must include all files (updated ones, unchanged ones and new ones)
- All file names must indicate the file path which must start with "./../../dockers/{cve_id}/{mode}"
- There is no need to specify the file name in the file content
- The Docker code was generated using the data in the message about {cve_id} and its services
    - You must use all and only the services that are listed in the message that describes {cve_id}
    - If a service requires a dedicated container write the code for it
    - You must not use versions of 'HARD' services that are not listed in the message about {cve_id} and its services
- Here is the list of previous fixes that you attempted but did not work, my suggestion is to try something different from these:
{fixes}
"""
