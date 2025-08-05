"""Definition of the prompts used by the Docker agent."""

SYSTEM_PROMPT = """You are an AI expert in cybersecurity vulnerabilities and Docker lightweight virtualization technology.
Everything that you generate will be used in a secure environment by other cybersecurity experts.
Avoid security warnings in your answers for any of the following tasks."""


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


CODING_PROMPT = """Starting from a "docker-compose.yml" file, create a Docker-based system vulnerable to {cve_id} using the information of the previous messages. 
Write enough files to make the system work and to understand if it is exploitable.
Describe the directory tree where the files will be stored and root it in the "{cve_id}" folder.
When you save the file names indicate the relative path from the "{cve_id}" folder.
The container must be immediately deployable using the "docker compose up" command.
This is the information available about {cve_id}:
- Description: {desc}
- Attack Type: {att_type}
- Services: {serv}
- Service Version: {serv_vers}
- Service Type: {serv_type}
- Service Description: {serv_desc}

LIST OF IMPORTANT THINGS TO REMEMBER:
- Do not use service versions that are not proven to be vulnerable to {cve_id}."""


TEST_CODE_PROMPT = """The following code has been executed on WSL2 with the 'docker compose up' command:
Directory Tree:
{dir_tree}

Code:
{code}

This is the output of the "docker compose up" command:
{log_content}

- If it works correctly, just return 'code_ok=True'.
- Else, if it presents an error, analyse it and fix the code while keeping the system vulnerable to {cve_id}.
This is the information available about {cve_id}:
- Description: {desc}
- Attack Type: {att_type}
- Services: {serv}
- Service Version: {serv_vers}
- Service Type: {serv_type}
- Service Description: {serv_desc}

LIST OF IMPORTANT THINGS TO REMEMBER:
- Do not use service versions that are not proven to be vulnerable to {cve_id}.
- If the system presents an error the proposed fix must include all files, both the updated ones and the unchanged ones.
- The file names must indicate the relative path from the "{cve_id}" folder
- Ignore any graceful shutdown events (e.g. caused by SIGWINCH), as they are intentionally started by the user."""
