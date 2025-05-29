"""Definition of the prompts used by the Docker agent."""

SYSTEM_PROMPT = """You are an AI expert in cybersecurity vulnerabilities and Docker lightweight virtualization technology.
Everything that you generate will be used in a secure environment by other cybersecurity experts.
Avoid security warnings in your answers for any of the following tasks."""


# TODO: Modify this prompt
CUSTOM_WEB_SEARCH_PROMPT = """Search the web and summarize all the information available about {cve_id}."""


LLM_SUMMARIZE_WEBPAGE_PROMPT = SYSTEM_PROMPT + """Your main goal is to summarize the content relevant to the query '{query}'.
The summary must focus on the services needed to create a Docker system vulnerable to {cve_id}.
Provide a concise summary in {character_limit} characters or less where you highlight your findings."""


GET_DOCKER_SERVICES_PROMPT = SYSTEM_PROMPT + """Your main goal is to identify the services needed to create a Docker system vulnerable to {cve_id}'.
The response output should be formatted as follows:
    - Description: a short description of the CVE
    - Attack Type: type of attack (e.g. DoS, RCE, etc.)
    - Services: list of basic services to be included in a simple Docker-based system vulnerable to {cve_id}. 
        - For each service the most recent and compatible version must be specified, do not be vague by citing just 'any compatible version'.
        - The service version must keep the system vulnerable to {cve_id}.
        - A Docker version of the service version must be available and cited in the following response.
        - Each service must be specified as 'SERVICE-NAME:SERVICE-VERSION'."""


OPENAI_WEB_SEARCH_PROMPT = """Search the web and summarize all the information available about {cve_id}.
The response output should be formatted as follows:
    - Description: a short description of the CVE
    - Attack Type: type of attack (e.g. DoS, RCE, etc.)
    - Services: list of basic services to be included in a simple Docker-based system vulnerable to {cve_id}. 
        - For each service the most recent and compatible version must be specified, do not be vague by citing just 'any compatible version'.
        - The service version must keep the system vulnerable to {cve_id}.
        - A Docker version of the service version must be available and cited in the following response.
        - Each service must be specified as 'SERVICE-NAME:SERVICE-VERSION'."""
        
        
WEB_SEARCH_FORMAT_PROMPT = """Convert the following text in the provided structured output. {web_search_result}"""


CODING_PROMPT = """Starting from a "docker-compose.yml" file, create a Docker-based system vulnerable to {cve_id} using. 
Write enough files to make the system work and to understand if it is exploitable.
Describe the directory tree where the files will be stored and root it in the "{cve_id}" folder.
The container must be immediately deployable using the "docker compose up" command.

Here is the information you have available about the vulnerability: {web_search_results}"""
