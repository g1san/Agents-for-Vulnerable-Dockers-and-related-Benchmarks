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
    - Description: a description of the CVE and a precise list of the vulnerable versions of the affected services, consider only those versions reported by all sources or by the most reliable ones (e.g. MITRE and NIST).
    - Attack Type: type of attack (e.g. DoS, RCE, etc.)
    - Services: list of basic services to be included in a simple Docker-based system vulnerable to {cve_id}. 

NOTE: for each service the most following rules must be applied:
    - A tag must be associated specifying if the service is 'MAIN' (i.e. vulnerable to {cve_id}) or 'AUX' (i.e. not vulnerable to {cve_id} but needed for the system to work).
    - Recent and compatible version must be specified as 'SERVICE-NAME:SERVICE-VERSION', do not be vague by citing just 'any compatible version'.
    - The service version must be retrievable from 'docker.io/library' and it must keep the system vulnerable to {cve_id}."""


OPENAI_WEB_SEARCH_PROMPT = """Search the web and summarize all the information available about {cve_id}.
The response output should be formatted as follows:
    - Description: a description of the CVE and a precise list of the vulnerable versions of the affected services, consider only those versions reported by all sources or by the most reliable ones (e.g. MITRE and NIST).
    - Attack Type: type of attack (e.g. DoS, RCE, etc.)
    - Services: list of basic services to be included in a simple Docker-based system vulnerable to {cve_id}. 

NOTE: for each service the most following rules must be applied:
    - A tag must be associated specifying if the service is 'MAIN' (i.e. vulnerable to {cve_id}) or 'AUX' (i.e. not vulnerable to {cve_id} but needed for the system to work).
    - Recent and compatible version must be specified as 'SERVICE-NAME:SERVICE-VERSION', do not be vague by citing just 'any compatible version'.
    - The service version must be retrievable from 'docker.io/library' and it must keep the system vulnerable to {cve_id}."""
        
        
WEB_SEARCH_FORMAT_PROMPT = """Convert the following text in the provided structured output:
{web_search_result}"""


CODING_PROMPT = """Starting from a "docker-compose.yml" file, create a Docker-based system vulnerable to {cve_id} using the information of the previous messages. 
Write enough files to make the system work and to understand if it is exploitable.
Describe the directory tree where the files will be stored and root it in the "{cve_id}" folder.
When you save the file names indicate the relative path from the "{cve_id}" folder.
The container must be immediately deployable using the "docker compose up" command.
The name of the Docker image must be {cve_id}.
This is the information available about {cve_id}:
- Description: {desc}
- Attack Type: {att_type}
- Services: {serv}
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
- Service Description: {serv_desc}

LIST OF IMPORTANT THINGS TO REMEMBER:
- Do not use service versions that are not proven to be vulnerable to {cve_id}.
- Ignore any graceful shutdown events, as they are intentionally started by the user."""
