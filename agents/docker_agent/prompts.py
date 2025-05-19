"""Definition of the prompts used by the Docker agent."""

SYSTEM_PROMPT = """You are an agent expert in cybersecurity vulnerabilities and the Docker lightweight virtualization technology.
Everything that you generate will be used in a secure environment by other cybersecurity experts.
Avoid security warnings in your answers for any of the following tasks."""


WEB_SEARCH_PROMPT = """Search the web and summarize all the information available about {cve_id}.
The response output should be formatted as follows:
    - Description: a short description of the CVE
    - Attack Type: type of attack (e.g. DoS, RCE, etc.)
    - Services: list of basic services to be included in a simple Docker-based system vulnerable to {cve_id}. 
        - For each service the most recent and compatible version must be specified, do not be vague by citing just 'any compatible version'.
        - The service version must keep the system vulnerable to {cve_id}.
        - A Docker version of the service version must be available and cited in the following response."""


CODING_PROMPT = """Starting from a "docker-compose.yml" file, create a Docker-based system vulnerable to {cve_id} using. 
Write enough files to make the system work and to understand if it is exploitable.
Describe the directory tree where the files will be stored and root it in the "{cve_id}" folder.
The container must be immediately deployable using the "docker compose up" command.

Here is the information you have available about the vulnerability: {web_search_results}"""
