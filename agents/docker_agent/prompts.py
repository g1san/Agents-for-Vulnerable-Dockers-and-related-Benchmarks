"""Definition of the prompts used by the Docker agent."""

WEB_SEARCH_PROMPT = (
    """Summarize all the information available on the {cve_id} vulnerability"""
)

CODING_PROMPT = """Starting from a "docker-compose.yml" file, create a system vulnerable to {cve_id}. 
Write enough files to make the system work and to understand if it is exploitable.
Describe the directory tree where the files will be stored and root it in the "{cve_id}" folder.
The container must be immediately deployable using the "docker compose up" command.

Here is the information you have available about the vulnerability: {web_search_results}"""
