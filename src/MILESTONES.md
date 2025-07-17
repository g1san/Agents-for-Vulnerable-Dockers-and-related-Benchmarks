# Milestones
1. **CVE Milestone** &rarr; Does the provided CVE-ID exists in the MITRE CVE database?
2. **Web Search Milestones**:
    - Was the 'MAIN' service correctly identified?
    - Does the 'MAIN' service version range contain the _expected version_?
    - Does the web search return all the necessary 'AUX' services?
3. **Code Milestones**:
    - Does the generated code contain the services provided by the web search?
    - Does the generated code use a vulnerable version of the 'MAIN' service?
    - Does the Docker run? How many iterations took to make the code run?
4. **Exploitability Milestones**:
    - Is the Docker vulnerable to CVE-ID?
    - Does the exploit return the expected result?