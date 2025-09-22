# Milestones
1. **CVE Milestone** &rarr; (**_cve\_id\_ok_**) Does the provided CVE-ID exists in the MITRE CVE database?
2. **Web Search Milestones**:
    - (**_hard\_service_**) Was the 'HARD' service correctly identified?
    - (**_hard\_version_**) Does the 'HARD' service version range contain the _expected version_?
    - (**_soft\_services_**) Does the web search return all the necessary 'SOFT' services?
3. **Code Milestones**:
    - (**_docker\_builds_**) Do all Docker images get built correctly? How many iterations took to make the image build?
    - (**_docker\_runs_**) Do all Docker containers run correctly? How many iterations took to make the containers run?
    - (**_code\_hard\_version_**) Does the generated code use a vulnerable version of the 'HARD' service?
    - (**_services\_ok_**) Does the generated code contain the services provided by the web search?
4. **Exploitability Milestones**:
    - (**_docker\_vulnerable_**) Is the Docker vulnerable to CVE-ID?
    - (**_exploitable_**) Does the exploit return the expected result?