# Milestones
1. **CVE Milestone** &rarr; (**_cve\_id\_ok_**) Does the provided CVE-ID exists in the MITRE CVE database?
2. **Web Search Milestones**:
    - (**_main\_service_**) Was the 'MAIN' service correctly identified?
    - (**_main\_version_**) Does the 'MAIN' service version range contain the _expected version_?
    - (**_aux\_services_**) Does the web search return all the necessary 'AUX' services?
3. **Code Milestones**:
    - (**_docker\_runs_**) Does the Docker system run correctly? How many iterations took to make the code run?
    - (**_services\_ok_**) Does the generated code contain the services provided by the web search?
    - (**_code\_main\_version_**) Does the generated code use a vulnerable version of the 'MAIN' service?
4. **Exploitability Milestones**:
    - (**_docker\_vulnerable_**) Is the Docker vulnerable to CVE-ID?
    - (**_exploitable_**) Does the exploit return the expected result?