# Milestones
1. **CVE Milestone** &rarr; (**_cve\_id\_exists_**) Does the provided CVE-ID exists in the MITRE CVE database?
2. **Web Search Milestones**:
    - (**_main\_service\_identified_**) Was the 'MAIN' service correctly identified?
    - (**_main\_service\_version_**) Does the 'MAIN' service version range contain the _expected version_?
    - (**_aux\_roles\_ok_**) Does the web search return all the necessary 'AUX' services?
3. **Code Milestones**:
    - (**_services\_implemented\_in\_code_**) Does the generated code contain the services provided by the web search?
    - (**_main\_service\_uses\_vulnerable\_version_**) Does the generated code use a vulnerable version of the 'MAIN' service?
    - (**_docker\_runs_**) Does the Docker run? How many iterations took to make the code run?
4. **Exploitability Milestones**:
    - (**_docker\_vulnerable\_to\_cve_**) Is the Docker vulnerable to CVE-ID?
    - (**_exploit\_returns\_expected\_result_**) Does the exploit return the expected result?