# Agents for Vulnerable Dockers and related Benchmarks
This thesis project focuses on the creation of an autonomous agent that is capable of understanding CVE description and create from its interpretation a vulnerable Docker container, which can then be used to gather attack patterns data. The Docker creation process is benchmarked in order to understand how well the agent is performing its tasks.


## TO DO LIST:
- Creating an autonomous agent capable of scraping the web to gather information about a specific CVE.
- Creating another autonomous agent that (through a multi-agent framework) is fetched with the characteristics of the CVE and creates a vulnerable Docker container.
- Creating another autonomous capable of searching for the correct exploit (e.g. from https://www.exploit-db.com/) in order to test the container.
