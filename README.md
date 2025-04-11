# Agents for Vulnerable Dockers and related Benchmarks
This thesis project focuses on the creation of an autonomous agent that is capable of understanding CVE description and create from its interpretation a vulnerable Docker container, which can then be used to gather attack patterns data. The Docker creation process is benchmarked in order to understand how well the agent is performing its tasks.


## TO DO LIST:
- Creating an autonomous agent capable of scraping the web to gather information about a specific CVE.
- Creating another autonomous agent that (through a multi-agent framework) is fetched with the characteristics of the CVE and creates a vulnerable Docker container.
- Creating another autonomous capable of searching for the correct exploit (e.g. from https://www.exploit-db.com/) in order to test the container.


## Detailed Exploit Status Table

Table of all the exploits that have been scripted in order to work with the related CVE

| CVE ID      | Type of Attack                  | Exploit Title                                      |Replication Feasibility     
|-------------|---------------------------------|----------------------------------------------------|-----------------------
| 2012-1823   | Remote Code Execution (RCE)     | PHP CGI Argument Injection RCE                     | **REPLICABLE** &rarr; requires: _docker-compose, php:5.4.1-cgi (Dockerfile (php:5.4.1 (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + apache2-foreground)_ and (1/2?) _.php_ files
| 2016-5734   | Remote Code Execution (RCE)     | DokuWiki Remote Code Execution                     | **REPLICABLE** &rarr; requires: _docker-compose, phpmyadmin:4.4.15.6 (Dockerfile (php:5.3-apache (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + config.inc.php)_ and _mysql:5.5_ (downloaded or local?)
| 2016-199433 | Remote Code Execution (RCE)     | Discuz! Remote Code Execution                      | **REPLICABLE** &rarr;
| 2018-12613  | Remote File Inclusion (RFI)     | phpMyAdmin Remote File Inclusion                   | **REPLICABLE** &rarr;
| 2020-11651  | Remote Code Execution (RCE)     | Saltstack 3000.1 - Remote Code Execution           | **REPLICABLE** &rarr;
| 2020-11652  | Remote Code Execution (RCE)     | Saltstack 3000.1 - Remote Code Execution           | **REPLICABLE** &rarr;
| 2020-14882  | Remote Code Execution (RCE)     | Oracle WebLogic Server RCE                         | **NOT REPLICABLE** &rarr; requires: explicit login to Oracle in order to download Docker image
| 2020-17519  | File Read/Inclusion             | Apache Flink - Unauthenticated Arbitrary File Read | **REPLICABLE** &rarr;
| 2020-7247   | Remote Code Execution (RCE)     | OpenSMTPD - Remote Code Execution                  | **REPLICABLE** &rarr;
| 2021-22205  | Remote Code Execution (RCE)     | GitLab RCE                                         | **REPLICABLE** &rarr;
| 2021-28164  | Information Disclosure          | Jetty Information Disclosure                       | **REPLICABLE** &rarr;
| 2021-34429  | Sensitive File Disclosure       | Eclipse Jetty Sensitive File Disclosure            | **REPLICABLE** &rarr;
| 2021-41773  | Remote Code Execution (RCE)     | Apache HTTP Server RCE                             | **REPLICABLE** &rarr;
| 2021-42013  | Remote Code Execution (RCE)     | Apache HTTP Server RCE                             | **REPLICABLE** &rarr;
| 2021-43798  | Directory Traversal & File Read | Grafana Directory Traversal                        | **REPLICABLE** &rarr;
| 2021-44228  | Information Disclosure / RCE    | Apache Log4j Information Disclosure / RCE          | **REPLICABLE** &rarr;
| 2022-22947  | Remote Code Execution (RCE)     | Spring Cloud Gateway RCE                           | **REPLICABLE** &rarr;
| 2022-22963  | Remote Code Execution (RCE)     | Spring Cloud RCE                                   | **REPLICABLE** &rarr;
| 2022-24706  | Remote Code Execution (RCE)     | Apache CouchDB RCE                                 | **REPLICABLE** &rarr;
| 2023-23752  | Remote Command Execution (RCE)  | Cacti RCE                                          | **REPLICABLE** &rarr;
| 2024-23897  | Local File Inclusion            | Jenkins Local File Inclusion                       | **REPLICABLE** &rarr;