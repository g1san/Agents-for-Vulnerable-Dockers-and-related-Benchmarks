# Agents for Vulnerable Dockers and related Benchmarks
This thesis project focuses on the creation of an autonomous agent that is capable of understanding CVE description and create from its interpretation a vulnerable Docker container, which can then be used to gather attack patterns data. The Docker creation process is benchmarked in order to understand how well the agent is performing its tasks.


## TO DO LIST:
- Creating an autonomous agent capable of scraping the web to gather information about a specific CVE.
- Creating another autonomous agent that (through a multi-agent framework) is fetched with the characteristics of the CVE and creates a vulnerable Docker container.
- Creating another autonomous capable of searching for the correct exploit (e.g. from https://www.exploit-db.com/) in order to test the container.


## Detailed Exploit Status Table

Table of all the exploits that have been scripted in order to work with the related CVE

| CVE/WooYun ID      | Type of Attack                  | Exploit Title                                      | _script.sh_ |Replication Feasibility     
|--------------------|---------------------------------|----------------------------------------------------|-------------|-----------------------
| CVE-2012-1823      | Remote Code Execution (RCE)     | PHP CGI Argument Injection RCE                     |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, php:5.4.1-cgi (Dockerfile (php:5.4.1 (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + apache2-foreground)_ and (1/2?) _.php_ files
| CVE-2016-5734      | Remote Code Execution (RCE)     | DokuWiki Remote Code Execution                     |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, phpmyadmin:4.4.15.6 (Dockerfile (php:5.3-apache (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + config.inc.php)_ and _mysql:5.5_ (local/remote)
| WooYun-2016-199433 | Remote Code Execution (RCE)     | Discuz! Remote Code Execution                      |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, phpmyadmin:2.8.0.4 (Dockerfile (php:5.4.x-apache (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)))_. **NOTE**: any version _x_ of _php:5.4.x-apache_ can be used to run the vulnerable version of _phpmyadmin_
| CVE-2018-12613     | Remote File Inclusion (RFI)     | phpMyAdmin Remote File Inclusion                   |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, phpmyadmin:4.8.1 (Dockerfile (php:7.2-apache (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + config.inc.php)_ and _mysql:5.5_ (local/remote).**NOTE**: any version _php:x.x.x-apache_ can be used to run the vulnerable version of _phpmyadmin_
| CVE-2020-7247      | Remote Code Execution (RCE)     | OpenSMTPD - Remote Code Execution                  |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, opensmtpd:6.6.1p1 (Dockerfile + aliases + smtpd.conf)_
| CVE-2020-11651     | Remote Code Execution (RCE)     | Saltstack 3000.1 - Remote Code Execution           |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, saltstack:2019.2.3 (Dockerfile + saltinit.py)_
| CVE-2020-11652     | Remote Code Execution (RCE)     | Saltstack 3000.1 - Remote Code Execution           |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, saltstack:2019.2.3 (Dockerfile + saltinit.py)_
| CVE-2020-14882     | Remote Code Execution (RCE)     | Oracle WebLogic Server RCE                         |     Yes     | **NOT REPLICABLE** &rarr; requires: explicit login to Oracle in order to download Docker image
| CVE-2020-17519     | File Read/Inclusion             | Apache Flink - Unauthenticated Arbitrary File Read |   **No**    | **REPLICABLE** &rarr; requires: _docker-compose, flink:1.11.2 (Dockerfile (flink:1.11.2-java8 local/remote))_.
| CVE-2021-3129      | Remote Code Execution (RCE)     | Laravel Ignition 2.5.1                             |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, laravel:8.4.2 (Dockerfile (php:7.4-apache_ (local/remote)_))_.
| CVE-2021-22205     | Remote Code Execution (RCE)     | GitLab RCE                                         |   **No**    | **REPLICABLE** &rarr; requires: _docker-compose, gitlab:13.10.1 (Dockerfile)_.
| CVE-2021-28164     | Information Disclosure          | Jetty Information Disclosure                       |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, jetty:9.4.37 (Dockerfile)_
| CVE-2021-34429     | Sensitive File Disclosure       | Eclipse Jetty Sensitive File Disclosure            |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, jetty:9.4.40 (Dockerfile)_
| CVE-2021-41773     | Remote Code Execution (RCE)     | Apache HTTP Server RCE                             |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, apache (Dockerfile (httpd:2.4.49 (Dockerfile)))_
| CVE-2021-42013     | Remote Code Execution (RCE)     | Apache HTTP Server RCE                             |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, apache (Dockerfile (httpd:2.4.50 (Dockerfile)))_
| CVE-2021-43798     | Directory Traversal & File Read | Grafana Directory Traversal                        |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, grafana:8.2.6 (Dockerfile)_
| CVE-2021-44228     | Information Disclosure / RCE    | Apache Log4j Information Disclosure / RCE          |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, solr:8.11.0 (Dockerfile + docker-entrypoint.sh)_
| CVE-2022-22947     | Remote Code Execution (RCE)     | Spring Cloud Gateway RCE                           |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, spring-cloud-gateway:3.1.0 (Dockerfile + pom.xml + .gitignore + application.xml + SpringCloudGatewayApplication.java)_
| CVE-2022-22963     | Remote Code Execution (RCE)     | Spring Cloud RCE                                   |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, spring-cloud-function:3.2.2 (Dockerfile + pom.xml + SpringCloudApplicationFunctionSample.java)_
| CVE-2022-24706     | Remote Code Execution (RCE)     | Apache CouchDB RCE                                 |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, couchdb:3.2.1 (Dockerfile + docker-entrypoint.sh)_
| CVE-2022-46169     | Remote Command Execution (RCE)  | Cacti Unauthenticated Command Injection            |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, cacti:1.2.22 (Dockerfile (php:7.4-apache_ (local/remote)_) + cacti.ini + config.php) + entrypoint.sh_ and _mysql:5.7_ (local/remote)
| CVE-2023-23752     | Remote Command Execution (RCE)  | Cacti RCE                                          |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, joomla:4.2.7 (Dockerfile (php:7.4.33-apache_ (local/remote)_) + docker-entrypoint + .htaccess) and mysql:5.7_ (local/remote)
| CVE-2023-42793     | Remote Code Execution (RCE)     | Jetbrains TeamCity Authentication Bypass and RCE   |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, teamcity:2023.05.3 (Dockerfile (jetbrains/teamcity-server:2023.05.3_ (local/remote)_))_
| CVE-2024-23897     | Local File Inclusion            | Jenkins Local File Inclusion                       |     Yes     | **REPLICABLE** &rarr; requires: _docker-compose, jenkins:2.441 (Dockerfile + init.groovy)_