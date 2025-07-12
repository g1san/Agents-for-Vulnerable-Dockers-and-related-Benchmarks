# Agents for Vulnerable Dockers Creation & Testing
This thesis project focuses on automating the creation of systems vulnerable to a specific CVE through the use of **LLMs** and **Agentic Workflows**. All these systems are created using **Docker lightweight virtualization**. The goals of the agentic workflow are to:
- Retrieve from the Internet a description/summary of a given CVE
- Create, test and exploit a vulnerable system with Docker


## Potential Use Cases
These containers can then be used to gather real/synthetic attack data from:
- an unsafe environment, exposing the container to real attackers
- a safe environment, by letting another autonomous agent perform the attack


# Smartdata's VDaaS Respository
The [VDaaS repository](https://github.com/SmartData-Polito/VDaaS/tree/main) contains a series of manually created vulnerable docker systems (taken from the [Vulhub repository](https://github.com/vulhub/vulhub), an open-source collection of pre-built vulnerable docker environments for security researchers and educators) and (for some of these systems) the associated exploits.

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


## Replication Complexity Table
Table of all exploitable CVE that lists:
- The CVE-ID
- If the CVE was already replicated through the LLM web interface
- The __*number of files*__ the LLM needs to replicate to create a vulnerable Docker
- The names of the files

The __*number of files*__ is used as an indicator of how difficult it can be for an LLM to create such container.

**NOTE**: only CVEs with a _script.sh_ file and **REPLICABLE** status are considered

| CVE/WooYun ID      | Replicated | # Files to Replicate | Files to Replicate     
|--------------------|------------|----------------------|--------------------
| CVE-2012-1823      |     No     | 9/10                 | _docker-compose, php:5.4.1-cgi (Dockerfile (php:5.4.1 (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + apache2-foreground)_ and (1/2?) _.php_ files
| CVE-2016-5734      |     No     | 8                    | _docker-compose, phpmyadmin:4.4.15.6 (Dockerfile (php:5.3-apache (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + config.inc.php)_ and _mysql:5.5_ (local/remote)
| WooYun-2016-199433 |     No     | 7                    | _docker-compose, phpmyadmin:2.8.0.4 (Dockerfile (php:5.4.x-apache (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)))_
| CVE-2018-12613     |     No     | 8                    | _docker-compose, phpmyadmin:4.8.1 (Dockerfile (php:7.2-apache (Dockerfile + apache2-foreground + docker-php-entrypoint + docker-php-ext-configure + docker-php-ext-install)) + config.inc.php)_ and _mysql:5.5_ (local/remote)
| CVE-2020-7247      |     No     | 4                    | _docker-compose, opensmtpd:6.6.1p1 (Dockerfile + aliases + smtpd.conf)_
| CVE-2020-11651     |     No     | 3                    | _docker-compose, saltstack:2019.2.3 (Dockerfile + saltinit.py)_
| CVE-2020-11652     |     No     | 3                    | _docker-compose, saltstack:2019.2.3 (Dockerfile + saltinit.py)_
| CVE-2021-3129      |     No     | 2                    |_docker-compose, laravel:8.4.2 (Dockerfile (php:7.4-apache_ (local/remote)_))_.
| CVE-2021-28164     |   **Yes**  | 2                    |_docker-compose, jetty:9.4.37 (Dockerfile)_
| CVE-2021-34429     |     No     | 2                    |_docker-compose, jetty:9.4.40 (Dockerfile)_
| CVE-2021-41773     |     No     | 3                    |_docker-compose, apache (Dockerfile (httpd:2.4.49 (Dockerfile)))_
| CVE-2021-42013     |     No     | 3                    |_docker-compose, apache (Dockerfile (httpd:2.4.50 (Dockerfile)))_
| CVE-2021-43798     |     No     | 2                    |_docker-compose, grafana:8.2.6 (Dockerfile)_
| CVE-2021-44228     |     No     | 3                    |_docker-compose, solr:8.11.0 (Dockerfile + docker-entrypoint.sh)_
| CVE-2022-22947     |     No     | 6                    |_docker-compose, spring-cloud-gateway:3.1.0 (Dockerfile + pom.xml + .gitignore + application.xml + SpringCloudGatewayApplication.java)_
| CVE-2022-22963     |     No     | 4                    |_docker-compose, spring-cloud-function:3.2.2 (Dockerfile + pom.xml + SpringCloudApplicationFunctionSample.java)_
| CVE-2022-24706     |     No     | 3                    |_docker-compose, couchdb:3.2.1 (Dockerfile + docker-entrypoint.sh)_
| CVE-2022-46169     |   **Yes**   | 5                    |_docker-compose, cacti:1.2.22 (Dockerfile (php:7.4-apache_ (local/remote)_) + cacti.ini + config.php) + entrypoint.sh_ and _mysql:5.7_ (local/remote) 
| CVE-2023-23752     |     No     | 4                    |_docker-compose, joomla:4.2.7 (Dockerfile (php:7.4.33-apache_ (local/remote)_) + docker-entrypoint + .htaccess) and mysql:5.7_ (local/remote) 
| CVE-2023-42793     |     No     | 2                    |_docker-compose, teamcity:2023.05.3 (Dockerfile (jetbrains/teamcity-server:2023.05.3_ (local/remote)_))_
| CVE-2024-23897     |   **Yes**  | 3                    |_docker-compose, jenkins:2.441 (Dockerfile + init.groovy)_


## CVEs with a Docker

| CVE ID        | Services     
|---------------|----------
| CVE-2015-5254 | _activemq:5.11.1_
| CVE-2016-3088 | _activemq:5.11.1-with-cron_
| CVE-2022-41678 | _activemq:5.17.3_
| CVE-2023-46604 | _activemq:5.17.3_
| CVE-2021-21311 | _adminer:4.7.8_
| CVE-2021-43008 | _adminer:4.6.2_
| CVE-2020-11978 | _airflow:1.10.10, postgres:13-alpine, redis:5-alpine_
| CVE-2020-11981 | _airflow:1.10.10, postgres:13-alpine, redis:5-alpine_
| CVE-2020-17526 | _airflow:1.10.10, postgres:13-alpine, redis:5-alpine_
| CVE-2024-7314 (CNVD-2024-15077) | _aj-report:1.4.0, mysql:5.7_
| CVE-2021-25646 | _apache-druid:0.20.0_
| CVE-2020-13945 | _apisix:2.11.0, bitnami/etcd:3.4.15_
| CVE-2021-45232 | _apisix:2.9, apisix-dashboard:2.9.0, bitnami/etcd:3.4.15_
| CVE-2018-8715 | _appweb:7.0.1_
| CVE-2023-39141 | _aria2:1.18.8_
| CVE-2023-39141 | _aria2:1.18.8_
| CVE-2014-6271 | _bash:4.3.0-with-httpd_
| CVE-2022-46169 | _cacti:1.2.22, mysql:5.7_
| CVE-2016-5385 | _nginx:1, php:httpoxy_
| CVE-2019-9053 | _cmsms:2.2.9.1, mysql:5.7_
| CVE-2021-26120 | _cmsms:2.2.9.1, mysql:5.7_
| CVE-2010-2861 | _coldfusion:8.0.1_
| CVE-2017-3066 | _coldfusion:11u3_
| CVE-2023-26360 | _coldfusion:2018.0.15_
| CVE-2023-29300 | _coldfusion:2018.0.15_
| CVE-2019-3396 | _confluence:6.10.2, postgres:10.7-alpine_
| CVE-2021-26084 | _confluence:7.4.10, postgres:12.8-alpine_
| CVE-2022-26134 | _confluence:7.13.6, postgres:12.8-alpine_
| CVE-2023-22515 | _confluence:8.5.1, postgres:15.4-alpine_
| CVE-2023-22527 | _confluence:8.5.3, postgres:15.4-alpine_
| CVE-2017-12635 | _couchdb:2.1.0, buildpack-deps:focal-curl_
| CVE-2017-12636 | _couchdb:1.6.0_
| CVE-2022-24706 | _couchdb:3.2.1_
| CVE-2017-12794 | _django:1.11.4, postgres:9.6-alpine_
| CVE-2018-14574 | _django:2.0.7_
| CVE-2019-14234 | _django:2.2.3, postgres:9.6-alpine_
| CVE-2020-9402 | _django:3.0.3, oracle:12c-ee_
| CVE-2021-35042 | _django:3.2.4, mysql:5.7_
| CVE-2022-34265 | _django:4.0.5, postgres:13-alpine_
| CVE-2014-3704 | _drupal:7.31, mysql:5.5_
| CVE-2017-6920 | _drupal:8.3.0_
| CVE-2018-7600 | _drupal:8.5.0_
| CVE-2018-7602 | _drupal:7.57_
| CVE-2019-6339 | _drupal:8.5.0_
| CVE-2019-6341 | _drupal:8.5.0_
| CVE-2019-17564 | _dubbo:2.7.3, zookeeper:3.7.0_
| CVE-2021-41460 | _ecshop:4.0.6, mysql:5.5_
| CVE-2014-3120 | _elasticsearch:1.1.1_
| CVE-2015-1427 | _elasticsearch:1.4.2_
| CVE-2015-3337 | _elasticsearch:1.4.4_
| CVE-2015-5531 | _elasticsearch:1.6.0_
| CVE-2018-15685 | _electron:wine, nginx:1_
| CVE-2021-32682 | _elfinder:2.1.58_
| CVE-2017-18349 | _fastjson:1.2.24_
| CVE-2016-1897 | _ffmpeg:2.8.4-with-php_
| CVE-2016-1898 | _ffmpeg:2.8.4-with-php_
| CVE-2017-9993 | _ffmpeg:3.2.4-with-php_
| CVE-2025-23211 | _flask:1.1.1_
| CVE-2020-17518 | _flink:1.11.2_
| CVE-2020-17519 | _flink:1.11.2_
| CVE-2021-40822 | _geoserver:2.19.1_
| CVE-2022-24816 | _geoserver:2.17.2_
| CVE-2023-35042 | _geoserver:2.17.2_
| CVE-2023-25157 | _geoserver:2.22.1, postgis:14-3.3-alpine_
| CVE-2024-36401 | _geoserver:2.23.2_
| CVE-2018-16509 | _imagemagick:7.0.8-10-php_
| CVE-2018-19475 | _imagemagick:7.0.8-20-php_
| CVE-2019-6116 | _imagemagick:7.0.8-27-php_
| CVE-2017-8386 | _git:2.12.2-with-openssh_
| CVE-2020-14144 | _gitea:1.4.0_
| CVE-2016-9086 | _gitlab:8.13.1, redis:4.0.14-alpine, postgres:11.9-alpine_
| CVE-2021-22205 | _gitlab:13.10.1, redis:5.0.9-alpine, postgres:12-alpine_
| CVE-2018-1000533 | _gitlist:0.6.0_
| CVE-2017-1000028 | _glassfish:4.1_
| CVE-2017-17562 | _goahead:3.6.4_
| CVE-2021-42342 | _goahead:5.1.4_
| CVE-2018-18925 | _gogs:0.11.66_
| CVE-2023-51449 | _gradio:4.10.0_
| CVE-2024-1561 | _gradio:4.12.0_
| CVE-2021-43798 | _grafana:8.2.6_
| CVE-2025–4123 | _grafana:8.5.4_
| CVE-2018-10054 | _spring-with-h2database:1.4.197_
| CVE-2021-42392 | _spring-with-h2database:2.0.204_
| CVE-2022-23221 | _spring-with-h2database:2.0.206_
| CVE-2023-26031 | _hadoop:2.8.1_
| CVE-2024-42323 | _hertzbeat:1.4.4_
| CVE-2017-15715 | _php:5.5-apache_
| CVE-2021-40438 | _httpd:2.4.43, tomcat:8.5.19_
| CVE-2021-41773 | _httpd:2.4.49_
| CVE-2021-42013 | _httpd:2.4.50_
| CVE-2024-27348 | _hugegraph:1.2.0_
| CVE-2024-43441 | _hugegraph:1.3.0_
| CVE-2016–3714 | _imagemagick:6.9.2-10-php_
| CVE-2020-29599 | _imagemagick:7.0.10-36_
| CVE-2022-44268 | _imagemagick:7.1.0-49-php_
| CVE-2019-20933 | _influxdb:1.6.6_
| CVE-2025-1974 | _ingress-nginx:1.9.5_
| CVE-2017-7525 | _spring-with-jackson:2.8.8_
| CVE-2017-12149 | _jboss:as-6.1.0_
| CVE-2017-7504 | _jboss:as-4.0.5_
| CVE-2017-1000353 | _jenkins:2.46.1_
| CVE-2018-1000861 | _jenkins:2.138_
| CVE-2024-23897 | _jenkins:2.441_
| CVE-2012-1823  | _php:5.4.1-cgi, php:5.4.1_
| CVE-2016-5734  | _phpmyadmin:4.4.15.6, php:5.3-apache, mysql:5.5_
| CVE-2018-12613 | _phpmyadmin:4.8.1, php:7.2-apache, mysql:5.5_
| CVE-2020-7247  | _opensmtpd:6.6.1p1_
| CVE-2020-11651 | _saltstack:2019.2.3_
| CVE-2020-11652 | _saltstack:2019.2.3_
| CVE-2021-3129  | _laravel:8.4.2_
| CVE-2021-28164 | _jetty:9.4.37_
| CVE-2021-34429 | _jetty:9.4.40_
| CVE-2021-44228 | _solr:8.11.0_
| CVE-2022-22947 | _spring-cloud-gateway:3.1.0_
| CVE-2022-22963 | _spring-cloud-function:3.2.2_
| CVE-2023-23752 | _joomla:4.2.7, php:7.4.33-apache, mysql:5.7_
| CVE-2023-42793 | _teamcity:2023.05.3, jetbrains/teamcity-server:2023.05.3_