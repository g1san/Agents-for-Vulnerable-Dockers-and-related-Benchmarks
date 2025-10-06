# 'custom'

## CVE-2012-1823
The web search shows the right version numbers just not the 'cgi' variant

## CVE-2016-5734
Web search results are ok, always fails to build image

## CVE-2018-12613
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit** was tested with slight modifications to Docker files and it works, but Docker Scout does not find the CVE even when exploit works.

## CVE-2020-7247
A vulnerable version of OpenSMTP is identified, but not the one of 'services.json'. CVE description is correct and includes the version of 'services.json'

## CVE-2020-11651
All ok, **exploit works**

## CVE-2020-11652
All ok, **exploit works**

## CVE-2021-3129
Web search results are ok, various containers manifest various issues that make them unstable

## CVE-2021-28164
Typical problem of _jetty_ versions

## CVE-2021-34429
All ok, **exploit works**, there is just a misplaced folder that does not allow it to work instantly. To make it work just move WEB-INF folder inside ROOT folder

## CVE-2021-41773
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**. Moreover, as usual, 'SOFT' service 'ubuntu' is not included in the Docker

## CVE-2021-42013
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**. Moreover, as usual, 'SOFT' service 'ubuntu' is not included in the Docker

## CVE-2021-43798
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2021-44228
Wrong 'HARD' dependency: _logstash_ instead of _log4j_

## CVE-2022-22947
Web search results are ok, always fails to build image

## CVE-2022-22963
Web search results are ok, always fails to build image

## CVE-2022-24706

### 1st RUN:
========== ERROR CAUGHT, NO SOLUTION FOUND ==========
The provided CVE ID is CVE-2022-24706!
	Directory '../../dockers/CVE-2022-24706/custom/logs' created successfully.

Checking if the CVE ID exists...
	CVE-2022-24706 exists!

Routing CVE (cve_id_ok = True)

Searching the web...
	The LLM invoked the 'web search' tool with parameters: query=CVE-2022-24706 details, cve_id=CVE-2022-24706
	Query: CVE-2022-24706 details
	Searching with Google API...
	Processing content from 5 web pages
	Content processed from https://github.com/cckuailong/pocsploit/blob/master/modules/cves/2022/CVE-2022-24706.py
	Content processed from https://medium.com/@ahmetsabrimert/apache-couchdb-cve-2022-24706-rce-exploits-548fe52f8c02
	Content processed from https://pentest-tools.com/vulnerabilities-exploits/couchdb-erlang-distribution-remote-command-execution_23022
	Content processed from https://www.wiz.io/vulnerability-database/cve/cve-2022-24706
	Content processed from https://www.tenable.com/plugins/nessus/161177
	Fetched 6 documents
Workflow invocation failed: 'NoneType' object has no attribute 'desc'
========== ERROR CAUGHT, NO SOLUTION FOUND ==========

### 2nd RUN:
Web search results are ok, wrong version of CouchDB is used in the container (3.2.2 is not a vulnerable version). Moreover, CouchDB container cannot me stabilised and keeps showing errors

## CVE-2022-46169
Web search results are ok, wrong version of Cacti is used in the container (1.2.23 is not a vulnerable version). Image cannot be built

## CVE-2023-23752
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2023-42793
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2024-23897
All ok, **exploit works**




# 'custom_no_tool'

## CVE-2012-1823
The web search shows the right version numbers just not the 'cgi' variant

## CVE-2016-5734
Web search results are ok, always fails to build image

## CVE-2018-12613
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit** was tested with slight modifications to Docker files it works, but Docker Scout does not find the CVE even when exploit works.

## CVE-2020-7247
Web search results are ok, wrong version of OpenSMTP is used in the container (alpine:3.12 is not a vulnerable version). Moreover, OpenSMTP container cannot me stabilised and keeps showing errors

## CVE-2020-11651
All ok, **exploit works**

## CVE-2020-11652
All ok, **exploit works**

## CVE-2021-3129
The version of 'services.json' is **not** included in the web search results. Other versions which are vulnerable are instead included. **Relaunch this with existing web search results**

## CVE-2021-28164
Typical problem of _jetty_ versions

## CVE-2021-34429
All ok, **exploit works**, there is just no file to read in the desired path. To make it work just add ROOT/WEB-INF/something.xml file inside 'webapps' folder. Adding this also allows Docker Scout to spot the CVE

## CVE-2021-41773
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**. Moreover, as usual, 'SOFT' service _ubuntu_ is not included in the Docker

## CVE-2021-42013
Web search results are ok, but the container hosting _httpd_ cannot be stabilised.  Moreover, as usual, 'SOFT' service 'ubuntu' is not included in the Docker

## CVE-2021-43798
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2021-44228
Web search results are ok, but the container hosting _log4j_ cannot be stabilised

## CVE-2022-22947
Web search results are ok, always fails to build image

## CVE-2022-22963
Web search results are ok, always fails to build image and it does not include the 'HARD' dependency service

## CVE-2022-24706
Web search results are ok, however the CouchDB container cannot be stabilised and keeps showing errors

## CVE-2022-46169
Web search results are ok, wrong version of Cacti is used in the container (uses _latest_ which is not a vulnerable version). Image cannot be built

## CVE-2023-23752
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2023-42793
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2024-23897
All ok, **to test exploit**



# 'openai'

## CVE-2012-1823
Web search results are ok, always fails to build image

## CVE-2016-5734
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit** does not work, probably because the Docker uses _php:7.4-apache_. Evaluate switch to 'HARD' dependency for _php_ to force lower version usage

## CVE-2018-12613
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit** was tested with slight modifications to Docker files it works, but Docker Scout does not find the CVE even when exploit works.

## CVE-2020-7247
Web search results are ok, an unspecified version of OpenSMTP is used in the container. Moreover, OpenSMTP container cannot be stabilised and keeps showing errors

## CVE-2020-11651
All ok, **exploit works**

## CVE-2020-11652
Wrong 'HARD' service name, _salt-master_ instead of _salt_

## CVE-2021-3129
'HARD' service not identified (_laravel_)

## CVE-2021-28164
All ok, **exploit works**

## CVE-2021-34429
All ok, **exploit works**, there is just a misplaced folder that does not allow it to work instantly. To make it work just move WEB-INF folder inside ROOT folder

## CVE-2021-41773
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2021-42013
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**. Moreover, as usual, 'SOFT' service _debian_ is not included in the Docker

## CVE-2021-43798
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2021-44228
Wrong 'HARD' dependency: _openjdk_ and _maven_ instead of _log4j_

## CVE-2022-22947
Web search results are ok, always fails to build image

## CVE-2022-22963
Web search results are **not** ok, no 'HARD' dependency was proposed (**allucination**)

## CVE-2022-24706
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2022-46169
Web search results are ok, wrong version of Cacti is used in the container (1.2.23 is not a vulnerable version). Image cannot be built

## CVE-2023-23752
Web search result do not show a 'SOFT-WEB' service (expected to be _php_)

## CVE-2023-42793
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**.

## CVE-2024-23897
All ok, **to test exploit**
