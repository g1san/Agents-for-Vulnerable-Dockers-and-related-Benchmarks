
# CVE-2012-1823 
## 'custom'
The web search shows the right version numbers just not the 'cgi' variant
## 'custom_no_tool'
The web search shows the right version numbers just not the 'cgi' variant
## 'openai'
Web search results are ok, always fails to build image





# CVE-2016-5734 
## 'custom'
Web search results are ok, always fails to build image
## 'custom_no_tool'
Web search results are ok, always fails to build image
## 'openai'
**Allucination**: incorrect versions of _php_ is used (_7.4_ does patches the CVE). Docker Scout does not find the CVE. **Exploit** does not work.





# CVE-2018-12613
## 'custom'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit** was tested with slight modifications to Docker files and it works, but Docker Scout does not find the CVE even when exploit works.
## 'custom_no_tool'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit** was tested with slight modifications to Docker files it works, but Docker Scout does not find the CVE even when exploit works.
## 'openai'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE. 
**Exploit** was tested with slight modifications to Docker files it works, but Docker Scout does not find the CVE even when exploit works.





# CVE-2020-7247 
## 'custom'
A vulnerable version of OpenSMTP is identified, but not the one of 'services.json'. CVE description is correct and includes the version of 'services.json'
## 'custom_no_tool'
Web search results are ok, wrong version of OpenSMTP is used in the container (alpine:3.12 is not a vulnerable version). Moreover, OpenSMTP container cannot me stabilised and keeps showing errors
## 'openai'
Web search results are ok, an unspecified version of OpenSMTP is used in the container. Moreover, OpenSMTP container cannot be stabilised and keeps showing errors





# CVE-2020-11651
## 'custom'
All ok, **exploit works**
## 'custom_no_tool'
All ok, **exploit works**
## 'openai'
All ok, **exploit works**





# CVE-2020-11652
## 'custom'
All ok, **exploit works**
## 'custom_no_tool'
All ok, **exploit works**
## 'openai'
Wrong 'HARD' service name, _salt-master_ instead of _salt_





# CVE-2021-3129 
## 'custom'
It is not clear whether or not the right version of _laravel_ is used. Docker Scout does not find the CVE neither does the exploit work
## 'custom_no_tool'
The version of 'services.json' is **not** included in the web search results. Other versions which are vulnerable are instead included. **Relaunch this with existing web search results**
## 'openai'
'HARD' service not identified (_laravel_)





# CVE-2021-28164
## 'custom'
Typical problem of _jetty_ versions
## 'custom_no_tool'
Typical problem of _jetty_ versions
## 'openai'
All ok, **exploit works**





# CVE-2021-34429
## 'custom'
All ok, **exploit works**, there is just a misplaced folder that does not allow it to work instantly. To make it work just move WEB-INF folder inside ROOT folder
## 'custom_no_tool'
All ok, **exploit works**, there is just no file to read in the desired path. To make it work just add ROOT/WEB-INF/something.xml file inside 'webapps' folder. Adding this also allows Docker Scout to spot the CVE
## 'openai'
All ok, **exploit works**, there is just a misplaced folder that does not allow it to work instantly. To make it work just move WEB-INF folder inside ROOT folder





# CVE-2021-41773
## 'custom'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE because it has problem analyzing images using _httpd_, since no CVEs are identified. **Exploit also works partially, path traversal works, but RCE does not**. Moreover, as usual, 'SOFT' service 'ubuntu' is not included in the Docker
## 'custom_no_tool'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE because it has problem analyzing images using _httpd_, since no CVEs are identified. 
**Exploit works** if line 34 of _httpd.conf_ is changed to 'Require all granted'
Moreover, as usual, 'SOFT' service _ubuntu_ is not included in the Docker
## 'openai'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE because it has problem analyzing images using _httpd_, since no CVEs are identified. **Exploit does NOT work**, probably because Docker is missing essential _httpd.conf_ file





# CVE-2021-42013
## 'custom'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit for RCE does does not work** unless line 13 of _httpd.conf_ is changed to 'Require all granted'.
Meanwhile, the arbitrary file read exploit does not work because the LLM did not generate the necessary files to read and folders to travel through.
Moreover, as usual, 'SOFT' service 'ubuntu' is not included in the Docker
## 'custom_no_tool'
Web search results are ok, but the container hosting _httpd_ cannot be stabilised.  Moreover, as usual, 'SOFT' service 'ubuntu' is not included in the Docker
## 'openai'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE. **Exploit works** if line 23 of _httpd.conf_ is changed to 'Require all granted'. There is just a problem with the _.decode()_ RCE function in the _.py_ file. Should not be a Docker problem Moreover, as usual, 'SOFT' service _debian_ is not included in the Docker





# CVE-2021-43798
## 'custom'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit works**
## 'custom_no_tool'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE. **Exploit works**
## 'openai'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE,. **Exploit works**





# CVE-2021-44228
## 'custom'
Wrong 'HARD' dependency: _logstash_ instead of _log4j_
## 'custom_no_tool'
Web search results are ok, but the container hosting _log4j_ cannot be stabilised
## 'openai'
Wrong 'HARD' dependency: _openjdk_ and _maven_ instead of _log4j_





# CVE-2022-22947
## 'custom'
It is not possible to understand which version of _spring-cloud-gateway_ is used. Docker Scout does not find the CVE. **Exploit seems to work, ASK**
## 'custom_no_tool'
Web search results are ok, always fails to build image
## 'openai'
Web search results are ok, always fails to build image





# CVE-2022-22963
## 'custom'
Web search results are ok, always fails to build image
## 'custom_no_tool'
It is not possible to understand which version of _spring-cloud-gateway_ is used. Docker Scout not finds the Docker vulnerable to CVE-2022-22963, but the **exploit does NOT seem to work**. Moreover the 'maven' container was observed to shutdown after about 1 minute of starting.
## 'openai'
Web search results are **not** ok, no 'HARD' dependency was proposed (**allucination**)





# CVE-2022-24706
## 'custom'
Web search results are ok, wrong version of CouchDB is used in the container (3.2.2 is not a vulnerable version). Moreover, CouchDB container cannot me stabilised and keeps showing errors
## 'custom_no_tool'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE. **Exploit does NOT work**
## 'openai'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE. **Exploit does NOT work**





# CVE-2022-46169
## 'custom'
Web search results are ok, wrong version of Cacti is used in the container (1.2.23 is not a vulnerable version). Image cannot be built
## 'custom_no_tool'
Web search results are ok, wrong version of Cacti is used in the container (uses _latest_ which is not a vulnerable version). Image cannot be built
## 'openai'
Web search results are ok, wrong version of Cacti is used in the container (1.2.23 is not a vulnerable version). Image cannot be built





# CVE-2023-23752
## 'custom'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit does NOT work** probably because of some missing files or because the DB is not populated
## 'custom_no_tool'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE. **Exploit does NOT work** probably because of some missing files or because the DB is not populated
## 'openai'
Web search result do not show a 'SOFT-WEB' service (expected to be _php_)





# CVE-2023-42793
## 'custom'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE.
**Exploit works AFTER manual setup**
## 'custom_no_tool'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE. **Exploit works AFTER manual setup**
## 'openai'
There seems to be nothing wrong, correct services and versions are used, but Docker Scout does not find the CVE, **to test exploit**. **Exploit works AFTER manual setup**





# CVE-2024-23897
## 'custom'
All ok, **exploit works**
## 'custom_no_tool'
All ok, **exploit does NOT work even AFTER manual setup**
## 'openai'
All ok, **exploit does NOT work even AFTER manual setup**
