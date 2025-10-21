
# GPT-5 3rd Benchmark Results

## CVE-2012-1823
### 'custom'
- **Web Search** &rarr; (_PASS_) right version numbers but not the 'cgi' variant, LM-as-a-Judge decided it was ok this time
- **Docker** &rarr; (_FAIL_) always fails to build image
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_) right version numbers but not the 'cgi' variant, LM-as-a-Judge decided it was ok this time
- **Docker** &rarr; (_FAIL_) always fails to build image or uses a wrong version of _php_





## CVE-2016-5734
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) always fails to build image or to recover from NETWORK MISCONFIGURATION error, which should be easy to fix
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) always fails to build image or uses a wrong version of _phpmyadmin_





## CVE-2018-12613
### 'custom'
- **Web Search** &rarr; (_FAILS_) missing 'SOFT-DB' service (expected _mySQL_) and wrong 'SOFT-WEB' service (_apache_ rather than _php_ which is instead tagged as 'SOFT')
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_) 'SOFT-WEB' service is _httpd_ instead of _php_ (might be a problem)
- **Docker** &rarr; (_FAIL_) latest fail is just network setup, it should be easily solved manually





## CVE-2020-7247 
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) latest error is a container error linked to the _OpenSTMPD_ service
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) latest fails are linked to image building problems





## CVE-2020-11651
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_PASS_)
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_PASS_)





## CVE-2020-11652
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_PASS_)
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_PASS_)





## CVE-2021-3129 
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_) not sure if a vulnerable version of _laravel_ is used.
- **Static VA** &rarr; (_FAIL_)
- **Dynamic VA** &rarr; (_FAIL_)
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_) not sure if a vulnerable version of _laravel_ is used.
- **Static VA** &rarr; (_FAIL_)
- **Dynamic VA** &rarr; (_FAIL_)





## CVE-2021-28164
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_FAIL_) it is not that the Docker is not vulnerable, the exploit probably fails because there are no files in the vulnerable directory
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) the container linked to the _apache_ service is stuck in a restarting loop
- **Static VA** &rarr; (_FAIL_)





## CVE-2021-34429
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_PASS_) the exploit can retrieve anything that is inside the ROOT folder
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_FAIL_) strange, even after having added the ROOT folder just like the _custom_ solution, the exploit did not work. _jetty:11.0.5-jdk11_ is used, this is a much later version than the _jetty:9.4.42-jdk11_ used by the _custom_ solution, but both the web search and Docker Scout say it should be vulnerable





## CVE-2021-41773
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_FAIL_) Docker Scout does not find the CVE because it has problem analyzing images using _httpd_, since no CVEs are present in the list 
- **Dynamic VA** &rarr; (_FAIL_) **RCE exploit works**, while **PT exploit does not**
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_FAIL_) Docker Scout does not find the CVE because it has problem analyzing images using _httpd_, since no CVEs are present in the list 
- **Dynamic VA** &rarr; (_FAIL_) the exploit does not work. The LLM did not generate the _httpd.conf_ configuration file





## CVE-2021-42013
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_FAIL_) Docker Scout does not find the CVE because it has problem analyzing images using _httpd_, since no CVEs are present in the list 
- **Dynamic VA** &rarr; (_FAIL_) **RCE exploit works**, while **PT exploit does not**
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) LLM cannot solve errors linked to _apache_ container





## CVE-2021-43798
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_FAIL_)
- **Dynamic VA** &rarr; (_PASS_)
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_FAIL_)
- **Dynamic VA** &rarr; (_PASS_)





## CVE-2021-44228
### 'custom'
- **Web Search** &rarr; (_FAIL_) wrong 'HARD' dependency: _openjdk_ instead of _log4j_
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_) not sure which version of _log4j_ is used
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_FAIL_) not sure why it fails. Some disconnection errors are shown in the exploit logs, moreover the Docker is set to use port 389 instead of exploit default 8983




## CVE-2022-22947
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) there seems to be a link between WRONG NETWORK SETUP and IMAGE BUILD failures
- **Static VA** &rarr; (_FAIL_)
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_) not sure which version of _spring-cloud-gateway_ is used
- **Static VA** &rarr; (_FAIL_)
- **Dynamic VA** &rarr; (_FAIL_) exploit error logs keep showing 404 code at each step





## CVE-2022-22963
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_) not sure which version of _spring-cloud-gateway_ is used
- **Static VA** &rarr; (_FAIL_)
- **Dynamic VA** &rarr; (_FAIL_) internal DOcker logs show this error when exploit is executed and returns code 405:
2025-10-21 12:08:14.500  WARN 1 --- [nio-8080-exec-7] .w.s.m.s.DefaultHandlerExceptionResolver : Resolved [org.springframework.web.HttpRequestMethodNotSupportedException: Request method 'POST' not supported]
### 'custom_no_tool'
- **Web Search** &rarr; (_FAIL_) wrong 'HARD' dependency, _springcloudfunction/function_ instead of _spring-cloud-gateway_





## CVE-2022-24706
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) generic problem with structured output of _gpt-oss:120b_ during revision phase does not allow the agent run to complete
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) generic problem with structured output of _gpt-oss:120b_ during revision phase does not allow the agent run to complete





## CVE-2022-46169
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_FAIL_) always fails to build image
### 'custom_no_tool'
- **Web Search** &rarr; (_FAIL_) no 'SOFT-WEB' service (should have been _php_)





## CVE-2023-23752
### 'custom'
- **Web Search** &rarr; (_FAIL_) no 'SOFT-WEB' service (should have been _php_)
### 'custom_no_tool'
- **Web Search** &rarr; (_FAIL_) no 'SOFT-WEB' service (should have been _php_)





## CVE-2023-42793
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_FAIL_)
- **Dynamic VA** &rarr; (_PASS_) **exploit works AFTER manual setup of _teamcity_**
### 'custom_no_tool'
- **Web Search** &rarr; (_FAIL_) wrong 'HARD' dependency name, _teamcity_ instead of _teamcity-server_





## CVE-2024-23897
### 'custom'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_PASS_)
### 'custom_no_tool'
- **Web Search** &rarr; (_PASS_)
- **Docker** &rarr; (_PASS_)
- **Static VA** &rarr; (_PASS_)
- **Dynamic VA** &rarr; (_FAIL_) files are there (check _jenkins_ container) but exploit cannot retrieve them. maybe do Wireshark capture to understand what is happening
