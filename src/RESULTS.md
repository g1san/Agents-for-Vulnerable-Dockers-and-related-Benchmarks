# 05/06/2025

## OBTAINED WITH 'custom'
- **CVE-2021-28164**
    - description='CVE-2021-28164 is an information disclosure vulnerability in the Eclipse Jetty web server, allowing unauthorized access to sensitive files in the WEB-INF directory due to improper URI parsing.,'
    - attack_type='Information Disclosure,'
    - services=['jetty:9.4.42.v20210604'],
    - service_description=['Jetty 9.4.42.v20210604 is a version of the Jetty web server that is vulnerable to CVE-2021-28164, allowing access to protected files in the WEB-INF directory through specially crafted URIs.'],
- **CVE-2022-46169**
    - description='CVE-2022-46169 is a critical command injection vulnerability in Cacti version 1.2.22, allowing unauthenticated remote code execution (RCE) by exploiting improper sanitization of query arguments in HTTP requests.,'
    - attack_type='Remote Code Execution (RCE),'
    - services=['cacti:1.2.22', 'php:7.4-apache', 'mysql:5.7'],
    - service_description=['Cacti 1.2.22 is the vulnerable version of the network monitoring tool where the command injection vulnerability exists.', 'PHP 7.4 with Apache is required to run Cacti, as it is a PHP-based application.', 'MySQL 5.7 is used as the database backend for Cacti to store monitoring data and configurations.'],
- **CVE-2024-23897**
    - description='CVE-2024-23897 is a critical vulnerability in Jenkins affecting its CLI, allowing unauthorized file read and potential RCE due to args4j library misuse.,'
    - attack_type='Remote Code Execution (RCE),'
    - services=['jenkins:2.441', 'openjdk:8-jdk'],
    - service_description=['Jenkins 2.441 is required as it is vulnerable to CVE-2024-23897 due to the CLI command parser flaw.', 'OpenJDK 8 is needed to run Jenkins, as Jenkins is a Java-based application.'],

## OBTAINED WITH 'custom_no_tool'
- **CVE-2021-28164**
    - description='CVE-2021-28164 is an information disclosure vulnerability in the Eclipse Jetty web server, allowing unauthorized access to sensitive files in the WEB-INF directory through crafted URIs with encoded characters.',
    - attack_type='Information Disclosure', 
    - services=['eclipse/jetty:9.4.42.v20210604'],
    - service_description=['Jetty 9.4.42.v20210604 is vulnerable to CVE-2021-28164, allowing access to protected files in the WEB-INF directory through crafted URIs.'],
- **CVE-2022-46169**
    - description='CVE-2022-46169 is a critical command injection vulnerability in Cacti version 1.2.22, allowing unauthenticated remote code execution (RCE) by exploiting improper sanitization in HTTP requests.', 
    - attack_type='Remote Code Execution (RCE)',
    - services=['cacti:1.2.22', 'php:7.4-apache', 'mysql:5.7'],
    - service_description=['Cacti 1.2.22 is the vulnerable version of the network monitoring tool where the command injection vulnerability exists.', 'PHP 7.4 with Apache is required to run Cacti, as it is a PHP-based application.', 'MySQL 5.7 is used as the database backend for Cacti to store monitoring data and configurations.'],
- **CVE-2024-23897**
    - description='CVE-2024-23897 is a critical vulnerability in Jenkins' CLI, allowing unauthorized file reads and potential RCE due to a flaw in the args4j library.',
    - attack_type='Remote Code Execution (RCE)',
    - services=['jenkins:2.441', 'openjdk:11-jre-slim'],
    - service_description=['Jenkins:2.441 - This version of Jenkins is vulnerable to CVE-2024-23897 due to the args4j library flaw in its CLI, allowing unauthorized file reads and potential RCE.', 'OpenJDK:11-jre-slim - Required to run Jenkins, as Jenkins is a Java-based application.'],

## OBTAINED WITH 'openai'
- **CVE-2021-28164**
    - description='Eclipse Jetty versions 9.4.37.v20210219 through 9.4.38.v20210224 allow requests with URIs containing `%2e` or `%2e%2e` segments to access protected resources within the `WEB-INF` directory, potentially exposing sensitive information.',
    - attack_type='Information Disclosure',
    - services=['eclipse/jetty:9.4.38.v20210224'],
    - service_description=['Eclipse Jetty is a widely used web server and servlet container that is vulnerable to the CVE-2021-28164, allowing unauthorized access to protected resources.'],
- **CVE-2022-46169**
    - description='CVE-2022-46169 is a critical command injection vulnerability in Cacti versions up to and including 1.2.22. It allows unauthenticated users to execute arbitrary code on servers running the affected versions. The flaw resides in the `remote_agent.php` file, which can be accessed without authentication. By manipulating HTTP headers, an attacker can bypass authorization checks and exploit the `poll_for_data` function to execute commands on the server. ([nvd.nist.gov](https://nvd.nist.gov/vuln/detail/cve-2022-46169?utm_source=openai))',
    - attack_type='Remote Code Execution (RCE)',
    - services=['Cacti:1.2.22', 'Apache:2.4.54', 'MariaDB:10.5.16', 'PHP:7.4.30'],
    - service_description=['This version is directly affected by CVE-2022-46169. Docker Image: `cacti/cacti:1.2.22`', 'A compatible web server for hosting Cacti. Docker Image: `httpd:2.4.54`', 'A compatible database server for Cacti. Docker Image: `mariadb:10.5.16`', 'A compatible PHP version required by Cacti 1.2.22. Docker Image: `php:7.4.30-apache`'],
- **CVE-2024-23897**
    - description='CVE-2024-23897 is a critical vulnerability in Jenkins versions 2.441 and earlier, as well as LTS versions 2.426.2 and earlier. This flaw allows unauthenticated attackers to read arbitrary files on the Jenkins controller file system by exploiting a feature in the CLI command parser that replaces an '@' character followed by a file path with the file's contents. ([nvd.nist.gov](https://nvd.nist.gov/vuln/detail/cve-2024-23897?utm_source=openai))',
    - attack_type='Arbitrary File Read',
    - services=['jenkins:2.441'],
    - service_description=['This Docker image corresponds to Jenkins version 2.441, which is susceptible to CVE-2024-23897.'],


# 01/07/2025

## OBTAINED WITH 'custom'
- **CVE-2021-28164**
    - description='CVE-2021-28164 is an information disclosure vulnerability in Eclipse Jetty, where certain encoded URIs can access protected files in the WEB-INF directory, potentially exposing sensitive information.,'
    - attack_type='Information Disclosure,'
    - services=['eclipse/jetty:9.4.38.v20210224', 'openjdk:8-jdk'],
    - service_type=['MAIN', 'AUX'],
    - service_description=['Eclipse Jetty is the main service affected by CVE-2021-28164, where the vulnerability allows unauthorized access to sensitive files in the WEB-INF directory.', 'OpenJDK is required to run Java applications, including the Jetty server, and is necessary for the system to function.'],

## OBTAINED WITH 'custom_no_tool'
- **CVE-2021-28164**
    - description='CVE-2021-28164 is an information disclosure vulnerability in Eclipse Jetty, where the default compliance mode allows requests with encoded URIs to access protected resources within the WEB-INF directory, potentially exposing sensitive files like web.xml.,'
    - attack_type='Information Disclosure,'
    - services=['jetty:9.4.38.v20210224', 'openjdk:8-jdk'],
    - service_type=['MAIN', 'AUX'],
    - service_description=['Jetty is the main service affected by CVE-2021-28164, where certain encoded URIs can access protected files in the WEB-INF folder.', 'OpenJDK is required to run Jetty, as it is a Java-based web server.'],


## OBTAINED WITH 'openai'
- **CVE-2021-28164**
    - description='CVE-2021-28164 is an information disclosure vulnerability in Eclipse Jetty versions 9.4.37.v20210219 to 9.4.38.v20210224. The default compliance mode in these versions allows requests with URIs containing `%2e` or `%2e%2e` segments to access protected resources within the `WEB-INF` directory. For example, a request to `/context/%2e/WEB-INF/web.xml` can retrieve the `web.xml` file, potentially exposing sensitive information about the web application's implementation. ([tenable.com](https://www.tenable.com/cve/CVE-2021-28164?utm_source=openai)),'
    - attack_type='Information Disclosure,'
    - services=['jetty:9.4.37.v20210219', 'openjdk:11.0.10', 'debian:buster'],
    - service_type=['MAIN', 'AUX', 'AUX'],
    - service_description=['Jetty is the main service affected by the vulnerability, providing the web server environment where the issue occurs.', 'OpenJDK is required to run Jetty, as it provides the necessary Java runtime environment.', 'Debian Buster serves as the base operating system, providing a stable environment for running the other services.'],


# 02/07/2025

## OBTAINED WITH 'custom_no_tool'
- **CVE-2017-7525**
    - description='CVE-2017-7525 is a deserialization vulnerability in the Jackson Databind library, allowing remote code execution by exploiting the deserialization of untrusted data.,'
    - attack_type='Remote Code Execution (RCE),'
    - services=['openjdk:8-jdk', 'jackson-databind:2.8.8'],
    - service_type=['AUX', 'MAIN'],
    - service_description=['Java Development Kit needed to run Java applications.', 'Vulnerable version of Jackson Databind library.'],


# 09/07/2025

## OBTAINED WITH 'custom_no_tool'

### **CVE-2022-46169**
"web_search_result": WebSearchResult(
                description="CVE-2022-46169 is a critical command injection vulnerability in Cacti, affecting versions up to 1.2.22. It allows unauthenticated remote code execution (RCE) by exploiting an authentication bypass and command injection in the `remote_agent.php` file. The vulnerability is due to improper sanitization of query arguments, allowing attackers to execute arbitrary commands on the server. The issue is patched in versions 1.2.23 and 1.3.0.", 
                attack_type="Remote Code Execution (RCE)", 
                services=['cacti:1.2.22', 'mysql:5.7', 'php:7.4-apache'], 
                service_type=['MAIN', 'AUX', 'AUX'], 
                service_description=['Cacti is the main service vulnerable to CVE-2022-46169, allowing RCE through command injection.', 'MySQL is required as the database service for Cacti to store monitoring data.', 'PHP with Apache is needed to serve the Cacti application and process PHP scripts.'],
            ),

### **CVE-2021-46169** (see 'attempt2')
"web_search_result": WebSearchResult(
                description='CVE-2021-28164 is a vulnerability in Eclipse Jetty, affecting versions 9.4.37.v20210219 to 9.4.42, 10.0.1 to 10.0.5, and 11.0.1 to 11.0.5. The vulnerability arises from improper handling of URIs containing encoded segments like %2e or %2e%2e, allowing unauthorized access to protected resources within the WEB-INF directory, such as the web.xml file. This can lead to information disclosure and potential further exploitation.',
                attack_type='Information Disclosure',
                services=['jetty:9.4.37', 'openjdk:8-jdk'],
                service_type=['MAIN', 'AUX'],
                service_description=['Jetty is the main service vulnerable to CVE-2021-28164, allowing unauthorized access to sensitive files through improperly handled URIs.', 'OpenJDK is required to run Jetty, as it is a Java-based web server.'],
            ),
'code': CodeGenerationResult(
                file_name=['docker-compose.yml', 'Dockerfile', 'webapps/WEB-INF/web.xml', 'webapps/index.html'],
                file_code=['version: \'3.8\'\nservices:\n  jetty:\n    build: .\n    ports:\n      - "8080:8080"\n    volumes:\n      - ./webapps:/var/lib/jetty/webapps\n', 'FROM jetty:9.4.38-jre8\n\nCOPY ./webapps /var/lib/jetty/webapps\n', '<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"\n         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee \n         http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"\n         version="3.1">\n\n    <servlet>\n        <servlet-name>default</servlet-name>\n        <servlet-class>org.eclipse.jetty.servlet.DefaultServlet</servlet-class>\n    </servlet>\n\n    <servlet-mapping>\n        <servlet-name>default</servlet-name>\n        <url-pattern>/</url-pattern>\n    </servlet-mapping>\n\n</web-app>\n', '<html>\n<head>\n    <title>Jetty Vulnerable App</title>\n</head>\n<body>\n    <h1>Welcome to the Jetty Vulnerable Application</h1>\n    <p>This application is vulnerable to CVE-2021-28164.</p>\n</body>\n</html>\n'],
                directory_tree='CVE-2021-28164/\n├── docker-compose.yml\n├── Dockerfile\n└── webapps\n    ├── WEB-INF\n    │   └── web.xml\n    └── index.html\n',
            ),