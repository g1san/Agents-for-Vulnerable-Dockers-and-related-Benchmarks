# Creation of Dockers through LLM Web Interface
These dockers were obtained by manually interacting with the web interface of various LLMs:
1. Grok 3
2. GPT-4o
3. DeepSeek-V3
4. 2.0 Flash
5. Claude 3.7 Sonnet

## Repository Organization
- **CVE-YYYY-XXXX** &rarr; directory named after the CVE the LLM was tasked with replicating. 
    - **LLM name** &rarr; contains the files generated by the LLM
    - _**exploit.py**_ &rarr; contains the exploit code
    - _**script.sh**_ &rarr; used to launch the exploit on _localhost_