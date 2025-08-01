"""Custom web search function."""

import os
import re
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

# My modules
from prompts import (
    LLM_SUMMARIZE_WEBPAGE_PROMPT, 
    GET_DOCKER_SERVICES_PROMPT,
)
from configuration import langfuse_handler, WebSearchResult


class ContextGenerator:
    def __init__(self, n_documents=10, text_len_threshold=50, verbose=False):
        self.verbose = verbose
        self.n_documents = n_documents
        self.text_len_threshold = text_len_threshold

        # Retrieve the Google CSE key and ID from environment variables
        self.google_api_key = os.getenv("GOOGLE_API_KEY")
        self.google_cse_id = os.getenv("GOOGLE_CSE_ID")

        if not self.google_api_key or not self.google_cse_id:
            raise ValueError("GOOGLE_API_KEY and GOOGLE_CSE_ID must be set as environment variables.")

    def is_text_clean(self, text):
        """Check if the given text is valid UTF-8 encoded content by trying to encode and decode it."""
        try:
            text.encode("utf-8").decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    def extract_and_clean_content(self, url):
        """For each URL that has been found by the Google API:
        - Check if the content is HTML
        - Remove script and style tags from the page
        - Extract the text from the page
        - Evaluate if enough data has been extracted"""
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                if self.verbose:
                    print(f"\t[SKIP] {url} - Response code: {response.status_code}")
                return None
            
            content_type = response.headers.get("Content-Type", "")
            if not content_type.startswith("text/html"):
                if self.verbose:
                    print(f"\t[SKIP] {url} - Content-Type not valid: {content_type}")
                return None

            # Parses the HTML using Python's built-in "html.parser" engine
            # & transform the raw HTML (i.e. response.content) into a tree-like object (soup) that represents the structure of the web page
            soup = BeautifulSoup(response.content, "html.parser")

            # Remove <script> and <style> elements, as these do not contribute to the main textual content
            for script_or_style in soup(["script", "style"]):
                script_or_style.decompose()

            # Extract the text from the soup object (ignoring tags)
            text = soup.get_text()
            # Removes excessive whitespaces
            text = re.sub(r"\s+", " ", text).strip()

            # If not enough text (e.g. 50) has been extracted, or if the text is not clean, skip this URL
            if len(text) < self.text_len_threshold or not self.is_text_clean(text):
                return None

            return text

        except Exception as e:
            if self.verbose:
                print(f"\t[ERROR] Failed to fetch {url}: {e}")
            return None

    def get_web_search_results(self, cve_id):
        """Use the Google Custom Search JSON API to retrieve data from the web."""
        print("\tSearching with Google API...")
        documents = []
        query = f"{cve_id}"

        # Gather data from 'n_documents'
        params = {
            "q": query,
            "key": self.google_api_key,
            "cx": self.google_cse_id,
            # The index of the first result to return.
            # The default number of results per page is 10, so 'start=11' would start at the top of the second page of results.
            # Only the first page (i.e, 10 results) are analysed
            "start": 1,
        }

        try:
            response = requests.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=10)
            # Raise an exception if the GET request was unsuccessful
            response.raise_for_status()
            results = response.json()

        # Catch the exception
        except Exception as e:
            if self.verbose:
                print(f"\t[GOOGLE SEARCH ERROR] {e}")
            return []

        items = results.get("items", [])
        for item in tqdm(items, disable=not self.verbose, leave=False):
            # Get the URL of the web page to extract its content
            url = item.get("link")
            if not url:
                continue

            print(f"\tProcessing content from {url}")

            # Extracting data from the URL
            doc = self.extract_and_clean_content(url)
            if doc:
                documents.append((url, doc))

            # If enough data has been collected, break the loop
            if len(documents) >= self.n_documents:
                break

        return documents

    def summarize_web_page(self, doc, cve_id, character_limit: int = 1000, max_chars: int = 450000) -> str:
        # Log when the content is too long, to evaluate how many times it happens and what you are losing
        if len(doc) > max_chars:
            try:
                with open("long_web_pages.log", "a", encoding="utf-8") as logf:
                    logf.write("\n\n========== [URL EXCEEDED LIMIT] ==========\n")
                    logf.write(f"CVE ID: {cve_id}\n")
                    logf.write(f"Document length: {len(doc)} characters\n")
                    logf.write(f"Document content:\n{doc}\n")

            except Exception as log_error:
                if self.verbose:
                    print(f"\t[LOGGING ERROR] {log_error}")

        try:
            # Create message history for the LLM
            messages = [
                # Passing the system prompt to the LLM
                SystemMessage(content=LLM_SUMMARIZE_WEBPAGE_PROMPT.format(cve_id=cve_id, character_limit=character_limit)),
                # Passing the content of the web page as a user message
                HumanMessage(content=f"Here is the content you have to summarise: {doc[:max_chars]}"),
            ]
            # Initialize the LLM with OpenAI's GPT-4o model
            llm_model = ChatOpenAI(model="gpt-4o", temperature=0, max_retries=2)
            
            # Invoke the LLM to summarize the web page content
            response = llm_model.invoke(messages, config={"callbacks": [langfuse_handler]})
            if self.verbose:
                print(f"\tSummary: {response.content.strip()}")
                
            # Count input and output tokens
            input_token_count = response.response_metadata.get("token_usage", {}).get("prompt_tokens", 0)
            output_token_count = response.response_metadata.get("token_usage", {}).get("completion_tokens", 0)
            return (response.content.strip(), input_token_count, output_token_count)

        except Exception as e:
            if self.verbose:
                print(f"\t[LLM WEB PAGE SUMMARY ERROR] {e}")
            return (None, 0, 0)

    def summarize_web_search(self, urls, summaries, cve_id, max_chars: int = 450000):
        try:
            # Concatenate the summaries
            conc_sum = ""
            for url, summary in zip(urls, summaries):
                conc_sum += f"Source: {url}\n{summary}\n\n"
                
            if self.verbose:
                print(f"\n\n\tSUMMARY CONCATENATION\n\t{conc_sum}")
                
            # Create message history for the LLM
            messages = [
                # Passing the system prompt to the LLM
                SystemMessage(content=GET_DOCKER_SERVICES_PROMPT.format(cve_id=cve_id)),
                # Passing the content of the web search as a user message
                HumanMessage(content=f"Use the following knowledge to achieve your task: {conc_sum[:max_chars]}"),
            ]
            # Initialize the LLM with OpenAI's GPT-4o model
            llm_model = ChatOpenAI(model="gpt-4o", temperature=0, max_retries=2)
            
            # Set the LLM to return a structured output from web search
            docker_services_llm = llm_model.with_structured_output(WebSearchResult)
            
            # Invoke the LLM to summarize the web search content
            formatted_response = docker_services_llm.invoke(messages, config={"callbacks": [langfuse_handler]})
            
            if self.verbose:
                print(f"\n\n\tFORMATTED WEB SEARCH RESPONSE\n\t{formatted_response}")
            
            return formatted_response

        except Exception as e:
            if self.verbose:
                print(f"\t[LLM WEB SEARCH SUMMARY ERROR] {e}")
    
    def get_cve_from_nist_api(self, cve_id):
        """Retrieve CVE data from NIST's NVE Database using the API."""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
    
            vuln = data.get("vulnerabilities", [])[0]["cve"]
            description = vuln["descriptions"][0]["value"]
    
            return (url, description)
    
        except Exception as e:
            return f"Failed to retrieve CVE data from NIST: {str(e)}"
            
    
    def invoke(self, cve_id):
        # Retrieve CVE data from the web
        results = self.get_web_search_results(cve_id)
        
        # Retrieve CVE information from NIST
        nist_data = self.get_cve_from_nist_api(cve_id)
        if isinstance(nist_data, tuple):
            results.append(nist_data)
        elif self.verbose:
            print(f"\t[NIST API ERROR] {nist_data}")

        if self.verbose:
            print(f"\tFetched {len(results)} documents")

        if not results:
            return "No documents retrieved from web search."

        # Count tokens and summarize the content of each web page
        input_token_count = 0
        output_token_count = 0
        summary_dict = {}
        for url, doc in tqdm(results, desc=f"Summarizing", disable=not self.verbose, leave=False):
            (summary, inputCount, outputCount) = self.summarize_web_page(doc=doc, cve_id=cve_id)
            input_token_count += inputCount
            output_token_count += outputCount
            if summary:
                summary_dict[url] = summary

        if not summary_dict:
            return "No relevant summaries could be extracted from the search results. Try refining your query."

        summaries = list(summary_dict.values())
        urls = list(summary_dict.keys())
        
        formatted_response = self.summarize_web_search(urls, summaries, cve_id)
        return (formatted_response, input_token_count, output_token_count)
    

def web_search_func(cve_id: str, verbose: bool = True):
    inCount = 0
    outCount = 0
    
    try:
        rag_model = ContextGenerator(n_documents=10, verbose=verbose)
        (formatted_response, inCount, outCount) = rag_model.invoke(cve_id)
    except Exception as e:
        formatted_response = f"An error occurred during the web search: {str(e)}"
        
    return (formatted_response, inCount, outCount)
