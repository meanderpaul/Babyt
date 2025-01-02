import requests
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(filename='combined_vuln_test.log', level=logging.INFO)

def log_step(step_description):
    logging.info(f"{datetime.now()} - {step_description}")

def load_vulnerabilities(file_path):
    log_step(f"Loading vulnerabilities from file: {file_path}")
    with open(file_path, 'r') as file:
        vulnerabilities = file.readlines()
    log_step(f"Loaded {len(vulnerabilities)} vulnerabilities")
    return vulnerabilities

def test_idor(endpoint, param, user_ids, cookies=None):
    for user_id in user_ids:
        url = f"{endpoint}?{param}={user_id}"
        response = requests.get(url, cookies=cookies)
        
        log_step(f"Testing URL: {url}")
        log_step(f"Response Status Code: {response.status_code}")
        
        if response.status_code == 200:
            with open('vulnerability_reports/idor.txt', 'a') as report_file:
                report_file.write(f"Bug Type: IDOR\nBug Location: {url}\nDescription: IDOR vulnerability with user ID '{user_id}'\nHow to Replicate: Access URL {url} directly\nSolution: Implement proper access controls and authorization checks.\n\n")
        else:
            log_step(f"Access denied for {user_id}")

def test_xss(endpoint, param, payloads, cookies=None):
    for payload in payloads:
        url = f"{endpoint}?{param}={payload}"
        response = requests.get(url, cookies=cookies)
        
        log_step(f"Testing XSS with payload: {payload}")
        log_step(f"Response Status Code: {response.status_code}")
        
        if payload in response.text:
            with open('vulnerability_reports/xss_cut.txt', 'a') as report_file:
                report_file.write(f"Bug Type: XSS\nBug Location: {endpoint}\nDescription: XSS attempt with payload '{payload}'\nHow to Replicate: Send payload '{payload}' to parameter '{param}' at {endpoint}\nSolution: Use proper escaping and Content Security Policy (CSP).\n\n")

def test_ssrf(endpoint, param, urls, cookies=None):
    for url in urls:
        response = requests.get(f"{endpoint}?{param}={url}", cookies=cookies)
        
        log_step(f"Testing SSRF with URL: {url}")
        log_step(f"Response Status Code: {response.status_code}")
        
        if response.status_code == 200:
            with open('vulnerability_reports/ssrf.txt', 'a') as report_file:
                report_file.write(f"Bug Type: SSRF\nBug Location: {endpoint}\nDescription: SSRF attempt with URL '{url}'\nHow to Replicate: Send URL '{url}' to parameter '{param}' at {endpoint}\nSolution: Validate and sanitize URL inputs and restrict outbound connections.\n\n")

def test_lfi_rfi(endpoint, param, paths, cookies=None):
    for path in paths:
        response = requests.get(f"{endpoint}?{param}={path}", cookies=cookies)
        
        log_step(f"Testing File Inclusion with path: {path}")
        log_step(f"Response Status Code: {response.status_code}")
        
        if "sensitive_data" in response.text:
            with open('vulnerability_reports/file_inclusion.txt', 'a') as report_file:
                report_file.write(f"Bug Type: File Inclusion\nBug Location: {endpoint}\nDescription: File Inclusion attempt with path '{path}'\nHow to Replicate: Send path '{path}' to parameter '{param}' at {endpoint}\nSolution: Validate and sanitize file paths.\n\n")

def test_privilege_escalation(endpoint, param, cookies, low_privilege_cookies):
    response = requests.get(f"{endpoint}?{param}", cookies=low_privilege_cookies)
    
    log_step(f"Testing Privilege Escalation with low privilege user")
    log_step(f"Response Status Code: {response.status_code}")
    
    if response.status_code == 200:
        with open('vulnerability_reports/privilege_escalation.txt', 'a') as report_file:
            report_file.write(f"Bug Type: Privilege Escalation\nBug Location: {endpoint}\nDescription: Privilege Escalation vulnerability with low privilege user\nHow to Replicate: Access {endpoint} with low privilege cookies\nSolution: Implement role-based access controls and proper authentication.\n\n")
    else:
        log_step(f"No Privilege Escalation vulnerability detected")

def run_cut(file_path, user_ids, xss_payloads, ssrf_urls, file_paths, low_privilege_cookies):
    vulnerabilities = load_vulnerabilities(file_path)
    if not vulnerabilities:
        print(f"No vulnerabilities loaded from {file_path}")
        return

    for vuln in vulnerabilities:
        vuln_data = vuln.strip().split(',')
        endpoint = vuln_data[0]
        param = vuln_data[1]
        vuln_type = vuln_data[2]
        
        log_step(f"Escalating {vuln_type} vulnerability at {endpoint} with parameter {param}")
        
        if vuln_type == 'IDOR':
            test_idor(endpoint, param, user_ids)
        elif vuln_type == 'XSS':
            test_xss(endpoint, param, xss_payloads)
        elif vuln_type == 'SSRF':
            test_ssrf(endpoint, param, ssrf_urls)
        elif vuln_type == 'File Inclusion':
            test_lfi_rfi(endpoint, param, file_paths)
        elif vuln_type == 'Privilege Escalation':
            test_privilege_escalation(endpoint, param, {}, low_privilege_cookies)
        else:
            log_step(f"Unknown vulnerability type: {vuln_type}")

if __name__ == '__main__':
    # This part is only for standalone testing
    file_path = input("Please enter the file path for detected vulnerabilities: ")
    user_ids = ['1', '2', '3']
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    ssrf_urls = ['http://localhost:8000', 'http://example.com']
    file_paths = ['/etc/passwd', '../etc/passwd']
    low_privilege_cookies = {}  # Example low privilege cookies

    run_cut(file_path, user_ids, xss_payloads, ssrf_urls, file_paths, low_privilege_cookies)
