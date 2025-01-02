import subprocess
import requests
from bs4 import BeautifulSoup

# Function to perform DNS enumeration using dnsenum
def dns_enum(url):
    try:
        # Call dnsenum and capture the output
        result = subprocess.run(['dnsenum', '--enum', url], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

# Function to search for plain text API keys in a domain and subdomain
def search_api_keys(domain):
    api_keys = []
    try:
        # Perform a simple HTTP request to the domain
        response = requests.get(f"http://{domain}")
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Search for potential API keys in the HTML content
        for script_tag in soup.find_all('script'):
            if 'api_key' in script_tag.text:
                api_keys.append(script_tag.text)
        
        return api_keys
    except Exception as e:
        return str(e)

# Function to test for XSS vulnerabilities
def test_xss(domain):
    xss_payload = "<script>alert('XSS');</script>"
    xss_results = []
    try:
        # Perform a simple HTTP request to the domain
        response = requests.get(f"http://{domain}")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Test XSS in forms
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()

            # Construct the form submission URL
            target_url = f"http://{domain}{action}"
            form_data = {input_tag.get('name'): xss_payload for input_tag in form.find_all('input')}
            
            if method == 'post':
                form_response = requests.post(target_url, data=form_data)
            else:
                form_response = requests.get(target_url, params=form_data)
                
            if xss_payload in form_response.text:
                xss_results.append((target_url, "Success", "XSS payload executed"))
            else:
                xss_results.append((target_url, "Fail", "XSS payload did not execute"))

        return xss_results
    except Exception as e:
        return [(domain, "Error", str(e))]

# Function to compile identified vulnerabilities into a single file
def compile_vulnerabilities(dns_results, api_results, xss_results, summary_output_path):
    with open(summary_output_path, 'w') as summary_file:
        summary_file.write("Identified Vulnerabilities Summary\n")
        
        # Add API keys and their URLs
        summary_file.write("\nAPI Keys:\n")
        for url, keys in api_results.items():
            if keys:
                summary_file.write(f"URL: {url}\n")
                for key in keys:
                    summary_file.write(f"API Key: {key}\n")
        
        # Add XSS vulnerabilities
        summary_file.write("\nXSS Vulnerabilities:\n")
        for url, results in xss_results.items():
            if results:
                summary_file.write(f"URL: {url}\n")
                for result in results:
                    summary_file.write(f"Test URL: {result[0]}\nOutcome: {result[1]}\nDescription: {result[2]}\n")
                    summary_file.write("\n")

# Ask the user for the output path
base_output_path = input("Please enter the base output path (e.g., /path/to/): ")

# Initialize dictionaries to store results
dns_results = {}
api_results = {}
xss_results = {}

# Open the input file with URLs
with open('urls.txt', 'r') as input_file:
    # Read each line (URL) from the file
    urls = input_file.readlines()

# Open the DNS enumeration output file in append mode
dns_output_path = base_output_path + "dns_enum_results.txt"
with open(dns_output_path, 'a') as dns_output_file:
    # Process each URL
    for url in urls:
        # Remove any leading/trailing whitespace (like newline characters)
        url = url.strip()

        # Perform DNS enumeration and get the result
        dns_enum_result = dns_enum(url)
        
        # Store the DNS enumeration result
        dns_results[url] = dns_enum_result

        # Write the URL and its DNS enumeration result to the DNS output file
        dns_output_file.write(f"URL: {url}\nDNS Enumeration Result:\n{dns_enum_result}\n\n")

# Open the API keys output file in append mode
api_output_path = base_output_path + "api_keys_results.txt"
with open(api_output_path, 'a') as api_output_file:
    # Process each URL
    for url in urls:
        # Remove any leading/trailing whitespace (like newline characters)
        url = url.strip()

        # Ask the user if they want to search for API keys in the domain and subdomain
        search_confirmation = input(f"Do you want to search for plain text API keys in {url} (yes/no)? ").strip().lower()
        
        if search_confirmation == 'yes':
            # Search for API keys in the domain and subdomain
            api_keys = search_api_keys(url)
            
            # Store the API keys
            api_results[url] = api_keys

            # Write the API keys and their details to the API keys output file
            if api_keys:
                api_output_file.write(f"URL: {url}\nAPI Keys Found:\n")
                for api_key in api_keys:
                    api_output_file.write(f"{api_key}\n")
                api_output_file.write("\n")
            else:
                api_output_file.write(f"URL: {url}\nNo API keys found.\n\n")

# Open the XSS investigation output file in append mode
xss_output_path = base_output_path + "xss_investigation_results.txt"
with open(xss_output_path, 'a') as xss_output_file:
    # Process each URL
    for url in urls:
        # Remove any leading/trailing whitespace (like newline characters)
        url = url.strip()

        # Ask the user if they want to proceed with XSS investigation
        xss_confirmation = input(f"Do you want to proceed with XSS investigation in {url} (yes/no)? ").strip().lower()
        
        if xss_confirmation == 'yes':
            # Test for XSS vulnerabilities
            xss_results_for_url = test_xss(url)
            
            # Sort XSS results: success at the top
            xss_results_for_url.sort(key=lambda x: x[1], reverse=True)
            
            # Store the XSS results
            xss_results[url] = xss_results_for_url

            # Write the XSS results to the XSS investigation output file
            xss_output_file.write(f"XSS Investigation Results for {url}:\n")
            for result in xss_results_for_url:
                xss_output_file.write(f"URL: {result[0]}\nOutcome: {result[1]}\nDescription: {result[2]}\n\n")

# Prompt the user to create a summary file if vulnerabilities are found
if api_results or xss_results:
    create_summary = input("Do you want to create a single file with known vulnerabilities (yes/no)? ").strip().lower()
    if create_summary == 'yes':
        summary_output_path = base_output_path + "vulnerabilities_summary.txt"
        compile_vulnerabilities(dns_results, api_results, xss_results, summary_output_path)
        print(f"Summary file created at {summary_output_path}")
else:
    print("No vulnerabilities were identified.")

# Optional: Confirm completion
print(f"All URLs processed and results written to:\n{dns_output_path}\n{api_output_path}\n{xss_output_path}")
