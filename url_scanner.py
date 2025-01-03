import os
import sublist3r
from urllib.parse import urlparse, urlunparse

def get_valid_file_path(prompt):
    while True:
        file_path = input(prompt).strip()
        if os.path.exists(file_path):
            print("File loaded and accepted.")
            return file_path
        elif os.path.exists(f"{file_path}.txt"):
            file_path = f"{file_path}.txt"
            print("File loaded and accepted.")
            return file_path
        else:
            print("File not found. Please enter the file path again.")

def ensure_correct_scheme(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = 'http://' + url
        parsed_url = urlparse(url)
    return urlunparse(parsed_url._replace(scheme='http'))

def scan_urls(file_path, output_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    results = []
    for url in urls:
        url = ensure_correct_scheme(url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        try:
            # Perform subdomain enumeration using Sublist3r with selected engines
            subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=["virustotal", "threatcrowd", "certspotter"])
            results.append(f"Subdomains for {domain}:")
            results.extend(subdomains)
        except Exception as e:
            results.append(f"Error occurred during subdomain enumeration for {domain}: {e}")

        # Check for other elements attached to the URL
        if parsed_url.path or parsed_url.query:
            results.append(f"Path and query found: {parsed_url.path} {parsed_url.query}")

    with open(output_path, 'w') as output_file:
        output_file.write('\n'.join(results))

    print(f"Scan results saved to {output_path}")

def main():
    # input_file = get_valid_file_path("Enter the path to the input file containing URLs: ")
    input_file = 'urls.txt'  # Replace with your fixed input file path for testing
    output_file = '/mnt/c/Users/Paulj/Documents/awf/url_scan_output.txt'  # Fixed output location

    scan_urls(input_file, output_file)

if __name__ == '__main__':
    main()
