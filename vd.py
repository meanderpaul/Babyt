import os

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

def analyze_vulnerabilities(url_file_path, output_path):
    # Load URLs from file
    with open(url_file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    # Example vulnerability analysis logic
    vulnerabilities = []
    for url in urls:
        # Vulnerability analysis logic here, placeholder example
        vulnerabilities.append(f"Vulnerability found for URL: {url}")

    # Save analysis results
    with open(output_path, 'w') as output_file:
        output_file.write('\n'.join(vulnerabilities))
    
    print(f"Vulnerability analysis results saved to {output_path}")

def main(url_file_path, output_path, additional_tasks):
    print("Running vulnerability detection...")
    analyze_vulnerabilities(url_file_path, output_path)
    for task_script in additional_tasks:
        exec(open(task_script).read())
    print("Vulnerability Detection Completed.")

if __name__ == '__main__':
    url_file_path = get_valid_file_path("Enter the path to the URL scanner output file: ")
    output_path = input("Enter the path to the output file for vulnerability analysis: ").strip()
    main(url_file_path, output_path, [])
