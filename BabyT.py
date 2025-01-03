import ve
import cut
import vd
import os
import url_scanner

def generate_final_report(project_output_directory):
    report_content = []
    for root, _, files in os.walk(project_output_directory):
        for file in files:
            if file.endswith('.txt'):
                with open(os.path.join(root, file), 'r') as f:
                    report_content.append(f.read())
    
    final_report_path = os.path.join(project_output_directory, 'final_report.txt')
    with open(final_report_path, 'w') as final_report:
        final_report.write('\n\n'.join(report_content))
    
    print(f"Final report generated: {final_report_path}")

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

def get_valid_output_path(prompt, default_filename, project_output_directory):
    while True:
        file_path = input(prompt).strip()
        
        # If the provided path is a directory
        if os.path.isdir(file_path):
            file_path = os.path.join(file_path, default_filename)
            print(f"Directory provided. Output file will be saved as: {file_path}")
            return file_path
        
        # If the provided file path is valid
        dir_path = os.path.dirname(file_path)
        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            print("Output location accepted.")
            return file_path
        else:
            print("Invalid output location. Please enter the file path again.")

def main():
    project_output_directory = '/mnt/c/Users/Paulj/Documents/awf/'
    
    # Ensure the project output directory exists
    if not os.path.exists(project_output_directory):
        os.makedirs(project_output_directory)
        print(f"Created project output directory: {project_output_directory}")
    else:
        print(f"Using existing project output directory: {project_output_directory}")

    vd_completed = False
    ve_completed = False
    cut_completed = False

    while True:
        print("Choose an option:")
        print("1. URL Scanner")
        print("2. Vulnerability Detection")
        print("3. Vulnerability Escalation")
        print("4. Combined Vulnerability Test")
        print("5. Exit")
        
        choice = input("Enter your choice: ").strip()
        
        if choice == '1':
            print("Choose the input method:")
            print("1. Enter file path containing URLs")
            print("2. Enter a single URL")
            input_choice = input("Enter your choice: ").strip()
            
            if input_choice == '1':
                input_file = get_valid_file_path("Enter the path to the input file containing URLs: ")
                output_file = os.path.join(project_output_directory, "url_scan_output.txt")
                url_scanner.scan_urls(input_file, output_file)
            elif input_choice == '2':
                url = input("Enter the URL: ").strip()
                output_file = os.path.join(project_output_directory, "url_scan_output.txt")
                with open("temp_urls.txt", 'w') as temp_file:
                    temp_file.write(url)
                url_scanner.scan_urls("temp_urls.txt", output_file)
                os.remove("temp_urls.txt")
            else:
                print("Invalid choice. Please try again.")
            
            print("URL Scanner has been completed.")
        
        elif choice == '2':
            print("Choose the source for URL data:")
            print("1. Use URL scanner output file")
            print("2. Enter file path for URL data")
            url_data_choice = input("Enter your choice: ").strip()

            if url_data_choice == '1':
                url_file_path = os.path.join(project_output_directory, "url_scan_output.txt")
            elif url_data_choice == '2':
                url_file_path = get_valid_file_path("Enter the path to the URL data file: ")
            else:
                print("Invalid choice. Please try again.")
                continue

            output_file = os.path.join(project_output_directory, "vd_output.txt")
            additional_tasks = []

            while True:
                run_more_tasks = input("Do you want to run additional tasks? (y/n/exit): ").strip().lower()
                if run_more_tasks in ['yes', 'y']:
                    task_script = get_valid_file_path("Enter the path to the Python script for the additional task: ")
                    additional_tasks.append(task_script)
                elif run_more_tasks in ['no', 'n']:
                    break
                elif run_more_tasks == 'exit':
                    print("Exiting the program.")
                    return
                else:
                    print("Invalid input. Please enter 'y', 'n', or 'exit'.")

            vd.main(url_file_path, output_file, additional_tasks)
            vd_completed = True
            print("Vulnerability Detection has been completed.")
            
            while True:
                load_into_ve = input("Would you like to load the output file into ve.py? (y/n/exit): ").strip().lower()
                if load_into_ve in ['yes', 'y']:
                    ve_input_file = output_file
                    break
                elif load_into_ve in ['no', 'n']:
                    ve_input_file = get_valid_file_path("Please enter the file path for detected vulnerabilities: ")
                    break
                elif load_into_ve == 'exit':
                    print("Exiting the program.")
                    return
                else:
                    print("Invalid input. Please enter 'y', 'n', or 'exit'.")
        
        elif choice == '3' and vd_completed:
            check_docs = input("Check for document access? (yes/no): ").lower() == 'yes'
            check_user_data = input("Check for user data access? (yes/no): ").lower() == 'yes'
            ve.run_ve(ve_input_file, check_docs, check_user_data)
            ve_completed = True
            print("Vulnerability Escalation has been completed.")
            
            while True:
                load_into_cut = input("Would you like to load the report into cut.py? (y/n/exit): ").strip().lower()
                if load_into_cut in ['yes', 'y']:
                    cut_input_file = os.path.join(project_output_directory, 'vulnerability_escalation_report.log')
                    break
                elif load_into_cut in ['no', 'n']:
                    cut_input_file = get_valid_file_path("Please enter the file path for detected vulnerabilities: ")
                    break
                elif load_into_cut == 'exit':
                    print("Exiting the program.")
                    return
                else:
                    print("Invalid input. Please enter 'y', 'n', or 'exit'.")
        
        elif choice == '4' and ve_completed:
            user_ids = ['1', '2', '3']
            xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
            ssrf_urls = ['http://localhost:8000', 'http://example.com']
            file_paths = ['/etc/passwd', '../etc/passwd']
            low_privilege_cookies = {}  # Example low privilege cookies
            cut.run_cut(cut_input_file, user_ids, xss_payloads, ssrf_urls, file_paths, low_privilege_cookies)
            cut_completed = True
            print("Combined Vulnerability Test has been completed.")
        
        elif choice == '5' or cut_completed:
            if cut_completed:
                generate_final_report(project_output_directory)
            print("Exiting...")
            break
        
        else:
            print("Invalid choice or script sequence not followed. Please try again.")

if __name__ == '__main__':
    main()
