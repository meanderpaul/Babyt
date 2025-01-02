# BabyT.py

import ve
import cut
import vd
import os

def generate_final_report():
    report_content = []
    for root, _, files in os.walk('vulnerability_reports'):
        for file in files:
            if file.endswith('.txt'):
                with open(os.path.join(root, file), 'r') as f:
                    report_content.append(f.read())
    
    final_report_path = 'vulnerability_reports/final_report.txt'
    with open(final_report_path, 'w') as final_report:
        final_report.write('\n\n'.join(report_content))
    
    print(f"Final report generated: {final_report_path}")

def main():
    vd_completed = False
    ve_completed = False
    cut_completed = False

    while True:
        print("Choose a script to run:")
        if not vd_completed:
            print("1. vd.py (must be run first)")
        elif not ve_completed:
            print("2. ve.py (must be run after vd.py)")
        else:
            print("3. cut.py (optional but recommended to run after ve.py)")
        
        print("4. Exit")
        
        choice = input("Enter your choice: ").strip()
        
        if choice == '1' and not vd_completed:
            input_file = input("Enter the path to the input file: ")
            output_file = input("Enter the path to the output file: ")
            additional_tasks = []

            while True:
                run_more_tasks = input("Do you want to run additional tasks? (yes/no): ").strip().lower()
                if run_more_tasks == 'yes':
                    task_script = input("Enter the path to the Python script for the additional task: ")
                    additional_tasks.append(task_script)
                else:
                    break

            vd.main(input_file, output_file, additional_tasks)
            vd_completed = True
            print("vd.py has been completed.")
            
            if input("Would you like to load the output file into ve.py? (yes/no): ").strip().lower() == 'yes':
                ve_input_file = output_file
            else:
                ve_input_file = input("Please enter the file path for detected vulnerabilities: ")
        
        elif choice == '2' and vd_completed and not ve_completed:
            check_docs = input("Check for document access? (yes/no): ").lower() == 'yes'
            check_user_data = input("Check for user data access? (yes/no): ").lower() == 'yes'
            ve.run_ve(ve_input_file, check_docs, check_user_data)
            ve_completed = True
            print("ve.py has been completed.")
            
            if input("Would you like to load the report into cut.py? (yes/no): ").strip().lower() == 'yes':
                cut_input_file = 'vulnerability_reports/vulnerability_escalation_report.log'
            else:
                cut_input_file = input("Please enter the file path for detected vulnerabilities: ")
        
        elif choice == '3' and ve_completed:
            user_ids = ['1', '2', '3']
            xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
            ssrf_urls = ['http://localhost:8000', 'http://example.com']
            file_paths = ['/etc/passwd', '../etc/passwd']
            low_privilege_cookies = {}  # Example low privilege cookies
            cut.run_cut(cut_input_file, user_ids, xss_payloads, ssrf_urls, file_paths, low_privilege_cookies)
            cut_completed = True
            print("cut.py has been completed.")
        
        elif choice == '4' or cut_completed:
            if cut_completed:
                generate_final_report()
            print("Exiting...")
            break
        
        else:
            print("Invalid choice or script sequence not followed. Please try again.")

if __name__ == '__main__':
    main()
