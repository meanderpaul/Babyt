import os

def log_step(step_description):
    with open('vulnerability_reports/vd_report.txt', 'a') as report_file:
        report_file.write(f"{step_description}\n")

def run_task(task_script):
    # Ensure the script exists before trying to run it
    if os.path.exists(task_script):
        os.system(f'python {task_script}')
        log_step(f"Ran additional task: {task_script}")
    else:
        log_step(f"Task script {task_script} not found.")

def copy_content(input_file, output_file):
    # Placeholder task - Just copying content from input to output
    with open(input_file, 'r') as infile:
        content = infile.read()
    
    with open(output_file, 'w') as outfile:
        outfile.write(content)
    
    log_step(f"Copied content from {input_file} to {output_file}")

def main(input_file, output_file, additional_tasks):
    # Copy content as the initial task
    copy_content(input_file, output_file)
    
    # Run additional tasks
    for task_script in additional_tasks:
        run_task(task_script)
    
    print("vd.py tasks completed.")

if __name__ == '__main__':
    # This part is only for standalone testing
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

    main(input_file, output_file, additional_tasks)
