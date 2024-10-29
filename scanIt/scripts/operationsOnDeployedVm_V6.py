import paramiko
import mysql.connector
from mysql.connector import Error
import winrm
import time
import sys
import os
from dotenv import load_dotenv
import logging
import requests
import json


# Load the .env file
load_dotenv()


logging.basicConfig(
    filename='operatonsOnDeployedVM.log',  
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")

mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': MYSQL_HOST,
    'database': 'vm_template_scan',
    'port': '3306'
}

# Jira parameters 
JIRA_BEARER_TOKEN = os.getenv("JIRA_BEARER_TOKEN")
# jira_base_url = "https://jira.nutanix.com/"
jira_base_url = "https://jiradev.nutanix.com/"
jira_email = "ivan.perkovic@nutanix.com"


# Function for adding comment in Jira case
def add_comment_to_jira_task(task_key, comment):
    try:
        jira_headers = {
            "Authorization": f"Bearer {JIRA_BEARER_TOKEN}",
            "Content-Type": "application/json"
        }

        comment_payload = {
            "body": comment
        }

        comment_url = f"{jira_base_url}/rest/api/2/issue/{task_key}/comment"
        response = requests.post(comment_url, headers=jira_headers, data=json.dumps(comment_payload), timeout=15)

        if response.status_code == 201:
            print("Comment added successfully!")
        else:
            print(f"Failed to add comment: {response.status_code}, {response.text}")

    except requests.Timeout:
        print("The request timed out!")

    except requests.ConnectionError:
        print("A connection error occurred!")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")


def insert_workflow_state(process_id, description, state, stage, source_url):
    conn = mysql.connector.connect(**mysql_config)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO vm_template_scan.workflow_state (process_ID, description, state, image_url, stage) VALUES (%s, %s, %s, %s, %s)',
        (process_id, description, state, source_url, stage)
    )
    conn.commit()
    cursor.close()


# Function that adds information to the DB (waitForFlexera table)
def log_to_database_waitForFlexera(process_id, vm_hostname, vm_uuid, vm_ip, source_url, new_jira_task):
    try:
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()

        # Insert new record or update the existing record if process_ID already exists
        cursor.execute(
            '''
            INSERT INTO vm_template_scan.waitForFlexera (process_ID, vm_hostname, vm_uuid, vm_ip, source_url, new_jira_task) 
            VALUES (%s, %s, %s, %s, %s, %s) 
            ON DUPLICATE KEY UPDATE
            vm_hostname = COALESCE(%s, vm_hostname),
            vm_uuid = COALESCE(%s, vm_uuid),
            vm_ip = COALESCE(%s, vm_ip),
            source_url = COALESCE(%s, source_url),
            new_jira_task = COALESCE(%s, new_jira_task)
            ''',
            (process_id, vm_hostname, vm_uuid, vm_ip, source_url, new_jira_task, 
             vm_hostname, vm_uuid, vm_ip, source_url, new_jira_task)
        )
        
        conn.commit()

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def log_to_database_rawInstallations(process_id, packages, source_url):
    try:
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()

        # Insert new record or update the existing record if process_ID already exists
        cursor.execute(
            '''
            INSERT INTO vm_template_scan.raw_Installations (process_ID, packages, source_url) 
            VALUES (%s, %s, %s) 
            ON DUPLICATE KEY UPDATE
            packages = COALESCE(VALUES(packages), packages),
            source_url = COALESCE(VALUES(source_url), source_url)
            ''',
            (process_id, packages, source_url)
        )
        
        conn.commit()
    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def execute_command(ssh, command, use_sudo=False, use_pty=False, sudo_password=None):
    # Get the username used for SSH connection
    ssh_username = ssh.get_transport().get_username()
    print(f"Executing command '{command}' as user '{ssh_username}'")

    if use_sudo:
        if sudo_password is None:
            raise ValueError("sudo_password must be provided when use_sudo is True")
        # command = f"echo {sudo_password} | sudo -S {command}"
        command = f"sudo -S {command}"

    stdin, stdout, stderr = ssh.exec_command(command, get_pty=use_pty)

    if use_sudo:
        stdin.write(sudo_password + '\n')
        stdin.flush()

    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    exit_code = stdout.channel.recv_exit_status()

    # Handle command success/failure
    if exit_code != 0:
        print(f"Command failed with exit code {exit_code}: {error}")
        return output, error, exit_code

    print(f"Command '{command}' executed successfully.")
    return output, None, exit_code


def retry_commands_with_winrm(ip, username, password, new_hostname, process_id, source_url, new_jira_task):
    try:
        session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password))

        connection_result = session.run_cmd('whoami')
        # Check if WinRM connection succeeded
        if connection_result.status_code == 0:
            print(f"WinRM connection to {ip} established successfully with username: {username}.")
            print(f"Logged in as: {connection_result.std_out.decode().strip()}")
            insert_workflow_state(process_id, f"WinRM connection to {ip} established successfully with username: {username}.", "SUCCEEDED", "Commands execution", source_url)
            
            # Check PowerShell version
            try:
                ps_version_command = "powershell -Command \"$PSVersionTable.PSVersion.Major\""
                response = session.run_cmd(ps_version_command)

                if response.status_code == 0:
                    ps_version = int(response.std_out.strip())
                    print(f"PowerShell version on target: {ps_version}")
                    insert_workflow_state(process_id, f"PowerShell version on target: {ps_version}.", "INFO", "Commands execution", source_url)
                    
                else:
                    print(f"Failed to retrieve PowerShell version, status code: {response.status_code}. Proceeding without version check. Commands for PS > 5 version will be executed.")
                    print(f"Error: {response.std_err.decode()}")
                    ps_version = 5  # if version check fails, default to 5

                    insert_workflow_state(process_id, f"Failed to retrieve PowerShell version, status code: {response.status_code}. Error: {response.std_err.decode()}. Commands for PS > 5 version will be executed.", "INFO", "Commands execution", source_url)
            
            except Exception as version_check_e:
                    print(f"Exception during PowerShell version check: {version_check_e}. Proceeding with commands for  PS > 5 version")
                    ps_version = 5
                    
                    insert_workflow_state(process_id, f"Exception during PowerShell version check: {version_check_e}. Proceeding with commands for  PS > 5 version", "INFO", "Commands execution", source_url)
                
            if ps_version < 5:
                print(f"Using fallback commands due to PowerShell version < 5")
                remaining_commands = [
                    "hostname",
                    "powershell -Command \"(New-Object System.Net.WebClient).DownloadFile('http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip', 'C:\\flexera_prodagent.zip')\"",
                    "powershell -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::ExtractToDirectory('C:\\flexera_prodagent.zip', 'C:\\flexera_prodagent')\"",
                    'cd C:\\flexera_prodagent\\prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                    # "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                ]

            else:
                print(f"Using standard commands for PowerShell version >= 5")
                remaining_commands = [
                    "hostname",
                    "powershell Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile 'C:\\flexera_prodagent.zip'",
                    "powershell Expand-Archive -Path 'C:\\flexera_prodagent.zip' -DestinationPath 'C:\\flexera_prodagent'",
                    'cd C:\\flexera_prodagent\\prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                    # "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                ]

            # Change the hostname and reboot with error handling
            try:
                print(f"Changing hostname to {new_hostname}...")
                response = session.run_cmd(f'powershell Rename-Computer -NewName "{new_hostname}" -Force')
                if response.status_code != 0:
                    print(f"PowerShell command failed. Attempting to change hostname using WMIC...")
                    insert_workflow_state(process_id, f"PowerShell command Rename-Computer failed. Attempting to change hostname using WMIC..." , "FAILED", "Commands execution", source_url)
                    wmic_command = f'WMIC computersystem where name="%COMPUTERNAME%" call rename name="{new_hostname}"'
                    response = session.run_cmd(wmic_command)
                    if response.status_code != 0:
                        raise Exception(f"Failed to change hostname using WMIC. Status code: {response.status_code}. Error: {response.std_err.decode()}")

                # Reboot immediately
                print("Rebooting the machine...")
                response = session.run_cmd("powershell Shutdown /r /t 0")
                if response.status_code != 0:
                    raise Exception(f"Failed to initiate reboot. Status code: {response.status_code}. Error: {response.std_err.decode()}")

                insert_workflow_state(process_id, f"Hostname changed to {new_hostname} and reboot initiated successfully.", "SUCCEEDED", "Commands execution", source_url)

            except Exception as hostname_reboot_error:
                print(f"Error during hostname change or reboot: {hostname_reboot_error}")
                insert_workflow_state(process_id, f"Error during hostname change or reboot: {hostname_reboot_error}", "FAILED", "Commands execution", source_url)

            # Wait for the VM to become accessible again
            print(f"Waiting for the machine to become accessible...")
            insert_workflow_state(process_id, f"Waiting for the machine to become accessible...", "INFO", "Commands execution", source_url)
            time.sleep(30)  # Wait a bit before retrying
            accessible = False
            for _ in range(5):  # Retry 5 times
                try:
                    # Attempt to reconnect using WinRM
                    session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password))
                    # Check if the session is alive by running a simple command
                    test_command = "powershell Get-Process"  # Just an example command
                    response = session.run_cmd(test_command)
                    
                    if response.status_code == 0:
                        accessible = True
                        print("Machine is accessible again.")
                        insert_workflow_state(process_id, f"Machine is accessible again. Execution of the remaining commands continues", "INFO", "Commands execution", source_url)
                        break
                except Exception:
                    print("Machine not accessible yet. Retrying...")
                    insert_workflow_state(process_id, f"Machine not accessible yet. Retrying...", "INFO", "Commands execution", source_url)
                    time.sleep(15)  # Wait before retrying

            if not accessible:
                print("Machine did not become accessible in the expected time.")
                insert_workflow_state(process_id, "Machine did not become accessible after reboot. Unable to continue installing Flexera agent.Terminating proces. ", "FAILED", "Commands execution", source_url)
                return

            # Execute remaining commands after reboot
            print("Executing remaining commands...")
            session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password))
            all_commands_successful = True
            for command in remaining_commands:
                response = session.run_cmd(command)

                if response.status_code != 0:
                    print(f"Failed to execute command '{command}', status code: {response.status_code}")
                    print(f"Error of '{command}': {response.std_err.decode()}")
                    insert_workflow_state(process_id, f"Failed to execute command '{command} via WinRM: {response.std_err.decode()}'", "FAILED", "Commands execution", source_url)
                    all_commands_successful = False
                else:
                    print(f"Command '{command}' executed successfully")
                    print(f"Output of '{command}': {response.std_out.decode().strip()}")
                    insert_workflow_state(process_id, f"Command '{command}' executed successfully with username: {username} via WinRM. Command output {response.std_out.decode().strip()}", "SUCCEEDED", "Commands execution", source_url)

                    # Log hostname for future Flexera checks
                    if command == 'hostname':
                        try:
                            # Attempt to log the data
                            log_to_database_waitForFlexera(process_id, response.std_out.decode().strip(), None, None, None, None)
                        except Exception as e:
                            # Handle the exception and continue
                            print(f"An error occurred while logging to the database: {e}")
                            insert_workflow_state(process_id, f"An error occurred while logging to the database: {e}. Process will continue, but check <log_to_database_waitForFlexera> function or <waitForFlexera> table in DB", "FAILED", "Commands execution", source_url)
                
                time.sleep(45)

            if all_commands_successful:
                print("All commands executed successfully via WinRM. Returning.")
                insert_workflow_state(process_id, f"All commands executed successfully via WinRM", "SUCCEEDED", "Commands execution", source_url)
                insert_workflow_state(process_id, f"Waiting for the machine to appear in Flexera and check report.", "INFO", "Commands execution", source_url)
                if new_jira_task:
                    add_comment_to_jira_task(new_jira_task, f"All commands executed successfully via WinRM. Flexera agent installed. Waiting for the machine to appear in Flexera and check report.")
                return
            else:
                add_comment_to_jira_task(new_jira_task, f"Not all commands were executed completely via WinRM. Check the status and services on VM.")
        else:
            print(f"Failed to establish WinRM connection to {ip} with username: {username}. Error: {connection_result.std_err.decode()}")
            insert_workflow_state(process_id, f"WinRM connection to {ip} failed with username: {username}. Error: {connection_result.std_err.decode()}", "FAILED", "Commands execution", source_url)

    except winrm.exceptions.WinRMTransportError as transport_err:
        logging.error(f"Failed to establish WinRM connection. Transport error occurred with username: {username}. Error: {transport_err}")
        insert_workflow_state(process_id, f"Failed to establish WinRM connection. Transport error occurred with username: {username}. Error: {transport_err}", "FAILED", "Commands execution", source_url)
    except winrm.exceptions.InvalidCredentialsError:
        logging.error(f"Failed to establish WinRM connection. Invalid credentials for {ip} with username: {username}.")
        insert_workflow_state(process_id, f"Failed to establish WinRM connection. Invalid credentials for {ip} with username: {username}.", "FAILED", "Commands execution", source_url)
    except Exception as err:
        logging.error(f"Failed to establish WinRM connection. An error occurred with username: {username}. Error: {err}")
        insert_workflow_state(process_id, f"Failed to establish WinRM connection. An error occurred with username: {username}. Error: {err}", "FAILED", "Commands execution", source_url)



def ssh_to_vm(process_id, ip, source_url, password, sudo_password):
    usernames = ['nutanix', 'root', 'Administrator']
    failed_commands = []

    new_hostname = 'DPRO-AUTOMATION-' + str(int(time.time()))

    for username in usernames:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)
            print(f"SSH connection to {ip} established successfully with username: {username}")
            insert_workflow_state(process_id, f"SSH connection to {ip} established successfully with username: {username}.", "SUCCEEDED", "Commands execution", source_url)

            if new_jira_task:
                add_comment_to_jira_task(new_jira_task, f"SSH connection established successfully with username: {username}.")

            # Check if the VM is a Windows or Linux machine or FreeBSD
            output, error, exit_code = execute_command(ssh, "uname -s")
            if "Linux" in output or "FreeBSD" in output:
                os_type = "Linux"
            else:
                output, error, exit_code = execute_command(ssh, "systeminfo")
                if "Microsoft" in output:
                    os_type = "Windows"
                else:
                    print("Unknown OS type.")
                    ssh.close()
                    return

            print(f"Detected OS type: {os_type}")
            insert_workflow_state(process_id, f"Detected OS type: {os_type}", "SUCCEEDED", "Commands execution", source_url)
            if new_jira_task:
                add_comment_to_jira_task(new_jira_task, f"Detected OS type: {os_type}")


            if os_type == "Windows":
                time.sleep(75)
                ps_version_command = "powershell -Command \"$PSVersionTable.PSVersion.Major\""
                ps_output, ps_error, ps_exit_code = execute_command(ssh, ps_version_command)

                if ps_exit_code != 0 or not ps_output.strip().isdigit():
                    print(f"Failed to check PowerShell version: {ps_error}")
                    insert_workflow_state(process_id, f"Failed to check PowerShell version. PS 5 commands will be used by default. Error: {ps_error}", "INFO", "Commands execution", source_url)
                    ps_version = 5  # If version check fails, default to 2
                else:
                    ps_version = int(ps_output.strip())
                    print(f"PowerShell version detected: {ps_version}")
                    insert_workflow_state(process_id, f"PowerShell version detected: {ps_version}" , "INFO", "Commands execution", source_url)

                # Commands for changing hostname and rebooting
                rename_command = f'powershell Rename-Computer -NewName "{new_hostname}" -Force'
                time.sleep(5)
                shutdown_command = "powershell Shutdown /r /t 0"

                # Execute the rename command
                output, error, exit_code = execute_command(ssh, rename_command)
                if exit_code != 0:
                    print(f"PowerShell command failed. Attempting to change hostname using WMIC...")
                    insert_workflow_state(process_id, f"PowerShell command Rename-Computer failed. Attempting to change hostname using WMIC..." , "FAILED", "Commands execution", source_url)
                    wmic_command = f'WMIC computersystem where name="%COMPUTERNAME%" call rename name="{new_hostname}"'
                    output, error, exit_code = execute_command(ssh, wmic_command)
                    if exit_code != 0:
                        print(f"Failed to change hostname using WMIC: {error}")
                        insert_workflow_state(process_id, f"Failed to change hostname. Error: {error}", "FAILED", "Commands execution", source_url)
                        continue # Skip to the next username if hostname change fails

                print(f"Hostname changed successfully. Output: {output}")
                insert_workflow_state(process_id, f"Hostname changed successfully to {new_hostname}.", "SUCCEEDED", "Commands execution", source_url)

                # Reboot the machine
                output, error, exit_code = execute_command(ssh, shutdown_command)
                if exit_code != 0:
                    print(f"Failed to initiate reboot: {error}")
                    insert_workflow_state(process_id, f"Failed to initiate reboot. Error: {error}", "FAILED", "Commands execution", source_url)

                print("Reboot initiated successfully.")
                insert_workflow_state(process_id, f"Reboot initiated successfully. Waiting for the machine to become available...", "INFO", "Commands execution", source_url)

                # Wait for the machine to become available
                print("Waiting for the machine to become available...")
                time.sleep(30)  # Adjust the sleep duration as needed
                
                # Check availability
                for _ in range(5):  # Retry for a 5 attempts
                    try:
                        ssh.connect(ip, username=username, password=password)
                        print("Machine is back online. Executing remaining commands.")
                        insert_workflow_state(process_id, f"Machine is back online. Executing remaining commands.", "INFO", "Commands execution", source_url)
                        break  # Break if successfully reconnected
                    except Exception as e:
                        print(f"Machine not yet available. Retrying... {e}")
                        insert_workflow_state(process_id, f"Machine not yet available. Retrying... {e}", "INFO", "Commands execution", source_url)
                        time.sleep(10)  # Wait before retrying

                else:
                    print("Machine did not come back online in expected time.")
                    insert_workflow_state(process_id, f"Machine did not come back online in expected time. Unable to continue installing Flexera agent. Terminating proces.", "FAILED", "Commands execution", source_url)
                    return  # Skip to the next username if the machine is still not available

                if ps_version >= 5:
                    windows_commands = [
                        "hostname",
                        # "powershell Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile 'C:\\flexera_prodagent.zip'",
                        'powershell -Command "Start-Process powershell -ArgumentList \'Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile C:\\flexera_prodagent.zip\' -Verb RunAs -Wait"',
                        "powershell Expand-Archive -Path 'C:\\flexera_prodagent.zip' -DestinationPath 'C:\\flexera_prodagent' -Force",
                        # 'cd C:/flexera_prodagent/prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                        "powershell -NoProfile -Command \"cd C:\\flexera_prodagent\\prodagent; & msiexec /i 'FlexNet Inventory Agent.msi' /qn\"",
                        # 'net start | findstr Flexera*'
                        # "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    ]
                else:
                    # Fallback commands for older PowerShell versions (below 5.0) (Expand-Archive command is missing)
                    
                    # windows_commands = [
                    #     "hostname",
                    #     'powershell -Command "Start-Process powershell -ArgumentList \'Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile C:\\flexera_prodagent.zip\' -Verb RunAs -Wait"',
                    #     'powershell -Command "Add-Type -A \'System.IO.Compression.FileSystem\'; [IO.Compression.ZipFile]::ExtractToDirectory(\'C:\\flexera_prodagent.zip\', \'C:\\flexera_prodagent\')"',
                    #     'powershell -NoProfile -Command "cd C:\\flexera_prodagent\\prodagent; & msiexec /i \'FlexNet Inventory Agent.msi\' /qn"',
                    #     # "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    # ]

                    windows_commands = [
                    "hostname",
                        "powershell -Command \"(New-Object System.Net.WebClient).DownloadFile('http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip', 'C:\\flexera_prodagent.zip')\"",
                        "powershell -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::ExtractToDirectory('C:\\flexera_prodagent.zip', 'C:\\flexera_prodagent')\"",
                        'cd C:\\flexera_prodagent\\prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                        # "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    ]

                all_commands_successful = True
                for command in windows_commands:
                    output, error, exit_code = execute_command(ssh, command)
                    if exit_code != 0:
                        print(f"Failed to execute command '{command}', exit code: {exit_code}")
                        print(f"Error of '{command}': {error}")
                        insert_workflow_state(process_id, f"Failed to execute command '{command}> Error: {error}'", "FAILED", "Commands execution", source_url)
                        all_commands_successful = False
                        retry_commands_with_winrm(ip, username, password, new_hostname, process_id, source_url, new_jira_task)
                        break  # Stop executing commands for this user if one command fails

                    else:
                        print(f"Command '{command}' executed successfully")
                        print(f"Output of '{command}': {output}")
                        insert_workflow_state(process_id, f"Command '{command}' executed successfully.", "SUCCEEDED",  "Commands execution", source_url)

                        # adding hostname in waitForFlexera DB table, for future checks on Flexera side by cron job script
                        if command == f'hostname':
                            try:
                                # Attempt to log the data
                                log_to_database_waitForFlexera(process_id, output, None, None, None, None)
                            except Exception as e:
                                # Handle the exception and continue
                                print(f"An error occurred while logging to the database: {e}")
                                insert_workflow_state(process_id, f"An error occurred while logging to the database: {e}. Process will continue, but check <log_to_database_waitForFlexera> function or <waitForFlexera> table in DB", "FAILED",  "Commands execution", source_url)

                    # print(output)
                    time.sleep(45)

                if all_commands_successful:
                    print("All commands executed successfully. Returning.")
                    insert_workflow_state(process_id, f"All commands executed successfully", "SUCCEEDED", "Commands execution", source_url)
                    insert_workflow_state(process_id, f"Waiting for the machine to appear in Flexera and check report.", "INFO", "Commands execution", source_url)
                    if new_jira_task:
                        add_comment_to_jira_task(new_jira_task, f"All commands executed successfully. Flexera agent installed. Waiting for the machine to appear in Flexera and check report.")
                    return

            else:  # Linux
                print("Checking linux distro")
                output, error, exit_code = execute_command(ssh, "cat /etc/os-release")
                distro = "Unknown"
                version = "Unknown"

                if exit_code == 0:
                    for line in output.split('\n'):
                        if line.startswith("PRETTY_NAME"):
                            distro = line.split('=')[1].strip().strip('"')
                            # print(f"Detected distribution: {distro}")  # Debug print
                        elif line.startswith("VERSION_ID"):
                            version_str = line.split('=')[1].strip().strip('"')
                            try:
                                version = float(version_str)
                                # print(f"Detected version: {version}")  # Debug print
                            except ValueError:
                                version = version_str
                                # print(f"Version string: {version}")  # Debug print

                # Fallback to /etc/system-release if /etc/os-release is not available
                elif exit_code != 0:
                    output, error, exit_code = execute_command(ssh, "cat /etc/system-release")
                    if exit_code == 0:
                        distro = output.strip()
                        # Try to extract version if possible
                        version_parts = distro.split()
                        if len(version_parts) > 1:
                            version = version_parts[-1]  # Assume version is the last word in the line

                print(f"Detected distribution: {distro} \nVersion: {version}")
                insert_workflow_state(process_id, f"Detected distribution: {distro}, Version: {version}", "SUCCEEDED", "Commands execution", source_url)
                if new_jira_task:
                    add_comment_to_jira_task(new_jira_task, f"Detected distribution: {distro} \nVersion: {version}")

                # Flag to identify if older version on which Flexera agent can't be installed. 
                is_old_version = False

                if "Ubuntu" in distro and isinstance(version, float):
                    if version >= 20.0:
                        commands = [
                            f"hostnamectl set-hostname {new_hostname}",
                            "apt install -y curl",
                            "curl -s -m 10 https://deb-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                            "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                            "curl https://deb-mirror.corp.nutanix.com/corp/flexera/flexera.list -o /etc/apt/sources.list.d/flexera.list",
                            "curl https://deb-mirror.corp.nutanix.com/corp/ntnx-corp-keyring-rsa3072.gpg -o /etc/apt/trusted.gpg.d/ntnx-corp-keyring-rsa3072.gpg",
                            "apt update",
                            "apt -y install managesoft-autoconf",
                            'apt list --installed',
                            # "cat /var/opt/managesoft/log/uploader.log"
                        ]
                    else:
                        is_old_version = True
                        commands = [
                            'dpkg --get-selections'  # Get list of installed packages for older versions
                        ]

                elif "CentOS" in distro and isinstance(version, float):
                    if version >= 7.0:
                        # commands = [
                        #     f"hostnamectl set-hostname {new_hostname}",
                        #     "yum install -y curl",
                        #     "curl -s -m 10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                        #     "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                        #     "curl https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera-centos-7.repo -o /etc/yum.repos.d/flexera.repo",
                        #     "yum -y install managesoft-autoconf",
                        #     "yum list installed",
                        #     # "cat /var/opt/managesoft/log/uploader.log"
                        # ]

                        commands = [
                            f"hostnamectl set-hostname {new_hostname}",
                            "wget -q --spider --timeout=10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                            "wget -q --timeout=10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                            "wget --no-check-certificate https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera-centos-7.repo -O /etc/yum.repos.d/flexera.repo",
                            "yum -y install managesoft-autoconf",
                            "yum list installed",
                            # "cat /var/opt/managesoft/log/uploader.log"
                        ]
                    else:
                        is_old_version = True
                        commands = [
                            'yum list installed'  # Get list of installed packages for older versions
                        ]

                elif ("RHEL" in distro or "Rocky" in distro or "Red Hat Enterprise Linux" in distro) and isinstance(version, float):
                    if version >= 8.0:
                        commands = [
                            f"hostnamectl set-hostname {new_hostname}",
                            "yum install -y curl",
                            "curl -s -m 10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                            "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                            'mkdir -p /etc/yum.repos.d/',
                            'sudo chmod -R o+rw /etc/yum.repos.d',
                            "curl https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera.repo -o /etc/yum.repos.d/flexera.repo",
                            "yum install -y managesoft-autoconf",
                            "yum list installed",
                            # opt/managesoft/log/uploader.log"
                        ]
                    else:
                        is_old_version = True
                        commands = [
                            'yum list installed'  # Get list of installed packages for older versions
                        ]
                elif "Debian" in distro and isinstance(version, float):
                    # Debian (all versions) just need to get installed packages list
                    commands = [
                        'dpkg --get-selections'
                    ]

                elif "Fedora" in distro and isinstance(version, float):
                    if version >= 22.0:
                        commands = [
                            f"hostnamectl set-hostname {new_hostname}",
                            "dnf install -y curl",
                            "curl -s -m 10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                            "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                            "curl https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera.repo -o /etc/yum.repos.d/flexera.repo",
                            "dnf -y install managesoft-autoconf",
                            "dnf list installed"
                        ]
                    else:
                        is_old_version = True
                        commands = [
                            'yum list installed'  
                        ]
                                        
                elif "AHV" in distro:
                    commands = [
                        f"hostnamectl set-hostname {new_hostname}",
                        "yum install -y curl",
                        "curl -s -m 10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                        "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                        "curl https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera-centos-7.repo -o /etc/yum.repos.d/flexera.repo",
                        "yum -y install managesoft-autoconf",
                        "yum list installed",
                        # "cat /var/opt/managesoft/log/uploader.log"
                    ]
                else:
                    print("Unknown or unsupported distribution. Stopping execution.")
                    insert_workflow_state(process_id, "Unknown or unsupported distribution. Stopping execution.", "FAILED", "Commands execution", source_url)

                    commands_for_unsupported = [
                                                "dpkg --get-selections",        # Debian-based systems
                                                "apt list --installed",         # Ubuntu-based systems
                                                "yum list installed",           # RedHat/CentOS 7 and older
                                                "dnf list installed",           # Fedora/CentOS 8+
                                                "zypper search --installed-only", # SUSE/openSUSE systems
                                                "pkg info" # FreeBSD
                                            ]
                    for command in commands_for_unsupported:
                        try:
                            output, error, exit_code = execute_command(ssh, command, use_sudo=True, use_pty=True, sudo_password=sudo_password)
                            if exit_code == 0:
                                print(f"Successfully retrieved installed applications using command: {command}")
                                print(output)
                                log_to_database_rawInstallations(process_id, output, source_url)
                                insert_workflow_state(process_id, f"Depricated or unsupported distribution for installing Flexera agent. The application list is pulled from the system. The Cron job script <cron_manualAppInfoCollector.py> will collect the records and upload it to Google Drive", "SUCCEEDED",  "Commands execution", source_url)

                                if new_jira_task:
                                    add_comment_to_jira_task(new_jira_task, f"Depricated or unsupported distribution for installing Flexera agent. The application list is pulled from the system. The Cron job script <cron_manualAppInfoCollector.py> will collect the records and upload it to Google Drive. Terminating proces.")
                                
                                # removing VM record from the waitForFlexera DB table since Flexera agent can't be installed
                                try:
                                    conn = mysql.connector.connect(**mysql_config)
                                    cursor = conn.cursor()
                                    cursor.execute(
                                        '''
                                        DELETE FROM vm_template_scan.waitForFlexera 
                                        WHERE process_ID = %s
                                        ''',
                                        (process_id,)  # The provided UUID to match
                                    )
                                    conn.commit()
                                    insert_workflow_state(process_id, f"VM record from the <waitForFlexera> DB table sucesfully removed since Flexera agent can't be installed on this OS.", "SUCCEEDED", "Commands execution", source_url)
                                except Error as err:
                                    logging.error(f"Database error: {err}")
                                    insert_workflow_state(process_id, f"Problem with the removing VM record from the <waitForFlexera> DB table. Check record for this process at DB directly.", "FAILED", "Commands execution", source_url)
                                return
                            
                            else:
                                print(f"Command '{command}' failed with exit code {exit_code}. Error: {error}")
                        
                        except Exception as e:
                            print(f"An error occurred while executing the command '{command}': {e}")
                            continue
                                            
                    ssh.close()
                    return

                # Attempt to run either the full command list or the failed commands
                commands_to_run = failed_commands if failed_commands else commands
                
                failed_commands_retry = []
                for command in commands_to_run:
                    output, error, exit_code = execute_command(ssh, command, use_sudo=True, use_pty=True, sudo_password=sudo_password)

                    if exit_code != 0:
                        print(f"Failed to execute command '{command}', exit code: {exit_code}")
                        print(f"Error of '{command}': {error}")
                        failed_commands_retry.append(command)
                        insert_workflow_state(process_id, f"Failed to execute command '{command}: {error}'", "FAILED", "Commands execution", source_url)
                    else:
                        print(f"Command '{command}' executed successfully")
                        print(f"Output of '{command}': {output}")
                        insert_workflow_state(process_id, f"Command '{command}' executed successfully.", "SUCCEEDED", "Commands execution", source_url)
                        
                        # adding hostname in waitForFlexera DB table, for future checks on Flexera side by cron job script
                        if command == f'hostnamectl set-hostname {new_hostname}':
                            try:
                                # Attempt to log the data
                                log_to_database_waitForFlexera(process_id, new_hostname, None, None, None, None)
                            except Exception as e:
                                # Handle the exception and continue
                                print(f"An error occurred while logging to the database: {e}")
                                insert_workflow_state(process_id, f"An error occurred while logging to the database: {e}. Process will continue, but check <log_to_database_waitForFlexera> function or <waitForFlexera> table in DB", "FAILED", "Commands execution", source_url)

                        elif command == 'apt list --installed' or command == 'dpkg --get-selections':
                            # Ubuntu/Debian systems (newer and older versions)
                            log_to_database_rawInstallations(process_id, output, source_url)
                        
                        elif command == 'yum list installed' or command == 'dnf list installed':
                            # CentOS/RHEL/Fedora/Rocky/AHV systems
                            log_to_database_rawInstallations(process_id, output, source_url)

                        if is_old_version:
                            insert_workflow_state(process_id, f"Depricated or unsupported distribution for installing Flexera agent. The application list is pulled from the system. The Cron job script <cron_manualAppInfoCollector.py> will collect the records and upload it to Google Drive. Terminationg proces.", "SUCCEEDED", "Commands execution", source_url)
                            
                            # removing VM record from the waitForFlexera DB table since Flexera agent can't be installed
                            try:
                                conn = mysql.connector.connect(**mysql_config)
                                cursor = conn.cursor()
                                cursor.execute(
                                    '''
                                    DELETE FROM vm_template_scan.waitForFlexera 
                                    WHERE process_ID = %s
                                    ''',
                                    (process_id,)  # The provided UUID to match
                                )
                                conn.commit()
                                insert_workflow_state(process_id, f"VM record from the <waitForFlexera> DB table sucesfully removed since Flexera agent can't be installed on this OS.", "SUCCEEDED", "Commands execution", source_url)
                            except Error as err:
                                logging.error(f"Database error: {err}")
                                
                            if new_jira_task:
                                add_comment_to_jira_task(new_jira_task, f"Depricated or unsupported distribution for installing Flexera agent. The application list is pulled from the system. The Cron job script <cron_manualAppInfoCollector.py> will collect the records and upload it to Google Drive.")
                            return

                    time.sleep(30)

                if failed_commands_retry:
                    insert_workflow_state(process_id, "Retrying failed commands.", "RUNNING", "Commands execution", source_url)
                    all_linux_commands_successful = True  # Flag to track all commands executed successfully
                    for command in failed_commands_retry:
                        time.sleep(90)
                        output, error, exit_code = execute_command(ssh, command, use_sudo=True, use_pty=True, sudo_password=sudo_password)
                        if exit_code != 0:
                            print(f"Failed to execute command '{command}', exit code: {exit_code}")
                            print(f"Error of '{command}': {error}")
                            insert_workflow_state(process_id, f"Failed to execute command again. Please check on device.'{command}: {error}'", "FAILED", "Commands execution", source_url)
                            failed_commands.append(command)
                            all_linux_commands_successful = False  # Set flag to False if any command fails
                        else:
                            print(f"Command '{command}' executed successfully")
                            print(f"Output of '{command}': {output}")
                            insert_workflow_state(process_id, f"Command '{command}' executed successfully after retry.", "SUCCEEDED", "Commands execution", source_url)
                        print(output)
                        time.sleep(30)
                        
                    if all_linux_commands_successful:
                        insert_workflow_state(process_id, "All commands executed successfully after retry.", "SUCCEEDED", "Commands execution", source_url)
                        insert_workflow_state(process_id, f"Waiting for the machine to appear in Flexera and check report.", "INFO", "Commands execution", source_url)
                        if new_jira_task:
                            add_comment_to_jira_task(new_jira_task, f"All commands executed successfully. Flexera agent installed. Waiting for the machine to appear in Flexera and check report.")
                        return  # Exit the loop if all commands are successful
                    else:
                        insert_workflow_state(process_id, "The problem with some commands still exists. Retrying with different account.", "FAILED", "Commands execution", source_url)
                
                else:
                    insert_workflow_state(process_id, "All commands executed successfully.", "SUCCEEDED", "Commands execution", source_url)
                    insert_workflow_state(process_id, f"Waiting for the machine to appear in Flexera and check report.", "INFO", "Commands execution", source_url)
                    if new_jira_task:
                        add_comment_to_jira_task(new_jira_task, f"All commands executed successfully. Flexera agent installed. Waiting for the machine to appear in Flexera and check report.")
                    return  

        except Exception as e:
            print(f"SSH connection to {ip} failed with username: {username}. Error: {e}")
            insert_workflow_state(process_id, f"SSH connection to {ip} failed with username: {username}. Error: {e}", "FAILED", "Commands execution", source_url)
            
            # Close SSH connection if it was established
            if 'ssh' in locals():
                ssh.close()
                print("SSH connection closed")

            
            # Try to connect using WinRM
            retry_commands_with_winrm(ip, username, password, new_hostname, process_id, source_url, new_jira_task)



if __name__ == "__main__":
    process_id = sys.argv[1]
    ip = sys.argv[2]
    source_url = sys.argv[3]
    new_jira_task = sys.argv[4]

    # username = 'nutanix'
    password = 'nutanix/4u'
    # sudo_username = 'root'
    sudo_password = 'nutanix/4u'
    ssh_to_vm(process_id, ip, source_url, password, sudo_password)  