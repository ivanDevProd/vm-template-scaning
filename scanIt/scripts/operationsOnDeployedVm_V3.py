import paramiko
import mysql.connector
import winrm
import time
import sys
import os
from dotenv import load_dotenv
import logging


# Load the .env file
load_dotenv()

MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")

mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': MYSQL_HOST,
    'database': 'vm_template_scan',
    'port': '3306'
}

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
def log_to_database_waitForFlexera(process_id, vm_hostname, vm_uuid, vm_ip):
    try:
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()

        # Insert new record or update the existing record if process_ID already exists
        cursor.execute(
            '''
            INSERT INTO vm_template_scan.waitForFlexera (process_ID, vm_hostname, vm_uuid, vm_ip) 
            VALUES (%s, %s, %s, %s) 
            ON DUPLICATE KEY UPDATE
            vm_hostname = COALESCE(%s, vm_hostname),
            vm_uuid = COALESCE(%s, vm_uuid),
            vm_ip = COALESCE(%s, vm_ip)
            ''',
            (process_id, vm_hostname, vm_uuid, vm_ip, vm_hostname, vm_uuid, vm_ip)
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
        command = f"echo {sudo_password} | sudo -S {command}"

    stdin, stdout, stderr = ssh.exec_command(command, get_pty=use_pty)

    if use_sudo:
        stdin.write(sudo_password + '\n')
        stdin.flush()

    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    exit_code = stdout.channel.recv_exit_status()

    return output, error, exit_code

def retry_commands_with_winrm(ip, username, password):
    try:
        session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password))

        fallback_command = "powershell -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::ExtractToDirectory('C:\\flexera_prodagent.zip', 'C:\\flexera_prodagent')\""
        windows_commands = [
                        "hostname",
                        "powershell Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile 'C:\\flexera_prodagent.zip'",
                        "powershell Expand-Archive -Path 'C:\\flexera_prodagent.zip' -DestinationPath 'C:\\flexera_prodagent'",
                        'cd C:\\flexera_prodagent\\prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                        "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    ]

        all_commands_successful = True
        for command in windows_commands:
            response = session.run_cmd(command)
            if response.status_code != 0:
                print(f"Failed to execute command '{command}', status code: {response.status_code}")
                print(f"Error of '{command}': {response.std_err}")
                insert_workflow_state(process_id, f"Failed to execute command '{command}: {response.std_err}'", "FAILED", "Commands execution", source_url)
                
                if "'Expand-Archive' is not recognized" in str(response.std_err):
                    print("Expand-Archive command not recognized, trying fallback method.")
                    response = session.run_cmd(fallback_command)
                    if response.status_code != 0:
                        print(f"Failed to execute fallback command '{fallback_command}', status code: {response.status_code}")
                        insert_workflow_state(process_id, f"Failed to execute fallback command '{fallback_command}', status code: {response.status_code}", "FAILED", "Commands execution", source_url)
                        all_commands_successful = False
                    else:
                        print(f"Fallback command '{fallback_command}' executed successfully with username: {username}")
                        insert_workflow_state(process_id, f"Fallback command '{fallback_command}' executed successfully with username: {username}", "SUCCEEDED", "Commands execution", source_url)
            else:
                print(f"Command '{command}' executed successfully")
                print(f"Output of '{command}': {response.decode()}")
                insert_workflow_state(process_id, f"Command '{command}' executed successfully with username: {username}. Command output {response.std_out.decode().strip()}", "SUCCEEDED", "Commands execution", source_url)

        if all_commands_successful:
            print("All commands executed successfully. Returning.")
            insert_workflow_state(process_id, f"All commands executed successfully", "SUCCEEDED", "Commands execution", source_url)
            return

    except Exception as winrm_e:
        print(f"WinRM connection to {ip} failed with username: {username}. Error: {winrm_e}")
        insert_workflow_state(process_id, f"WinRM connection to {ip} failed with username: {username}. Error: {winrm_e}", source_url)


def ssh_to_vm(process_id, ip, source_url, password, sudo_password):
    usernames = ['nutanix', 'root', 'Administrator']
    failed_commands = None 
    
    for username in usernames:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)
            print(f"SSH connection to {ip} established successfully with username: {username}")
            insert_workflow_state(process_id, f"SSH connection to {ip} established successfully with username: {username}.", "SUCCEEDED", "Commands execution", source_url)

            # Check if the VM is a Windows or Linux machine
            output, error, exit_code = execute_command(ssh, "uname -s")
            if "Linux" in output:
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

            if os_type == "Windows":
                ps_version_command = "powershell -Command \'$PSVersionTable.PSVersion.Major\'"
                ps_output, ps_error, ps_exit_code = execute_command(ssh, ps_version_command)

                if ps_exit_code != 0 or not ps_output.strip().isdigit():
                    print(f"Failed to check PowerShell version: {ps_error}")
                    insert_workflow_state(process_id, f"Failed to check PowerShell version. Error: {ps_error}", "FAILED", "Commands execution", source_url)
                    ps_version = 0  # If version check fails, default to 0
                else:
                    ps_version = int(ps_output.strip())
                    print(f"PowerShell version detected: {ps_version}")

                if ps_version >= 5:
                    windows_commands = [
                        "hostname",
                        # "powershell Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile 'C:\\flexera_prodagent.zip'",
                        'powershell -Command "Start-Process powershell -ArgumentList \'Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile C:\\flexera_prodagent.zip\' -Verb RunAs -Wait"',
                        "powershell Expand-Archive -Path 'C:\\flexera_prodagent.zip' -DestinationPath 'C:\\flexera_prodagent' -Force",
                        # 'cd C:/flexera_prodagent/prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                        "powershell -NoProfile -Command \"cd C:\\flexera_prodagent\\prodagent; & msiexec /i 'FlexNet Inventory Agent.msi' /qn\"",
                        # 'net start | findstr Flexera*'
                        "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    ]
                else:
                    # Fallback commands for older PowerShell versions (below 5.0) (Expand-Archive command is missing)
                    windows_commands = [
                        "hostname",
                        'powershell -Command "Start-Process powershell -ArgumentList \'Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile C:\\flexera_prodagent.zip\' -Verb RunAs -Wait"',
                        'powershell -Command "Add-Type -A \'System.IO.Compression.FileSystem\'; [IO.Compression.ZipFile]::ExtractToDirectory(\'C:\\flexera_prodagent.zip\', \'C:\\flexera_prodagent\')"',
                        'powershell -NoProfile -Command "cd C:\\flexera_prodagent\\prodagent; & msiexec /i \'FlexNet Inventory Agent.msi\' /qn"',
                        "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    ]

                all_commands_successful = True
                for command in windows_commands:
                    output, error, exit_code = execute_command(ssh, command)
                    if exit_code != 0:
                        print(f"Failed to execute command '{command}', exit code: {exit_code}")
                        print(f"Error of '{command}': {error}")
                        insert_workflow_state(process_id, f"Failed to execute command '{command}> Error: {error}'", "FAILED", "Commands execution", source_url)
                        all_commands_successful = False
                        retry_commands_with_winrm(username,password)
                        break  # Stop executing commands for this user if one command fails

                    else:
                        print(f"Command '{command}' executed successfully")
                        print(f"Output of '{command}': {output}")
                        insert_workflow_state(process_id, f"Command '{command}' executed successfully> Output: {output}", "SUCCEEDED", "Commands execution", source_url)

                        # adding hostname in waitForFlexera DB table, for future checks on Flexera side by cron job script
                        if command == f'hostname':
                            log_to_database_waitForFlexera(process_id, output, None, None)

                    # print(output)
                    time.sleep(5)

                if all_commands_successful:
                    print("All commands executed successfully. Returning.")
                    insert_workflow_state(process_id, f"All commands executed successfully", "SUCCEEDED", "Commands execution", source_url)
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
                else:
                    output, error, exit_code = execute_command(ssh, "cat /etc/system-release")
                    if exit_code == 0:
                        distro = output.strip()
                        # Try to extract version if possible
                        version_parts = distro.split()
                        if len(version_parts) > 1:
                            version = version_parts[-1]  # Assume version is the last word in the line

                print(f"Detected distribution: {distro} \nVersion: {version}")
                insert_workflow_state(process_id, f"Detected distribution: {distro}, Version: {version}", "SUCCEEDED", "Commands execution", source_url)

                new_hostname = 'DPRO_AUTOMATION_' + str(int(time.time()))
                if "Ubuntu" in distro and isinstance(version, float) and version >= 20.0:
                    commands = [
                        f"hostnamectl set-hostname {new_hostname}",
                        "apt install -y curl",
                        "curl -s -m 10 https://deb-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                        "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                        "curl https://deb-mirror.corp.nutanix.com/corp/flexera/flexera.list -o /etc/apt/sources.list.d/flexera.list",
                        "curl https://deb-mirror.corp.nutanix.com/corp/ntnx-corp-keyring-rsa3072.gpg -o /etc/apt/trusted.gpg.d/ntnx-corp-keyring-rsa3072.gpg",
                        "apt update",
                        "apt -y install managesoft-autoconf",
                        "cat /var/opt/managesoft/log/uploader.log"
                    ]
                elif "CentOS" in distro and isinstance(version, float) and version >= 7.0:
                    commands = [
                        f"hostnamectl set-hostname {new_hostname}",
                        "yum install -y curl",
                        "curl -s -m 10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                        "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                        "curl https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera-centos-7.repo -o /etc/yum.repos.d/flexera.repo",
                        "yum -y install managesoft-autoconf",
                        "cat /var/opt/managesoft/log/uploader.log"
                    ]
                elif ("RHEL" in distro or "Rocky" in distro or "Red Hat Enterprise Linux" in distro) and isinstance(version, float) and version >= 8.0:
                    commands = [
                        f"hostnamectl set-hostname {new_hostname}",
                        "yum install -y curl",
                        "curl -s -m 10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                        "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                        'mkdir -p /etc/yum.repos.d/',
                        'sudo chmod -R o+rw /etc/yum.repos.d',
                        "curl https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera.repo -o /etc/yum.repos.d/flexera.repo",
                        "yum -y install managesoft-autoconf",
                        "cat /var/opt/managesoft/log/uploader.log"
                    ]
                elif "AHV" in distro:
                    commands = [
                        f"hostnamectl set-hostname {new_hostname}",
                        "yum install -y curl",
                        "curl -s -m 10 https://rpm-mirror.corp.nutanix.com/ 1>/dev/null; echo $?",
                        "curl -s -m 10 https://phxitflexerap1.corp.nutanix.com/ManageSoftRL/ 1>/dev/null; echo $?",
                        "curl https://rpm-mirror.corp.nutanix.com/corp/flexera/flexera-centos-7.repo -o /etc/yum.repos.d/flexera.repo",
                        "yum -y install managesoft-autoconf",
                        "cat /var/opt/managesoft/log/uploader.log"
                    ]
                else:
                    print("Unknown or unsupported distribution. Stopping execution.")
                    insert_workflow_state(process_id, "Unknown or unsupported distribution. Stopping execution.", "FAILED", "Commands execution", source_url)
                    ssh.close()
                    return


                # Attempt to run either the full command list or the failed commands
                if failed_commands is None:
                    commands_to_run = commands
                else:
                    commands_to_run = failed_commands

                failed_commands = []
                for command in commands_to_run:
                    output, error, exit_code = execute_command(ssh, command, use_sudo=True, use_pty=True, sudo_password=sudo_password)
                    if exit_code != 0:
                        print(f"Failed to execute command '{command}', exit code: {exit_code}")
                        print(f"Error of '{command}': {error}")
                        failed_commands.append(command)
                        insert_workflow_state(process_id, f"Failed to execute command '{command}: {error}'", "FAILED", "Commands execution", source_url)
                    else:
                        print(f"Command '{command}' executed successfully")
                        print(f"Output of '{command}': {output}")
                        insert_workflow_state(process_id, f"Command '{command}' executed successfully> Output: {output}", "SUCCEEDED", "Commands execution", source_url)
                        
                        # adding hostname in waitForFlexera DB table, for future checks on Flexera side by cron job script
                        if command == f'hostnamectl set-hostname {new_hostname}':
                            log_to_database_waitForFlexera(process_id, new_hostname, None, None)

                    # print(output)
                    time.sleep(30)

                if failed_commands:
                    insert_workflow_state(process_id, "Retrying failed commands.", "RUNNING", "Commands execution", source_url)
                    all_commands_successful = True  # Flag to track all commands executed successfully
                    for command in failed_commands:
                        time.sleep(90)
                        output, error, exit_code = execute_command(ssh, command, use_sudo=True, use_pty=True, sudo_password=sudo_password)
                        if exit_code != 0:
                            print(f"Failed to execute command '{command}', exit code: {exit_code}")
                            print(f"Error of '{command}': {error}")
                            insert_workflow_state(process_id, f"Failed to execute command again. Please check on device.'{command}: {error}'", "FAILED", "Commands execution", source_url)
                            all_commands_successful = False  # Set flag to False if any command fails
                        else:
                            print(f"Command '{command}' executed successfully")
                            print(f"Output of '{command}': {output}")
                            insert_workflow_state(process_id, f"Command '{command}' executed successfully after retry> Output: {output}", "SUCCEEDED", "Commands execution", source_url)
                        print(output)
                        time.sleep(30)
                        
                    if all_commands_successful:
                        insert_workflow_state(process_id, "All commands executed successfully after retry.", "SUCCEEDED", "Commands execution", source_url)
                        return  # Exit the loop if all commands are successful
                    else:
                        insert_workflow_state(process_id, "The problem with some commands still exists. Retrying with different account.", "FAILED", "Commands execution", source_url)
                else:
                    insert_workflow_state(process_id, "All commands executed successfully.", "SUCCEEDED", "Commands execution", source_url)
                    return  # Exit the loop after retry even tehere are still some failed commands

        except Exception as e:
            print(f"SSH connection to {ip} failed with username: {username}. Error: {e}")
            insert_workflow_state(process_id, f"SSH connection to {ip} failed with username: {username}. Error: {e}", "FAILED", "Commands execution", source_url)
            
            # Close SSH connection if it was established
            if 'ssh' in locals():
                ssh.close()

            # Try to connect using WinRM
            try:
                session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password))

                # Check PowerShell version
                try:
                    ps_version_command = "powershell -Command \'$PSVersionTable.PSVersion.Major\'"
                    response = session.run_cmd(ps_version_command)

                    if response.status_code == 0:
                        ps_version = int(response.std_out.strip())
                        print(f"PowerShell version on target: {ps_version}")
                    else:
                        print(f"Failed to retrieve PowerShell version, status code: {response.status_code}. Proceeding without version check.")
                        print(f"Error: {response.std_err.decode()}")
                        ps_version = 0  # If version check fails, default to 0
                        
                except Exception as version_check_e:
                    print(f"Exception during PowerShell version check: {version_check_e}. Proceeding with fallback as precaution.")
                    ps_version = 0  # Assume old PowerShell version if version check fails

                if ps_version < 5:
                    print(f"Using fallback commands due to PowerShell version < 5")
                    windows_commands = [
                        "hostname",
                        "powershell Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile 'C:\\flexera_prodagent.zip'",
                        "powershell -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::ExtractToDirectory('C:\\flexera_prodagent.zip', 'C:\\flexera_prodagent')\"",
                        'cd C:\\flexera_prodagent\\prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                        "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    ]
                else:
                    print(f"Using standard commands for PowerShell version >= 5")
                    windows_commands = [
                        "hostname",
                        "powershell Invoke-WebRequest -Uri http://drtitfsprod03.corp.nutanix.com/flexera/flexera_prodagent.zip -OutFile 'C:\\flexera_prodagent.zip'",
                        "powershell Expand-Archive -Path 'C:\\flexera_prodagent.zip' -DestinationPath 'C:\\flexera_prodagent'",
                        'cd C:\\flexera_prodagent\\prodagent && msiexec /i "FlexNet Inventory Agent.msi" /qn',
                        "powershell -NoProfile -Command \"net start | findstr Flexera*\""
                    ]

                all_commands_successful = True
                for command in windows_commands:
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
                            log_to_database_waitForFlexera(process_id, response.std_out.decode().strip(), None, None)

                if all_commands_successful:
                    print("All commands executed successfully via WinRM. Returning.")
                    insert_workflow_state(process_id, f"All commands executed successfully via WinRM", "SUCCEEDED", "Commands execution", source_url)
                    return

            except Exception as winrm_e:
                print(f"WinRM connection to {ip} failed with username: {username}. Error: {winrm_e}")
                insert_workflow_state(process_id, f"WinRM connection to {ip} failed with username: {username}. Error: {winrm_e}", "FAILED", "Commands execution", source_url)

        finally:
            if 'ssh' in locals():
                ssh.close()
                print("SSH connection closed")


if __name__ == "__main__":
    process_id = sys.argv[1]
    ip = sys.argv[2]
    source_url = sys.argv[3]

    # username = 'nutanix'
    password = 'nutanix/4u'
    # sudo_username = 'root'
    sudo_password = 'nutanix/4u'
    ssh_to_vm(process_id, ip, source_url, password, sudo_password)