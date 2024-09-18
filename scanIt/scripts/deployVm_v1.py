import requests
from requests.auth import HTTPBasicAuth
import time
from datetime import datetime
import paramiko
import winrm
import sys
import subprocess
import mysql.connector
import json
from mysql.connector import Error
import logging
import os
from dotenv import load_dotenv


# Load the .env file
load_dotenv()

# DB parameters
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
JIRA_BEARER_TOKEN = os.getenv("JIRA_BEARER_TOKEN")
CLUSTER_IP = os.getenv("CLUSTER_IP")
CLUSTER_USERNAME = os.getenv("CLUSTER_USERNAME")
CLUSTER_PASSWORD = os.getenv("CLUSTER_PASSWORD")


mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': '127.0.0.1',
    'database': 'vm_template_scan',
    'port': '3306'
}

# Define variables
cluster_ip = CLUSTER_IP
username = CLUSTER_USERNAME
password = CLUSTER_PASSWORD

# Jira parameters 
jira_base_url = "https://jira.nutanix.com/"
jira_email = "ivan.perkovic@nutanix.com"
jira_bearer_token = JIRA_BEARER_TOKEN


# Function for adding comment in Jira case
def add_comment_to_jira_task(task_key, comment):
    try:
        jira_headers = {
            "Authorization": f"Bearer {jira_bearer_token}",
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


# Function that adds information to the DB that is displayed on the portal page
def log_to_database(process_id, description, state, image_url, stage):
    try:
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO vm_template_scan.workflow_state (process_ID, description, state, image_url, stage) '
            'VALUES (%s, %s, %s, %s, %s)',
            (process_id, description, state, image_url, stage)
        )
        conn.commit()
    except Error as err:
        logging.error(f"Database error: {err}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def get_image_size(image_uuid):
    image_url = f"https://{cluster_ip}:9440/api/nutanix/v3/images/{image_uuid}"
    response = requests.get(image_url, auth=HTTPBasicAuth(username, password), verify=False)
    if response.status_code == 200:
        image_data = response.json()
        image_size_bytes = image_data['status']['resources']['size_bytes']
        image_size_mib = int((image_size_bytes / (1024 * 1024)) + 1024)
        return image_size_mib
    else:
        print(f"Failed to retrieve image details: {response.status_code}")
        return None


def get_vm_ip(vm_uuid):
    vm_url = f"https://{cluster_ip}:9440/api/nutanix/v3/vms/{vm_uuid}"
    response = requests.get(vm_url, auth=HTTPBasicAuth(username, password), verify=False)
    if response.status_code == 200:
        vm_data = response.json()
        try:
            ip_endpoint = vm_data['status']['resources']['nic_list'][0]['ip_endpoint_list'][0]['ip']
            return ip_endpoint
        except IndexError:
            print("Failed to retrieve VM details: IP endpoint list is out of range.")
            return None
    else:
        print(f"Failed to retrieve VM details: {response.status_code}")
        return None


def delete_vm(vm_uuid):
    delete_response = requests.delete(f"https://{cluster_ip}:9440/api/nutanix/v3/vms/{vm_uuid}",
                                      auth=(username, password), verify=False)
    if delete_response.status_code == 202:
        print(f"VM with ID {vm_uuid} deleted successfully.")
    else:
        print(f"Failed to delete VM with ID {vm_uuid}: {delete_response.status_code}")


def pre_check(ip):
    usernames = ['nutanix', 'root', 'Administrator']
    password = 'nutanix/4u'
    for username in usernames:
        try:
            # Attempt SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)
            print(f"SSH connection to {ip} established successfully with user {username}")
            ssh.close()  # Close SSH connection
            return 'SSH'
        
        except Exception as ssh_exception:
            print(f"Failed to connect via SSH with {username}: {ssh_exception}")
        
        try:
            # Attempt WinRM connection
            print(f"Trying WinRM with user: {username}")
            session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password))
            
            response = session.run_cmd('hostname')
            if response.status_code == 0:
                print(f"Successfully ran command 'hostname' with {username} account.")
                print(f"Command output:\n{response.std_out.decode()}\n")
                return 'WinRM'
            else:
                print(f"Command 'hostname' failed with status code: {response.status_code}")
                print(f"Error output:\n{response.std_err.decode()}\n")

        except Exception as winrm_exception:
            print(f"Failed to connect via WinRM with {username}: {winrm_exception}")
    
    return None  # Return None if all connection attempts fail


def create_vm_with_uefi(vm_name, image_uuid, process_id, source_url):
    # Get the size of the image
    image_size_mib = get_image_size(image_uuid)
    if image_size_mib is None:
        print("Cannot proceed without image size")
        return

    # Define the URL for VM creation
    url = f"https://{cluster_ip}:9440/api/nutanix/v3/vms"

    # Payload for VM creation
    payload = {
        "spec": {
            "name": f"{vm_name}",
            "resources": {
                "memory_size_mib": 4096,
                "num_vcpus_per_socket": 2,
                "num_sockets": 1,
                "boot_config": {

                    "boot_type": "UEFI"
                },
                "disk_list": [
                    {
                        "data_source_reference": {
                            "kind": "image",
                            "uuid": f"{image_uuid}"
                        },
                        "disk_size_mib": image_size_mib  
                    }
                ],
                "power_state": "ON",
                "nic_list": [
                    {
                        "subnet_reference": {
                            "kind": "subnet",
                            "uuid": "9614bc8d-a5d4-4e02-b884-458b554584e3" 
                        }
                    }
                ]
            }
        },
        "api_version": "3.1.0",
        "metadata": {
            "kind": "vm"
        }
    }

    # Make the request to create the VM
    response = requests.post(url, auth=HTTPBasicAuth(username, password), json=payload, verify=False)
    if response.status_code == 202:
        print("UEFI VM creation initiated successfully")
        task_uuid = response.json()['status']['execution_context']['task_uuid']
        print(f"Task UUID: {task_uuid}")

        task_url = f"https://{cluster_ip}:9440/api/nutanix/v3/tasks/{task_uuid}"
        task_response = requests.get(task_url, auth=HTTPBasicAuth(username, password), verify=False)
        task_status = task_response.json()
        try:
            state = task_status['status']
        except Exception as e:
            state = e 

        log_to_database(process_id, f"UEFI VM creation initiated successfully. Task UUID: {task_uuid}", f"{state}", source_url, "VM deployment")

        while True:
            task_response = requests.get(task_url, auth=HTTPBasicAuth(username, password), verify=False)

            if task_response.status_code == 200:
                task_status = task_response.json()

                # Check if task is complete
                state = task_status['status']
                if state:
                    print(f"Current state: {state}")
                    if state == 'SUCCEEDED':
                        print("UEFI VM creation completed successfully")
                        print(task_status)
                        # print(task_status['entity_reference_list'][0]['uuid'])
                        vm_uuid = task_status['entity_reference_list'][0]['uuid']

                        log_to_database(process_id, f"UEFI VM <{vm_name}>creation completed successfully. VM UUID on cluster: {vm_uuid}", "SUCCEEDED", source_url, "VM deployment")

                        # Wait for a few seconds to ensure the VM is fully initialized
                        time.sleep(45)

                        # Retrieve the VM's IP address
                        vm_ip = get_vm_ip(vm_uuid)

                        log_to_database(process_id, f"IP address check for deployed UEFI VM {vm_name}", "RUNNING", source_url, "VM deployment")

                        if vm_ip:
                            print(f"VM IP Address: {vm_ip}")
                            log_to_database(process_id, f"IP address for deployed UEFI VM {vm_name}: {vm_ip}", "SUCCEEDED", source_url, "VM deployment")

                            log_to_database(process_id, f"Checking machine access via ssh/winrm. The pre-check method has been initiated. It can take a couple of minutes.", "RUNNING", source_url, "VM deployment")

                            check_result = pre_check(vm_ip)
                            print(f"Check Result: {check_result}")

                            if check_result == 'SSH' or check_result == 'WinRM':
                                print('VM avialable via ssh/winRM')
                                log_to_database(process_id, f"VM {vm_ip} can be accessed via ssh/winRM", "SUCCEEDED", source_url, "VM deployment")

                                # Connecting and executing commands on deployed machine (using ssh_to_vm method) passing IP address
                                script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/operationsOnDeployedVm_V1.py'
                                command = f"python3 {script_path} {process_id} {vm_ip} {source_url}"
                                # Run the script asynchronously
                                subprocess.Popen(command, shell=True)

                            else:
                                print("Failed to establish connection via SSH or WinRM to UEFI enabled VM. ")
                                log_to_database(process_id, f"Failed to establish connection via SSH or WinRM to UEFI enabled VM <{vm_ip}>. Terminating Process.", "FAILED", source_url, "VM deployment")

                                delete_vm(vm_uuid)

                                log_to_database(process_id, f"VM with ID {vm_uuid} deleted successfully.", "SUCCEEDED", source_url, "VM deployment")

                                time.sleep(1)

                                log_to_database(process_id, f"Stage completed with errors. Boot the machine manually using the uploaded image and check the status. Possible reasons for the problem are the machine not booting, booting with error, unable to log in with root, nutanix, administrator user, winRM config does not allow Basic auth or Unencrypted traffic, etc", "FAILED", source_url, "VM deployment")

                                return
                        else:
                            print("Failed to get VM IP for UEFI booted VM.")
                            log_to_database(process_id, f"Failed to get VM IP for UEFI booted VM. Terminating Process.", "FAILED", source_url, "VM deployment")

                            break
                        break
                    else:
                        print("State not found in response")
                else:
                    print(f"Failed to get task status: {task_response.status_code}")
                    print(task_response.json())
                    break

            else:
                print(f"Failed to get task status: {task_response.status_code}")
                print(task_response.json())
                break
            # Wait for a few seconds before polling again
            time.sleep(5)
    else:
        print("Failed to create VM")
        print("Response Code:", response.status_code)
        print("Response:", response.json())


def deploy_vm():
    process_id = sys.argv[1]
    image_uuid = sys.argv[2]
    vm_name = sys.argv[3]
    source_url = sys.argv[4]
    new_jira_task = sys.argv[5]

    print(process_id, image_uuid, vm_name,source_url )

    # Get the size of the image
    image_size_mib = get_image_size(image_uuid)
    if image_size_mib is None:
        print("Cannot proceed without image size")
        return

    # Define the URL for VM creation
    url = f"https://{cluster_ip}:9440/api/nutanix/v3/vms"

    # Define the payload for VM creation
    vm_payload = {
        "spec": {
            "name": f"{vm_name}",
            "resources": {
                "memory_size_mib": 4096,
                "num_vcpus_per_socket": 2,
                "num_sockets": 1,
                "disk_list": [
                    {
                        "data_source_reference": {
                            "kind": "image",
                            "uuid": f"{image_uuid}"
                        },
                        "disk_size_mib": image_size_mib
                    }
                ],
                "power_state": "ON",
                "nic_list": [
                    {
                        "subnet_reference": {
                            "kind": "subnet",
                            "uuid": "9614bc8d-a5d4-4e02-b884-458b554584e3"
                        }
                    }
                ]
            }
        },
        "api_version": "3.1.0",
        "metadata": {
            "kind": "vm"
        }
    }

    # Make the request to create the VM
    response = requests.post(url, auth=HTTPBasicAuth(username, password), json=vm_payload, verify=False)

    # Check the response
    if response.status_code == 202:
        print("VM creation initiated successfully")
        task_uuid = response.json()['status']['execution_context']['task_uuid']
        print(f"Task UUID: {task_uuid}")

        task_url = f"https://{cluster_ip}:9440/api/nutanix/v3/tasks/{task_uuid}"
        task_response = requests.get(task_url, auth=HTTPBasicAuth(username, password), verify=False)
        task_status = task_response.json()
        try:
            state = task_status['status']
        except Exception as e:
            state = e 

        log_to_database(process_id, f"VM creation initiated successfully. Task UUID: {task_uuid}", f"{state}", source_url, "VM deployment")

        if new_jira_task:
            add_comment_to_jira_task(new_jira_task, f"VM creation initiated successfully.")

        while True:
            task_response = requests.get(task_url, auth=HTTPBasicAuth(username, password), verify=False)

            if task_response.status_code == 200:
                task_status = task_response.json()

                # Check if task is complete
                state = task_status['status']
                if state:
                    print(f"Current state: {state}")
                    if state == 'SUCCEEDED':
                        print("VM creation completed successfully")
                        print(task_status)
                        # print(task_status['entity_reference_list'][0]['uuid'])
                        vm_uuid = task_status['entity_reference_list'][0]['uuid']

                        log_to_database(process_id, f"VM <{vm_name}>creation completed successfully. VM UUID on cluster: {vm_uuid}", "SUCCEEDED", source_url, "VM deployment")

                        if new_jira_task:
                            add_comment_to_jira_task(new_jira_task, f"VM successfully created.")

                        # Wait for a few seconds to ensure the VM is fully initialized
                        time.sleep(45)

                        # Retrieve the VM's IP address
                        vm_ip = get_vm_ip(vm_uuid)

                        log_to_database(process_id, f"IP address check for deployed VM {vm_name}", "RUNNING", source_url, "VM deployment")

                        if vm_ip:
                            print(f"VM IP Address: {vm_ip}")
                            log_to_database(process_id, f"IP address for deployed VM {vm_name}: {vm_ip}", "SUCCEEDED", source_url, "VM deployment")

                            if new_jira_task:
                                add_comment_to_jira_task(new_jira_task, f"IP address for deployed VM {vm_name}: {vm_ip}")

                            log_to_database(process_id, f"Checking machine access via ssh/winrm. The pre-check method has been initiated. It can take a couple of minutes.", "RUNNING", source_url, "VM deployment")

                            if new_jira_task:
                                add_comment_to_jira_task(new_jira_task, f"Checking machine access via ssh/winrm.")

                            check_result = pre_check(vm_ip)
                            print(f"Check Result: {check_result}")


                            if check_result:
                                print('VM avialable via ssh/winRM')
                                log_to_database(process_id, f"VM avialable via ssh/winRM. Continues executing commands on the running machine.", "SUCCEEDED", source_url, "VM deployment")

                                if new_jira_task:
                                    add_comment_to_jira_task(new_jira_task, f"VM avialable via ssh/winRM. Continues executing commands on the running machine.")

                                # Connecting and executing commands on deployed machine (using ssh_to_vm method) passing IP address
                                script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/operationsOnDeployedVm_V1.py'
                                command = f"python3 {script_path} {process_id} {vm_ip} {source_url}"
                                # Run the script asynchronously
                                subprocess.Popen(command, shell=True)

                            else:
                                print("Failed to establish connection via SSH or WinRM. Creating New with UEFI enabled..")
                                log_to_database(process_id, f"Failed to establish connection via SSH or WinRM. Creating New VM with UEFI enabled. Running create_vm_with_uefi method.", "FAILED", source_url, "VM deployment")


                                delete_vm(vm_uuid)

                                log_to_database(process_id, f"VM with ID {vm_uuid} deleted successfully.", "SUCCEEDED", source_url, "VM deployment")

                                create_vm_with_uefi(vm_name, image_uuid , process_id, source_url)
                        else:
                            print("Failed to get VM IP. Trying to boot machine with UEFI enabled.")
                            log_to_database(process_id, f"Failed to get VM IP. Creating New VM with UEFI enabled. Running create_vm_with_uefi method.", "FAILED", source_url, "VM deployment")

                            delete_vm(vm_uuid)

                            log_to_database(process_id, f"VM with ID {vm_uuid} deleted successfully.", "SUCCEEDED", source_url, "VM deployment")

                            create_vm_with_uefi(vm_name, image_uuid, process_id, source_url)
                        break
                    else:
                        print("State not found in response")
                else:
                    print(f"Failed to get task status: {task_response.status_code}")
                    print(task_response.json())
                    break

            else:
                print(f"Failed to get task status: {task_response.status_code}")
                print(task_response.json())
                break
            # Wait for a few seconds before polling again
            time.sleep(5)
    else:
        print("Failed to create VM")
        print("Response Code:", response.status_code)
        print("Response:", response.json())
        log_to_database(process_id, f"Failed to create VM. Response: {response.json()}", "FAILED", source_url, "VM deployment")

        if new_jira_task:
            add_comment_to_jira_task(new_jira_task, f"Failed to create VM. Response: {response.json()}")


if __name__ == '__main__':
    deploy_vm()
