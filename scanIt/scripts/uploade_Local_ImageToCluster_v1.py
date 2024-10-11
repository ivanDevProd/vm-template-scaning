import sys
import uuid
import logging
import mysql.connector
from mysql.connector import Error
import os
import tarfile
from requests.auth import HTTPBasicAuth
import requests
import shutil
import json
from dotenv import load_dotenv
import subprocess
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage


# Load the .env file
load_dotenv()

# mail function 
def emailing(email_content, recipients):
    user =  os.getenv("SVC_MAIL_USER")
    password = os.getenv("SVC_MAIL_PASS")
    server = smtplib.SMTP('smtp.office365.com', 587)
    server.ehlo()
    server.starttls()

    sender = os.getenv("SVC_MAIL_USER")
    server.login(user, password)

    server.sendmail(sender, recipients, '{}'.format(email_content))
    server.close()


# DB parameters
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")
CLUSTER_IP = os.getenv("CLUSTER_IP")
CLUSTER_USERNAME = os.getenv("CLUSTER_USERNAME")
CLUSTER_PASSWORD = os.getenv("CLUSTER_PASSWORD")


mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': MYSQL_HOST,
    'database': 'vm_template_scan',
    'port': '3306'
}

# Jira parameters 
jira_base_url = "https://jira.nutanix.com/"
jira_bearer_token = os.getenv("JIRA_BEARER_TOKEN") 


# Cluster variables
cluster_ip = CLUSTER_IP
username = CLUSTER_USERNAME
password = CLUSTER_PASSWORD

# Initial Payload 
payload = {
            "spec": {
                "name": "xxx",
                "description": "User local image - self-service",
                "resources": {
                    "image_type": "DISK_IMAGE",
                    "source_uri": "zzz"
                }
            },
            "api_version": "3.1.0",
            "metadata": {
                "kind": "image"
            }
        }


# Configure logging
logging.basicConfig(filename='download_extract.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Generate a unique UUID for process ID
def generate_unique_id():
    process_id = str(uuid.uuid4())  
    return process_id


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


def create_jira_task(summary, description):
    jira_headers = {
                    "Authorization": f"Bearer {jira_bearer_token}",
                    "Content-Type": "application/json"
                }
    
    new_jira_task_payload = {
        "fields": {
            "project": {
                "key": 'DPROREQ'
            },
            "summary": summary,
            "description": description,
            "issuetype": {
                "name": "VM Templates"
            },
            "reporter": {
                "name": "ivan.perkovic"
            },
        }
    }

    create_url = f"{jira_base_url}/rest/api/2/issue"
    try:
        response = requests.post(create_url, headers=jira_headers, data=json.dumps(new_jira_task_payload), timeout=15)  # Timeout set to 15 seconds
        
        if response.status_code == 201:
            print("Task created successfully!")
            task_key = response.json().get("key", "No key in response")
            print(f"Task Key: {task_key}")
            return task_key
        else:
            print(f"Failed to create task: {response.status_code}, {response.text}")
            return None

    except requests.Timeout:
        print("The request timed out!")
        return None
    except requests.ConnectionError:
        print("A connection error occurred!")
        return None
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None
    

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


def extract_image(download_dir_file, extracted_dir, process_id, jira_task_key=None):
    try:
        with tarfile.open(download_dir_file, "r:*") as tar:  # "r:*" handles both gzip and uncompressed tar
            file_info = [member for member in tar.getmembers() if member.isfile()]
            
            # Calculate file details
            num_files = len(file_info)
            total_size = sum(file.size for file in file_info)
            
            # Log file details
            logging.info(f"Number of files in archive: {num_files}")
            logging.info(f"Total size of files: {total_size / (1024 ** 2):.2f} MB")

            log_to_database(process_id, f"Number of files in archive: {num_files}. Total size of files: {total_size / (1024 ** 2):.2f} MB.", "INFO", "Local file uploaded - Self-service", "Processing of the received file")

            if num_files != 1:
                error_message = f"Multiple files found in archive. Found {num_files} files. Process aborted."
                logging.error(error_message)
                log_to_database(process_id, f"Multiple files found in archive. Found {num_files} files. Process aborted.", "FAILED", "Local file uploaded - Self-service", "Processing of the received file")

                if jira_task_key:
                    add_comment_to_jira_task(jira_task_key, f"Multiple files found in archive. Found {num_files} files. Process aborted.")

                return None

            # Extract the single file
            extracted_file_name = file_info[0].name
            tar.extract(file_info[0], path=extracted_dir)
            logging.info(f"Extraction completed to {extracted_dir}")
            log_to_database(process_id, f"Extraction completed to {extracted_dir}", "SUCCEEDED", "Local file uploaded - Self-service", "Processing of the received file")

            if jira_task_key:
                    add_comment_to_jira_task(jira_task_key, f"Extraction completed. ")

        # Generate URL for the extracted image
        extracted_image_url = f"http://10.67.22.100/static/scanIt/extracted_images/{extracted_file_name}"
        logging.info(f"Extracted image URL: {extracted_image_url}")
        log_to_database(process_id, f"Extracted image URL: {extracted_image_url}", "SUCCEEDED", extracted_image_url, "Processing of the received file")
        return extracted_image_url, extracted_file_name

    except Exception as e:
        logging.error(f"Error during extraction: {e}")

        if jira_task_key:
            add_comment_to_jira_task(jira_task_key, f"Error during extraction: {e}")
        return None


def upload_image_to_nutanix():
    process_id = generate_unique_id()

    file_path = sys.argv[1]
    user_email = sys.argv[2]
    file_name = os.path.basename(file_path)

    # Create Jira case
    new_jira_task = create_jira_task(f"System Image Scan request - {file_name}", f"A ticket created based on a request received through the self-selfice portal. New image scan request {file_name}")
    if new_jira_task:
        log_to_database(process_id, f"Jira ticket: {new_jira_task}", "INFO", "Local file uploaded - Self-service", "Jira case")
        log_to_database(process_id, f"The scan was initiated by: {user_email}", "INFO", "Local file uploaded - Self-service", "Jira case")
    
        body_text = f'Hi {user_email.split('.')[0].capitalize()},'\
                    f'<p>Scanning of the image {file_name} has been successfully initiated.'\
                    f'<br>Process id: {process_id}'\
                    f'<p>The speed of the whole process depends on the system and network load, image size, and it may take some time.'\
                    f'<br>You can follow all the details about the progress through the Jira ticket {new_jira_task}.'\
                    f'<p>If you have any questions or concerns regarding this process, please feel free to contact the EngSAM Team for assistance.'\
                    f'<p>Email: eng_sam_admins@nutanix.com'\
                    f'<br>Slack: #ask-eng-sam'\
                    f"<p>Kind regards,"\
                    '<br>EngSAM Team'
        
        msg = MIMEMultipart('mixed')
        msg['Subject'] = f'VM image scan progress'
        part1 = MIMEText(body_text, 'html')
        msg.attach(part1)
        try:
            emailing(msg.as_string(), f'{user_email}')
            log_to_database(process_id, f"The initial mail was successfully sent to: {user_email}", "INFO", "Local file uploaded - Self-service", "Mailing")
        except Exception as e:
            log_to_database(process_id, f"The mail was not successfully sent to the user. Error: {e}", "INFO", "Local file uploaded - Self-service", "Mailing")
   
    else:
        log_to_database(process_id, f"Jira ticket not created. There was a problem. The scanning process will continue without recording in the ticket", "FAILED", "Local file uploaded - Self-service", "Jira case")

    logging.info(f"{file_name} recived to be scaned. It is stored at: {file_path}")
    log_to_database(process_id, f"{file_name} img recived to be scaned. It is stored at: {file_path}", "SUCCEEDED", "Local file uploaded - Self-service", "Processing of the received file")

    logging.info(f"Initiating image upload to the Artifactory")
    log_to_database(process_id, f"Initiating image upload to the Artifactory", "INITIATED", "Local file uploaded - Self-service", "Artifactory Upload")
    jfrog_artifactory_upload_script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/upload_local_image_to_artifactory.py'
    command = f"python3 {jfrog_artifactory_upload_script_path} {file_path} {user_email} {process_id} {new_jira_task}"
    try:
        subprocess.Popen(command, shell=True)
    except Exception as e:
        log_to_database(process_id, f"An error occurred while initiating the upload: {str(e)}", "ERROR", source_url, "Artifactory Upload")

    extracted_dir = '/home/noc_admin/image_scanner_project/static/scanIt/extracted_images/'

    # Get the file size
    file_size_bytes = os.path.getsize(file_path)
    # Convert size to MB
    file_size_mb = file_size_bytes / (1024 * 1024)  # 1 MB = 1024 * 1024 bytes

    if file_path.endswith('.tar.gz'):
        logging.info(f"The file has been archived. File size: {file_size_mb:.2f} MB. It needs to be extracted before uploading.")
        log_to_database(process_id, f"The file has been archived. File size: {file_size_mb:.2f} MB. It needs to be extracted before uploading.", "INFO", "Local file uploaded - Self-service", "Processing of the received file")

        if new_jira_task:
            add_comment_to_jira_task(new_jira_task, f"The file has been archived. File size: {file_size_mb:.2f} MB. It needs to be extracted before uploading.")

        source_url = extract_image(file_path, extracted_dir, process_id, new_jira_task)

        if source_url:
            image_name = "DPRO-AUTOMATION-LOCAL_FILE-" + f"{source_url[1]}"
            payload['spec']['name'] = image_name
            payload['spec']['resources']['source_uri'] = source_url[0]

            remove_file_path = extracted_dir + f'{source_url[1]}'
            image_url = f"http://10.67.22.100/static/scanIt/extracted_images/{source_url[1]}"
        else:
            print("Failed to extract image.")
            log_to_database(process_id, f"Error during extraction: {e}. Aborting process.", "FAILED", "Local file uploaded - Self-service", "Processing of the received file")
            return
        
    elif file_path.endswith(('.qcow', '.qcow2', '.img')):
        # move file to extracted_dir using shutil function
        remove_file_path = shutil.copy(file_path, extracted_dir)
        image_url = f"http://10.67.22.100/static/scanIt/extracted_images/{file_name}"

        log_to_database(process_id, f"File copied to Apache folder. Image URL: {image_url}", "SUCCEEDED", f"Local file uploaded {file_name} - Self-service", "Processing of the received file")
        
        image_name = "DPRO-AUTOMATION-LOCAL_FILE-" + f"{file_name}"
        payload['spec']['name'] = image_name
        payload['spec']['resources']['source_uri'] = image_url


    upload_url = f"https://{cluster_ip}:9440/api/nutanix/v3/images"
    try:
        upload_response = requests.post(
            upload_url,
            auth=HTTPBasicAuth(username, password),
            json=payload,
            verify=False
        )
        print(f"Upload Response Code: {upload_response.status_code}")
        print(f"Upload Response Content: {upload_response.text}")
    except requests.RequestException as e:
        print(f"Failed to initiate image upload: {e}")
        return

    if upload_response.status_code == 202:
        # print("Image upload initiated successfully")
        logging.info(f"Image upload initiated successfully")
        log_to_database(process_id, f"Image upload initiated successfully.", "INITIATED", image_url, "Cluster Image Upload")
        
        task_uuid = upload_response.json().get('status', {}).get('execution_context', {}).get('task_uuid', '')
        print(f"Task UUID: {task_uuid}")

        task_url = f"https://{cluster_ip}:9440/api/nutanix/v3/tasks/{task_uuid}"
        if new_jira_task:
            add_comment_to_jira_task(new_jira_task, f"Image upload initiated successfully.")

        while True:
            try:
                task_response = requests.get(task_url, auth=HTTPBasicAuth(username, password), verify=False)
                task_status = task_response.json()

                state = task_status.get('status', 'UNKNOWN')
                percentage_complete = task_status.get('percentage_complete', 'N/A')
                print(f"State: {state}, Percentage completed: {percentage_complete}%")

                if state == 'SUCCEEDED':
                    # print("Image upload completed successfully")
                    logging.info(f"Image upload completed successfully")
                    uuid = task_status['entity_reference_list'][0]['uuid']
                    print(f"Image UUID on cluster: {uuid}")
                    log_to_database(process_id, f"Image <{image_name}> successfully uploaded. Image UUID: {uuid}", "SUCCEEDED", image_url, "Cluster Image Upload")
                    if new_jira_task:
                        add_comment_to_jira_task(new_jira_task, f"Image successfully uploaded.")

                    script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/deployVm_v1.py'
                    command = f"python3 {script_path} {process_id} {uuid} {image_name} {image_url} {new_jira_task}"
                    subprocess.Popen(command, shell=True)

                    # Clean up the extracted file only if upload was successful 
                    try:
                        if os.path.exists(remove_file_path):
                            os.remove(remove_file_path)
                            # print(f"{remove_file_path} has been deleted successfully.")
                            logging.info(f"{remove_file_path} has been deleted successfully.")
                            log_to_database(process_id, f"Image {file_name} removed from Apache server. Path was: {remove_file_path}", "SUCCEEDED", image_url, "Processing of the received file")
                        else:
                            # print(f"File {remove_file_path} does not exist.")
                            logging.info(f"File {remove_file_path} does not exist.")
                    except Exception as e:
                        # print(f"Error occurred while deleting file: {e}")
                        logging.info(f"Error occurred while deleting file: {e}")
                        log_to_database(process_id, f"Error occurred while deleting image from server: {e}", "FAILED", image_url, "Processing of the received file")
                    
                    break

                elif state == 'FAILED':
                    # print("Image upload failed")
                    logging.info(f"Image upload failed")
                    log_to_database(process_id, f"Image upload failed", "FAILED", image_url, "Cluster Image Upload")

                    if new_jira_task:
                        add_comment_to_jira_task(new_jira_task, f"Image upload failed.")
                    break

            except requests.RequestException as e:
                # print(f"Error retrieving task status: {e}")
                logging.info(f"Error retrieving task status: {e}")


    else:
        # print("Failed to initiate image upload")
        logging.info(f"Failed to initiate image upload")
        # print(f"Response Code: {upload_response.status_code}")
        logging.info(f"Response Code: {upload_response.status_code}")
        # print(f"Response Content: {upload_response.text}")
        logging.info(f"Response Content: {upload_response.text}")



if __name__ == "__main__":
    upload_image_to_nutanix()
