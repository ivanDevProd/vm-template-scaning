import requests
from requests.auth import HTTPBasicAuth
import json
import time
import os
import tarfile
from datetime import datetime
import mysql.connector
from mysql.connector import Error
import sys
import subprocess
import urllib.request
import uuid
from memory_profiler import profile
import logging
from urllib.parse import urlparse, unquote
from dotenv import load_dotenv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

# Load the .env file
load_dotenv()

# Configure logging
logging.basicConfig(filename='download_extract.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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
JIRA_BEARER_TOKEN = os.getenv("JIRA_BEARER_TOKEN")
CLUSTER_IP = os.getenv("CLUSTER_IP")
CLUSTER_USERNAME = os.getenv("CLUSTER_USERNAME")
CLUSTER_PASSWORD = os.getenv("CLUSTER_PASSWORD")


# DB parameters
mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': '127.0.0.1',
    'database': 'vm_template_scan',
    'port': '3306'
}

# Cluster variables
cluster_ip = CLUSTER_IP
username = CLUSTER_USERNAME
password = CLUSTER_PASSWORD

# Jira parameters 
jira_base_url = "https://jira.nutanix.com/"
jira_email = "ivan.perkovic@nutanix.com"
jira_bearer_token = JIRA_BEARER_TOKEN


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



# Function to download and extract a .tar.gz file
@profile
def download_and_extract_image(source_url, download_dir, extracted_dir, process_id, jira_task_key=None):
    file_size_bytes = 0
    try:
        # Retrieve file size using HEAD request
        response = requests.head(source_url)
        file_size_bytes = int(response.headers.get('Content-Length', 0))
        if file_size_bytes == 0:
            logging.warning(f"Could not retrieve file size from headers: {source_url}")
        file_size_gb = file_size_bytes / (1024 ** 3)  # Convert bytes to gigabytes
        logging.info(f"File size: {file_size_gb:.2f} GB")
        log_to_database(process_id, f"Download started: {source_url}. File size: {file_size_gb:.2f} GB", "INITIATED", source_url, "Download and Extraction")

        if jira_task_key:
            add_comment_to_jira_task(jira_task_key, f"Starting download of {source_url}. File size: {file_size_gb:.2f} GB")
            
    except Exception as e:
        logging.error(f"Error retrieving file size: {e}")
        log_to_database(process_id, f"Error retrieving file size: {e}", "FAILED", source_url, "Download and Extraction")
        return None

    file_name = os.path.basename(source_url)
    download_path = os.path.join(download_dir, file_name)

    try:
        # Download the file using requests to stream large files
        logging.info(f"Downloading file to {download_path}")
        with requests.get(source_url, stream=True) as response:
            response.raise_for_status()
            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):  # Download in 8KB chunks
                    f.write(chunk)
        logging.info(f"Downloaded file to {download_path}")
        log_to_database(process_id, f"File downloaded: {download_path}", "SUCCEEDED", source_url, "Download and Extraction")
        
        if jira_task_key:
            add_comment_to_jira_task(jira_task_key, f"The archived file has been downloaded to the server.")

    except Exception as e:
        logging.error(f"Error during download: {e}")
        log_to_database(process_id, f"Error during download: {e}", "FAILED", source_url, "Download and Extraction")

        if jira_task_key:
            add_comment_to_jira_task(jira_task_key, f"Error during download: {e}")

        return None

    try:
        # Analyze and extract the tar file
        logging.info(f"Attempting to analyze tar file: {download_path}")
        with tarfile.open(download_path, "r:*") as tar:  # "r:*" handles both gzip and uncompressed tar
            file_info = [member for member in tar.getmembers() if member.isfile()]
            
            # Calculate file details
            num_files = len(file_info)
            total_size = sum(file.size for file in file_info)
            
            # Log file details
            logging.info(f"Number of files in archive: {num_files}")
            logging.info(f"Total size of files: {total_size / (1024 ** 2):.2f} MB")
            log_to_database(process_id, f"Number of files in archive: {num_files}, Total size of files: {total_size / (1024 ** 2):.2f} MB", "INFO", source_url, "Download and Extraction")

            if jira_task_key:
                add_comment_to_jira_task(jira_task_key, f"Number of files in archive: {num_files}, Total size of files: {total_size / (1024 ** 2):.2f} MB")

            if num_files != 1:
                error_message = f"Multiple files found in archive. Found {num_files} files. Process aborted."
                logging.error(error_message)
                log_to_database(process_id, error_message, "FAILED", source_url, "Download and Extraction")
                return None

            # Proceed to extract the single file
            extracted_file_name = file_info[0].name
            logging.info(f"Extracting image from {download_path} to {extracted_dir}")
            log_to_database(process_id, f"Extracting image from {download_path} to {extracted_dir}", "INITIATED", source_url, "Download and Extraction")

            if jira_task_key:
                add_comment_to_jira_task(jira_task_key, f"Extracting image initiated.")

            tar.extract(file_info[0], path=extracted_dir)
            logging.info(f"Extraction completed to {extracted_dir}")

        # Generate URL for the extracted image
        extracted_image_url = f"http://10.67.22.100/static/scanIt/extracted_images/{extracted_file_name}"
        logging.info(f"Extracted image URL: {extracted_image_url}")
        log_to_database(process_id, f"Extracted image URL: {extracted_image_url}", "SUCCEEDED", source_url, "Download and Extraction")

        if jira_task_key:
            add_comment_to_jira_task(jira_task_key, f"Extraction completed.")

        return extracted_image_url

    except Exception as e:
        logging.error(f"Error during extraction: {e}")
        log_to_database(process_id, f"Error during extraction: {e}", "FAILED", source_url, "Download and Extraction")

        if jira_task_key:
            add_comment_to_jira_task(jira_task_key, f"Error during extraction: {e}")
        return None


def cleanup_extracted_file(image_url, extracted_dir, process_id):
    # Extract file name from the URL
    parsed_url = urlparse(image_url)
    file_name_from_url = os.path.basename(unquote(parsed_url.path))
    
    file_path = None
    dir_to_remove = None
    
    # Search for the file recursively in extracted_dir
    for root, dirs, files in os.walk(extracted_dir):
        if file_name_from_url in files:
            file_path = os.path.join(root, file_name_from_url)
            dir_to_remove = root  # The directory containing the file
            break

    # Delete the specific file if found
    if file_path and os.path.isfile(file_path):
        os.remove(file_path)
        logging.info(f"Deleted file: {file_path}")
        log_to_database(process_id, f"Extracted image removed from server. Path was: {file_path}", "SUCCEEDED", image_url, "Download and Extraction")

        # Remove the parent subfolder if it is empty after file deletion
        if dir_to_remove and dir_to_remove != extracted_dir:
            # Check if the directory is empty
            if not os.listdir(dir_to_remove):
                os.rmdir(dir_to_remove)
                logging.info(f"Deleted empty subfolder: {dir_to_remove}")
                log_to_database(process_id, f"Deleted empty subfolder: {dir_to_remove}", "SUCCEEDED", image_url, "Download and Extraction")
            else:
                logging.info(f"Subfolder {dir_to_remove} is not empty, not deleted.")
    else:
        logging.error(f"File not found for deletion: {file_name_from_url}")
        log_to_database(process_id, f"File not found for deletion: {file_name_from_url}", "FAILED", image_url, "Download and Extraction")


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

# function generate a unique UUID
def generate_unique_id():
    process_id = str(uuid.uuid4())  
    return process_id


# Function to upload image to Nutanix cluster
@profile
def upload_image_to_nutanix():
    process_id = generate_unique_id()
    json_data_str = sys.argv[1]
    user_email = sys.argv[2]
    try:
        payload = json.loads(json_data_str)
        print(f"Processing payload with ID: {process_id}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return

    # Extract image name and source URL
    image_name = payload['spec']['name']
    source_url = payload['spec']['resources']['source_uri']
    
    # Create Jira case
    new_jira_task = create_jira_task(f"System Image Scan request. URL: {source_url}", f"A ticket created based on a request received through the self-selfice portal. System Image Scan request. URL: {source_url}. The scan was initiated by: {user_email}.")
    if new_jira_task:
        log_to_database(process_id, f"Jira ticket: {new_jira_task}", "INFO", source_url, "Jira case")
        log_to_database(process_id, f"Scan triggered by: {user_email}", "INFO", source_url, "Jira case")

        body_text = f'Hi {user_email.split('.')[0].capitalize()},'\
                    f'<p>Scanning of the image {source_url} has been successfully initiated.'\
                    f'<br>You can follow all the details about the progress through the Jira ticket {new_jira_task}.'\
                    f"<p>Kind regards,"\
                    '<br>DevProd Team'
        
        msg = MIMEMultipart('mixed')
        msg['Subject'] = f'Scanning of the image {source_url} has been successfully initiated.'
        part1 = MIMEText(body_text, 'html')
        msg.attach(part1)
        try:
            emailing(msg.as_string(), f'{user_email}')
            log_to_database(process_id, f"The initial mail was successfully sent to: {user_email}", "INFO", source_url, "Mailing")
        except Exception as e:
            log_to_database(process_id, f"The mail was not successfully sent to the user. Error: {e}", "INFO", source_url, "Mailing")
        
    else:
        log_to_database(process_id, f"Jira ticket not created. There was a problem. The scanning process will continue without recording in the ticket", "FAILED", source_url, "Jira case")
    
    logging.info(f"Initiating image upload to the Artifactory")
    log_to_database(process_id, f"Initiating image upload to the Artifactory", "INITIATED", source_url, "Artifactory Upload")
    jfrog_artifactory_upload_script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/upload_image_from_url_to_artifactory.py'
    command = f"python3 {jfrog_artifactory_upload_script_path} {source_url} {user_email} {process_id} {new_jira_task}"
    try:
        subprocess.Popen(command, shell=True)
    except Exception as e:
        log_to_database(process_id, f"An error occurred while initiating the upload: {str(e)}", "ERROR", source_url, "Artifactory Upload")

    
    # Define directories
    download_dir = '/home/noc_admin/image_scanner_project/downloads/'
    extracted_dir = '/home/noc_admin/image_scanner_project/static/scanIt/extracted_images/'

    if source_url.endswith('.tar.gz'):   
        new_source_url = download_and_extract_image(source_url, download_dir, extracted_dir, process_id, new_jira_task)

        if new_source_url:
            payload['spec']['resources']['source_uri'] = new_source_url
        else:
            print("Failed to download and extract image.")
            return

    # URL for image upload
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
        print("Image upload to cluster initiated successfully.")
        
        task_uuid = upload_response.json().get('status', {}).get('execution_context', {}).get('task_uuid', '')
        print(f"Task UUID: {task_uuid}")

        task_url = f"https://{cluster_ip}:9440/api/nutanix/v3/tasks/{task_uuid}"

        log_to_database(process_id, f"Image upload to cluster initiated successfully. . Task UUID: {task_uuid}", "INITIATED", source_url, "Cluster Image Upload")

        if new_jira_task:
            add_comment_to_jira_task(new_jira_task, f"Image upload to cluster initiated successfully. .")

        while True:
            try:
                task_response = requests.get(task_url, auth=HTTPBasicAuth(username, password), verify=False)
                task_status = task_response.json()

                state = task_status.get('status', 'UNKNOWN')
                percentage_complete = task_status.get('percentage_complete', 'N/A')
                print(f"State: {state}, Percentage completed: {percentage_complete}%")

                if state == 'SUCCEEDED':
                    print("Image upload completed successfully")
                    uuid = task_status['entity_reference_list'][0]['uuid']
                    print(f"Image UUID on cluster: {uuid}")
                    log_to_database(process_id, f"Image <{image_name}> successfully uploaded. Image UUID: {uuid}", "SUCCEEDED", source_url, "Cluster Image Upload")
                    if new_jira_task:
                        add_comment_to_jira_task(new_jira_task, f"Image successfully uploaded.")

                    # log_to_database(process_id, f"NEXT STEPS STOPPED. Uncoment subprocess in uploadeImageToCluster_v2.py", "INFO", source_url, "Cluster Image Upload")
                    script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/deployVm_v1.py'
                    command = f"python3 {script_path} {process_id} {uuid} {image_name} {source_url} {new_jira_task}"
                    subprocess.Popen(command, shell=True)

                    # Clean up the extracted file only if upload was successful
                    cleanup_extracted_file(new_source_url, extracted_dir, process_id)
                    break

                elif state == 'FAILED':
                    print("Image upload failed")
                    log_to_database(process_id, f"Image upload failed", "FAILED", source_url, "Cluster Image Upload")

                    if new_jira_task:
                        add_comment_to_jira_task(new_jira_task, f"Image upload failed.")
                    break

            except requests.RequestException as e:
                print(f"Error retrieving task status: {e}")

            time.sleep(15)

    else:
        print("Failed to initiate image upload")
        print(f"Response Code: {upload_response.status_code}")
        print(f"Response Content: {upload_response.text}")


if __name__ == '__main__':
    upload_image_to_nutanix()