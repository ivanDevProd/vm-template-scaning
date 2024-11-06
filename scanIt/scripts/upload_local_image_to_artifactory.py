import os
import sys
import requests
import logging
import smtplib
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mysql.connector
from mysql.connector import Error
import json


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


# Jira parameters 
jira_base_url = "https://jira.nutanix.com/"
# jira_base_url = "https://jiradev.nutanix.com/"
jira_email = "ivan.perkovic@nutanix.com"
jira_bearer_token = os.getenv("JIRA_BEARER_TOKEN")


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


def create_repo_path(email, file_path):
    user_name = email.split('@')[0]
    file_name = os.path.basename(file_path)
    # Combine username and file name to create the repository path
    return f"{user_name}/{file_name}"

def log_to_database(process_id, message, log_level, source, operation):
    # Implement your logging logic here (to a database, file, etc.)
    if log_level == "INFO":
        logging.info(f"[{operation}] Process ID: {process_id}, Source: {source} - {message}")
    elif log_level == "ERROR":
        logging.error(f"[{operation}] Process ID: {process_id}, Source: {source} - {message}")

def upload_local_image_to_artifactory(file_path, email, process_id, task_key):
    artifactory_url = "https://repos.ntnxdpro.com/artifactory/vmtemplates-qa-vm-images"  
    api_token = os.getenv("JFROG_API_TOKEN")  # Retrieve API token from environment variables

    # Check if the file exists before attempting to upload
    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        log_to_database(process_id, f"File not found: {file_path}", 'FAILED', file_path, "Artifactory Upload")
        return

    repo_path = create_repo_path(email, file_path)  # Create the repository path dynamically

    try:
        with open(file_path, 'rb') as file_to_upload:
            artifactory_upload_url = f"{artifactory_url}/{repo_path}"

            headers = {
                'Authorization': f'Bearer {api_token}',
                'Content-Type': 'application/octet-stream'  # Set the content type for binary data
            }

            log_to_database(process_id, "The process of uploading image to Artifactory has started.", 'RUNNING', file_path, "Artifactory Upload")
            add_comment_to_jira_task(task_key, f"The process of uploading image to Artifactory has started.")
            
            response = requests.put(artifactory_upload_url, data=file_to_upload, headers=headers)

            if response.status_code == 201:
                print(f"Image uploaded successfully to {repo_path}.")
                logging.info(f"Image uploaded successfully to {repo_path}.")
                log_to_database(process_id, f"Image uploaded successfully. Repo path: {artifactory_upload_url}.", 'SUCCEEDED', file_path, "Artifactory Upload")
                add_comment_to_jira_task(task_key, f"Image successfully uploaded to Artifactory. Repo path: {artifactory_upload_url}.")

                body_text = f'Hi {email.split('.')[0].capitalize()},'\
                    f'<p>The image has been successfully uploaded to Artifactory. The repository path is: {artifactory_upload_url}.'\
                    f'<p>The image is now available for use. Please note that the scanning process is ongoing, and if any non-compliant software is detected, the image will be removed from Artifactory.'\
                    f'<p>You can track the progress and further details via the Jira ticket: {task_key}.'\
                    f"<p>Kind regards,"\
                    '<br>EngSAM Team'
        
                msg = MIMEMultipart('mixed')
                msg['Subject'] = f'VM image scan progress'
                part1 = MIMEText(body_text, 'html')
                msg.attach(part1)
                try:
                    emailing(msg.as_string(), f'{email}')
                    log_to_database(process_id, f"The mail with details about new image Artifactory path was successfully sent to: {email}", "INFO", file_path, "Mailing")
                except Exception as e:
                    log_to_database(process_id, f"The mail was not successfully sent to the user. Error: {e}", "INFO", file_path, "Mailing")

                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        # print(f"{remove_file_path} has been deleted successfully.")
                        logging.info(f"{file_path} has been deleted successfully.")
                        log_to_database(process_id, f"Image {os.path.basename(file_path)} removed from server. Path was: {file_path}", "SUCCEEDED", {file_path}, "Processing of the received file")
                    else:
                        # print(f"File {remove_file_path} does not exist.")
                        logging.info(f"File {os.path.basename(file_path)} does not exist.")
                except Exception as e:
                    # print(f"Error occurred while deleting file: {e}")
                    logging.info(f"Error occurred while deleting file: {e}")
                    log_to_database(process_id, f"Error occurred while deleting image from server: {e}", "FAILED", {file_path}, "Processing of the received file")
                    
            else:
                print(f"Failed to upload image to the Artifactory. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                logging.error(f"Failed to upload image. Status code: {response.status_code}. Response: {response.text}")
                log_to_database(process_id, f"Failed to upload image to the Artifactory. Status code: {response.status_code}. Response: {response.text}", 'FAILED', file_path, "Artifactory Upload")
                add_comment_to_jira_task(task_key, f"Failed to upload image to the Artifactory. Status code: {response.status_code}. Response: {response.text}")
    except Exception as e:
        print(f"An error occurred: {e}")
        log_to_database(process_id, f"An error occurred: {str(e)}", 'FAILED', file_path, "Artifactory Upload")

if __name__ == '__main__':
    file_path = sys.argv[1]  # Full file path passed as argument
    email = sys.argv[2]  # User email passed as argument
    process_id = sys.argv[3]  # Process ID passed as argument
    task_key = sys.argv[4]  # Jira ticket number passed as argument
    upload_local_image_to_artifactory(file_path, email, process_id, task_key)
