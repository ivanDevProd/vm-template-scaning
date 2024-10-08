import sys
import requests
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
import logging
import smtplib
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


def create_repo_path(email, image_url):
    user_name = email.split('@')[0]

    # Parse the image URL and remove the domain
    parsed_url = urlparse(image_url)
    image_path = parsed_url.path.split('/', 3)[-1]  # Get the path after the domain

    # Combine user name and image file name to create the repo path
    repo_path = f"{user_name}/{image_path}"

    return repo_path


def upload_image_from_url_to_artifactory(image_url, email, process_id, task_key):
    artifactory_url = "https://repos.ntnxdpro.com/artifactory/vmtemplates-qa-vm-images"  
    api_token = os.getenv("JFROG_API_TOKEN")

    repo_path = create_repo_path(email, image_url) # Create the repo path dynamically

    try:
        image_response = requests.get(image_url, stream=True)  # stream the image directly from the URL (without downloading)
        
        if image_response.status_code == 200:
            artifactory_upload_url = f"{artifactory_url}/{repo_path}"

            headers = {
                'Authorization': f'Bearer {api_token}',
                'Content-Type': image_response.headers.get('Content-Type', 'application/octet-stream')  # Use the content type of the image
            }

            log_to_database(process_id, "The process of uploading image to Artifactory has started.",'RUNNING', image_url, "Artifactory Upload")
            response = requests.put(
                artifactory_upload_url, 
                data=image_response.raw,  
                headers=headers
            )

            if response.status_code == 201:
                # print(f"Image uploaded successfully to the Artifactory {repo_path}.")
                logging.info(f"Image successfully uploaded to Artifactory {artifactory_upload_url}.")
                log_to_database(process_id, f"IImage successfully uploaded to Artifactory. Repo path: {artifactory_upload_url}.",'SUCCEEDED', image_url, "Artifactory Upload")
                add_comment_to_jira_task(task_key, f"Image successfully uploaded to Artifactory. Repo path: {artifactory_upload_url}.")
                
            else:
                # print(f"Failed to upload image. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                logging.error(f"Failed to upload image. Status code: {response.status_code}. Response: {response.text}")
                log_to_database(process_id, f"Failed to upload image. Status code: {response.status_code}. Response: {response.text}",'FAILED', image_url, "Artifactory Upload")
                add_comment_to_jira_task(task_key, f"Failed to upload image. Status code: {response.status_code}. Response: {response.text}")
        else:
            print(f"Failed to download image from URL. Status code: {image_response.status_code}")
            log_to_database(process_id, f"Failed to download image from URL. Status code: {image_response.status_code}",'FAILED', image_url, "Artifactory Upload")
            logging.error(f"Failed to download image from URL. Status code: {image_response.status_code}")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    image_url = sys.argv[1]
    email = sys.argv[2]
    process_id = sys.argv[3]
    task_key = sys.argv[4]
    upload_image_from_url_to_artifactory(image_url, email, process_id, task_key)