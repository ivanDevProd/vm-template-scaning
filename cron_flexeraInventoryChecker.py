import requests
from requests.exceptions import RequestException
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import logging
import pandas as pd
import gspread
import json

# Load the .env file
os.environ.pop("JIRA_BEARER_TOKEN", None) #  clear Cached Variables
load_dotenv()

logging.basicConfig(
    filename='flexera_inventory_check.log',  
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# DB parameters
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")

# Cluster variables
CLUSTER_IP = os.getenv("CLUSTER_IP")
CLUSTER_USERNAME = os.getenv("CLUSTER_USERNAME")
CLUSTER_PASSWORD = os.getenv("CLUSTER_PASSWORD")


# DB config
mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': MYSQL_HOST,
    'database': 'vm_template_scan',
    'port': '3306'
}

# Jira parameters 
jira_bearer_token = os.getenv("JIRA_BEARER_TOKEN")
# jira_base_url = "https://jira.nutanix.com/"
jira_base_url = "https://jiradev.nutanix.com"

# Function for adding comment in Jira case
def add_comment_to_jira_task(task_key, comment):
    try:
        jira_headers = {
            "Authorization": f"Bearer {jira_bearer_token}",
            "Content-Type": "application/json"
        }
        
        comment_payload = {"body": comment}
        comment_url = f"{jira_base_url}/rest/api/2/issue/{task_key}/comment"

        # Log the headers, payload, and URL for debugging
        print(f"URL: {comment_url}")
        logging.info(f"URL: {comment_url}")
        print(f"Headers: {jira_headers}")
        logging.info(f"Headers: {jira_headers}")
        print(f"Payload: {comment_payload}")
        logging.info(f"Payload: {comment_payload}")

        response = requests.post(comment_url, headers=jira_headers, data=json.dumps(comment_payload), timeout=15)

        if response.status_code == 201:
            print("Comment added successfully to Jira")
            logging.info("Comment added successfully to Jira")
        else:
            print(f"Failed to add Jira comment: {response.status_code}, {response.text}")
            logging.error(f"Failed to add Jira comment: {response.status_code}, {response.text}")

    except requests.Timeout:
        print("The request timed out!")
        logging.error("The request timed out!")

    except requests.ConnectionError:
        print("A connection error occurred!")
        logging.error("A connection error occurred!")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")


def change_jira_task_status(task_key, transition_id):
    try:
        jira_headers = {
            "Authorization": f"Bearer {jira_bearer_token}",
            "Content-Type": "application/json"
        }

        # payload to change the status using transition ID
        transition_payload = {
            "transition": {
                "id": transition_id
            }
        }

        transition_url = f"{jira_base_url}/rest/api/2/issue/{task_key}/transitions"
        response = requests.post(transition_url, headers=jira_headers, data=json.dumps(transition_payload), timeout=15)

        if response.status_code == 204:
            print("Status changed successfully!")
            logging.info("Status changed successfully!")
        else:
            print(f"Failed to change status: {response.status_code}, {response.text}")
            logging.error(f"Failed to change status: {response.status_code}, {response.text}")

    except requests.Timeout:
        print("The request timed out!")
        logging.error("The request timed out!")

    except requests.ConnectionError:
        print("A connection error occurred!")
        logging.error("A connection error occurred!")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")



def delete_vm(vm_uuid, process_id, source_url, jira_task_key):
    try:
        delete_response = requests.delete(
            f"https://{CLUSTER_IP}:9440/api/nutanix/v3/vms/{vm_uuid}",
            auth=(CLUSTER_USERNAME, CLUSTER_PASSWORD), 
            verify=False
        )
        
        # Check the response status code
        if delete_response.status_code == 202:
            print(f"VM with ID {vm_uuid} deleted successfully.")
            logging.info(f"VM with ID {vm_uuid} deleted successfully.")
            log_to_database(process_id, f"VM with ID {vm_uuid} deleted successfully.", "SUCCEEDED", source_url, "VM Termination")

            # removing VM record from the waitForFlexera DB table
            try:
                # Establish a database connection
                conn = mysql.connector.connect(**mysql_config)
                cursor = conn.cursor()

                # Execute the DELETE statement
                cursor.execute(
                    '''
                    DELETE FROM vm_template_scan.waitForFlexera 
                    WHERE vm_uuid = %s
                    ''',
                    (vm_uuid,)  # The provided UUID to match
                )

                # Commit the changes to the database
                conn.commit()

                # Log success messages
                print(f"VM with ID {vm_uuid} deleted successfully from waitForFlexera DB table.")
                logging.info(f"VM with ID {vm_uuid} deleted successfully from waitForFlexera DB table.")
                
                log_to_database(process_id, f"VM with ID {vm_uuid} deleted successfully from <waitForFlexera> DB table.", "SUCCEEDED", source_url, "VM Termination")
                log_to_database(process_id, "The entire scanning process has been successfully completed!", "SUCCEEDED", source_url, "END")

            except mysql.connector.Error as err:
                # Handle database connection errors or query execution errors
                logging.error(f"An error occurred while deleting VM record with ID. Error: {err}")
                print(f"An error occurred while deleting VM record with ID. Error: {err}")

                log_to_database(process_id, f"An error occurred while deleting VM record with ID: {vm_uuid} from <waitForFlexera> DB table: {err}", "FAILED", source_url, "VM Termination")
                log_to_database(process_id, "The entire scanning process has been successfully completed!", "SUCCEEDED", source_url, "END")

            except Exception as e:
                # Handle any other exceptions
                logging.error(f"An unexpected error occurred: {e}")
                print(f"An unexpected error occurred: {e}")

                log_to_database(process_id, f"An unexpected error occurred: {e}. Please check repo", "FAILED", source_url, "VM Termination")
                log_to_database(process_id, "The entire scanning process has been successfully completed!", "SUCCEEDED", source_url, "END")

            finally:
                # Close the cursor and connection
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()

            add_comment_to_jira_task(jira_task_key, "VM deleted successfully from the cluster.")
            add_comment_to_jira_task(jira_task_key, "Scanning process completed successfully!")
            
        else:
            logging.error(f"Failed to delete VM with ID {vm_uuid}: {delete_response.status_code}")
            print(f"Failed to delete VM with ID {vm_uuid}: {delete_response.status_code}")

            log_to_database(process_id, f"Failed to delete VM with ID {vm_uuid}: {delete_response.status_code} on the cluster.", "FAILED", source_url, "VM Termination")

    except RequestException as e:
        print(f"An error occurred while trying to delete VM with ID {vm_uuid}: {e}")
        logging.error(f"An error occurred while trying to delete VM with ID {vm_uuid}: {e}")


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
        print(f"Database error: {err}")
        logging.error(f"Database error: {err}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# Function to generate a new access token based on the refresh token stored in DB
def create_new_access_token():
    try:
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()

        cursor.execute("SELECT refresh_token FROM vm_template_scan.flexera_tokens_prod LIMIT 1")
        current_tokens = cursor.fetchone()

        if not current_tokens:
            print("No refresh token found in database")
            logging.error("No refresh token found in database")
            return None

        # Generating a new access token
        url = "https://login.flexera.com/oidc/token"
        payload = f'grant_type=refresh_token&refresh_token={current_tokens[0]}'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = requests.post(url, headers=headers, data=payload)

        if response.status_code != 200:
            print(f"Error fetching access token: {response.status_code}")
            logging.error(f"Error fetching access token: {response.status_code}")
            return None

        response_json = response.json()
        new_access_token = response_json.get('access_token')

        if new_access_token:
            # Use parameterized query to prevent SQL injection
            cursor.execute("UPDATE vm_template_scan.flexera_tokens_prod SET access_token = %s", (new_access_token,))
            conn.commit()
        else:
            print("No access token in response")
            logging.error("No access token in response")

        return new_access_token

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        logging.error(f"Database error: {err}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def increment_number_of_checks(hostname):
    conn = mysql.connector.connect(**mysql_config)
    cursor = conn.cursor()

    # Query to increment the number_of_checks for the given hostname
    query = "UPDATE vm_template_scan.waitForFlexera SET number_of_checks = number_of_checks + 1 WHERE vm_hostname = %s"
    
    cursor.execute(query, (hostname,))
    conn.commit()
    
    # Clean up
    cursor.close()
    conn.close()


def vmListToCheckOnFlexera():
    try:
        with mysql.connector.connect(**mysql_config) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT vm_hostname, process_ID, vm_uuid, number_of_checks, source_url, new_jira_task FROM vm_template_scan.waitForFlexera")
            # print(cursor.fetchall())
            return cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Error fetching VM list: {err}")
        logging.error(f"Error fetching VM list: {err}")
        return []


# Flexera API base URL
api_base_url = "https://api.flexera.com/fnms/v1/orgs/{orgId}/reports/{reportId}/execute"

def get_flexera_report(org_id, report_id, search_text, access_token):
    url = api_base_url.format(orgId=org_id, reportId=report_id)

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    params = {
        'searchText': search_text  # If empty, it will return all results
    }

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching report: {response.status_code}")
            logging.error(f"Error fetching report: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        logging.error(f"Request error: {e}")
        return None
    

def create_google_sheet_from_df(df, spreadsheet_name, folder_id, process_id, source_url):
    """Creates a new Google Sheet in a specified folder and populates it with data from a pandas DataFrame."""
    try:
        # Create a new Google Sheet in the specified folder
        gspread_client = gspread.service_account(filename="/home/noc_admin/image_scanner_project/tech-support-automation-11363608fad2.json")
        spreadsheet = gspread_client.create(spreadsheet_name, folder_id=folder_id)

        print(f"Spreadsheet created successfully: {spreadsheet.url}")
        logging.info(f"Spreadsheet created successfully: {spreadsheet.url}")

        # Select the first sheet
        worksheet = spreadsheet.get_worksheet(0)

        # Prepare data from the DataFrame to insert into the sheet
        data = [df.columns.values.tolist()] + df.values.tolist()  # Header and values

        # Update the sheet with data
        worksheet.update(data, 'A1')
        print("Data successfully written to Google Sheet.")
        logging.info("Data successfully written to Google Sheet.")
        log_to_database(process_id, f"Machine information is found on the Flexera. Flexera report successfully uploaded/created on Google Drive: {spreadsheet.url}", "SUCCEEDED", source_url, "FLEXERA REPORT")

    except gspread.exceptions.APIError as e:
        print(f"An API error occurred during uploading/creating Flexera report document on G-Drive: {e}")
        logging.error(f"An API error occurred during uploading/creating Flexera report document on G-Drive: {e}")
        log_to_database(process_id, f"An API error occurred during uploading/creating Flexera report document on G-Drive: {e}", "FAILED", source_url, "FLEXERA REPORT")
    except Exception as e:
        print(f"An API error occurred during uploading/creating Flexera report document on G-Drive: {e}")
        logging.error(f"An API error occurred during uploading/creating Flexera report document on G-Drive: {e}")
        log_to_database(process_id, f"An API error occurred during uploading/creating Flexera report document on G-Drive: {e}", "FAILED", source_url, "FLEXERA REPORT")


# Function to check for commercial software and return a dictionary of hostname and application names
def check_commercial_software(report_data):
    found_commercial_software_list = []

    if "values" in report_data:
        for item in report_data["values"]:
            classification = item.get("R3_5d630f71104d446b1788c0e4d47c9de3_InstallationToApplication_Classification", "")

            # Check if the classification is "Commercial"
            if classification and classification.lower() == "commercial":
                application_name = item.get("R2_4b7b120890bd74197bace50e3658cfdc_ComputerToInstallation_ApplicationName", "Unknown")
                found_commercial_software_list.append(application_name)

    expected_commercial_apps = ['Windows 10 Enterprise', 'Windows Server 2019 Standard']
    attention_list = [app for app in found_commercial_software_list if app not in expected_commercial_apps]

    return found_commercial_software_list, expected_commercial_apps, attention_list


def run_flexera_checks():
    org_id = "35715"
    report_id = "351"  # name of report: "Checking the existence of the machine & apps (VM Image scan ...)"
    access_token = create_new_access_token()

    hostnames = vmListToCheckOnFlexera()
    hostnames = [item for item in hostnames if item[0] != "-"]
    # hostnames = ['DPRO_AUTOMATION_1728469955', 'DPRO_AUTOMATION_1728468621', 'GRW0MP6649']
    # print(hostnames)

    for hostname in hostnames:
        # print(hostname[0])
        # Get the current number_of_checks before incrementing
        current_checks = int(hostname[3])
        print(f"Checking hostname: {hostname[0]}. (Checked {current_checks} times so far.)")
        logging.info(f"Checking hostname: {hostname[0]}. (Checked {current_checks} times so far.)")

        jira_task_key = hostname[5]
        print(f"Jira task: {jira_task_key}")
        logging.info(f"Jira task: {jira_task_key}")
        process_id = hostname[1]
        print(f"Process ID: {process_id}")
        logging.info(f"Process ID: {process_id}")
        # print(process_id)
        
        report_data = get_flexera_report(org_id, report_id, hostname[0], access_token)

        # Check if the report data is not empty
        if report_data:
            if "values" in report_data and report_data["values"]:
                # Total number of applications (all types)
                total_apps_found = len(report_data["values"])

                extracted_data = []
                for computer_info in report_data["values"]:
                    computer_name = computer_info['ComputerName']
                    app_name = computer_info['R2_4b7b120890bd74197bace50e3658cfdc_ComputerToInstallation_ApplicationName']
                    classification = computer_info['R3_5d630f71104d446b1788c0e4d47c9de3_InstallationToApplication_Classification']
                    
                    extracted_data.append({
                        'ComputerName': computer_name,
                        'ApplicationName': app_name,
                        'Classification': classification
                    })

                # Create a DataFrame
                df = pd.DataFrame(extracted_data)

                # Create a Google Sheet from the DataFrame in the specified folder
                folder_id = '1U5Vo1pfM9XYaW_KIOVbNSGMr_3beVG7r' # Ivan's Gdrive Self-Service Reporting (change to ENG Gdrive...)
                file_name = hostname[0]+ f' - {hostname[1]}'
                source_url = hostname[4]
                create_google_sheet_from_df(df, file_name, folder_id, process_id, source_url)

                # classification of registered applications
                found_commercial_software_list, expected_commercial_apps, attention_list = check_commercial_software(report_data)

                # total count of applications
                print(f"Total applications found for {hostname[0]}: {total_apps_found}")
                logging.info(f"Total applications found for {hostname[0]}: {total_apps_found}")

                if found_commercial_software_list:
                    if total_apps_found > 5 or current_checks > 3:
                        print(f"Commercial software found for {hostname[0]}:")
                        logging.info(f"Commercial software found for {hostname[0]}:")

                        list_of_commercial_apps = []
                        for application_name in found_commercial_software_list:
                            list_of_commercial_apps.append(application_name)
                            logging.info(f"- {application_name}")

                        log_to_database(process_id, f"Commercial software found for {hostname[0]}: {list_of_commercial_apps}.", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                        log_to_database(process_id, f"Anticipated commercial applications on Windows VMs: {expected_commercial_apps}", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                        
                        if len(attention_list) == 0:
                            log_to_database(process_id, f"No unauthorized commercial applications are present.", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                            log_to_database(process_id, f"Removing VM: {hostname[0]}, UUID: {hostname[2]} initiated", "INITIATED", f"{hostname[4]}", "VM Termination")
                            add_comment_to_jira_task(jira_task_key, f"Commercial software found for {hostname[0]}: {list_of_commercial_apps}. There are no unauthorized commercial applications to be aware of. Scanning process completed succesfuly.")
                            
                            delete_vm(hostname[2], process_id, hostname[4], hostname[5])

                        else:
                            log_to_database(process_id, f"Unauthorized commercial applications: {attention_list}", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                            log_to_database(process_id, f"The machine should be removed from Artifactory. After conducting {current_checks} checks, {total_apps_found} applications were found, with {len(attention_list)} unauthorized commercial apps detected: {attention_list}", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                            
                            add_comment_to_jira_task(jira_task_key, f"Commercial software found for {hostname[0]}: {list_of_commercial_apps}. Unauthorized commercial applications: {attention_list}. Machine should be removed from Artifactory. Check with image owner!")
                            
                    else:
                        print(f"Commercial software found for {hostname[0]}:")
                        logging.info(f"Commercial software found for {hostname[0]}:")

                        list_of_commercial_apps = []
                        for application_name in found_commercial_software_list:
                            list_of_commercial_apps.append(application_name)
                            print(f"- {application_name}")

                        log_to_database(process_id, f"Commercial software found for {hostname[0]}: {list_of_commercial_apps}.", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                        log_to_database(process_id, f"Anticipated commercial applications on Windows VMs: {expected_commercial_apps}", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                        
                        if len(attention_list) == 0:
                            log_to_database(process_id, f"There are no unauthorized commercial applications to be aware of", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                            log_to_database(process_id, f"Awaiting the next check tomorrow, as the total applications found is {total_apps_found}, with {current_checks} checks completed so far.", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                            add_comment_to_jira_task(jira_task_key, f"No unauthorized commercial applications have been detected. Awaiting the next check tomorrow, as the total applications found is {total_apps_found}, with {current_checks} checks completed so far.")
                        else:
                            log_to_database(process_id, f"Unauthorized commercial applications: {attention_list}", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                            log_to_database(process_id, f"Awaiting the next check tomorrow, as the total applications found is {total_apps_found}, with {current_checks} checks completed so far.", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                            add_comment_to_jira_task(jira_task_key, f"List of unauthorized commercial applications: {attention_list}. Awaiting the next check tomorrow, as the total applications found is {total_apps_found}, with {current_checks} checks completed so far. ")

                else:
                    print(f"No commercial software found for {hostname[0]}.")
                    logging.info(f"No commercial software found for {hostname[0]}.")

                    if total_apps_found > 5 or current_checks > 3:
                        print(f"Machine {hostname[0]} can be deleted from the cluster.")
                        logging.info(f"Machine {hostname[0]} can be deleted from the cluster.")

                        log_to_database(process_id, f"No commercial software found for {hostname[0]}. It can be deleted from cluster. (Applications found: {total_apps_found}, Checked: {current_checks} times.)", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                        log_to_database(process_id, f"Removing VM: {hostname[0]}, UUID: {hostname[2]} initiated", "INITIATED", f"{hostname[4]}", "VM Termination")
                        add_comment_to_jira_task(jira_task_key, f"No commercial software found for {hostname[0]}. Scanning process completed succesfuly.")

                        # change ticket status from "In Progress" to "Approved" 
                        change_jira_task_status(jira_task_key, '201')
                        # change ticket status from "Approved" to "Done"
                        change_jira_task_status(jira_task_key, '211')

                        delete_vm(hostname[2], process_id, hostname[4], hostname[5])
                            
                    else:
                        log_to_database(process_id, f"No commercial software found for {hostname[0]}. Waiting for the next check tomorrow, because the number of applications found is {total_apps_found}, and the number of checks so far is {current_checks}.", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                        add_comment_to_jira_task(jira_task_key, f"No commercial software found for {hostname[0]}. Waiting for the next check tomorrow, because the number of applications found is {total_apps_found}, and the number of checks so far is {current_checks}.")

                increment_number_of_checks(hostname[0])

            else:
                print(f"Machine not found for hostname: {hostname[0]}.")
                logging.info(f"Machine not found for hostname: {hostname[0]}.")

                # Increment the number_of_checks in the database
                increment_number_of_checks(hostname[0])
                log_to_database(process_id, f"No matching inventory ({hostname[0]}) in Flexera. Waiting for the next check tomorrow. Number of checks: {current_checks}", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
                add_comment_to_jira_task(jira_task_key, f"No matching inventory ({hostname[0]}) in Flexera. Waiting for the next check tomorrow. Number of checks: {current_checks}")
        
        else:
            print(f"Error fetching report or no data returned for hostname: {hostname[0]}.")
            logging.error(f"Error fetching report or no data returned for hostname: {hostname[0]}.")

            log_to_database(process_id, f"Error fetching report or no data returned for hostname: {hostname[0]}. Check flexeraInventoryChecker.py script or Flexera API issues.", "INFO", f"{hostname[4]}", "FLEXERA REPORT")
            add_comment_to_jira_task(jira_task_key, f"Error fetching report or no data returned for hostname: {hostname[0]}. Check flexeraInventoryChecker.py script or Flexera API issues.")


if __name__ == '__main__':
    run_flexera_checks()
