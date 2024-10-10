import requests
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import logging

# Load the .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)

# DB parameters
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")

# DB config
mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': MYSQL_HOST,
    'database': 'vm_template_scan',
    'port': '3306'
}


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


# Function to generate a new access token based on the refresh token stored in DB
def create_new_access_token():
    try:
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()

        cursor.execute("SELECT refresh_token FROM vm_template_scan.flexera_tokens_prod LIMIT 1")
        current_tokens = cursor.fetchone()

        if not current_tokens:
            logging.error("No refresh token found in database")
            return None

        # Generating a new access token
        url = "https://login.flexera.com/oidc/token"
        payload = f'grant_type=refresh_token&refresh_token={current_tokens[0]}'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = requests.post(url, headers=headers, data=payload)

        if response.status_code != 200:
            logging.error(f"Error fetching access token: {response.status_code}")
            return None

        response_json = response.json()
        new_access_token = response_json.get('access_token')

        if new_access_token:
            # Use parameterized query to prevent SQL injection
            cursor.execute("UPDATE vm_template_scan.flexera_tokens_prod SET access_token = %s", (new_access_token,))
            conn.commit()
        else:
            logging.error("No access token in response")

        return new_access_token

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# Function to retrieve the current number_of_checks for a given hostname
def get_number_of_checks(hostname):
    conn = mysql.connector.connect(**mysql_config)
    cursor = conn.cursor()

    query = "SELECT number_of_checks FROM vm_template_scan.waitForFlexera WHERE vm_hostname = %s"
    
    cursor.execute(query, (hostname,))
    result = cursor.fetchone()
    
    cursor.close()
    conn.close()

    if result:
        return result[0]
    else:
        return None
    
def get_process_ID(hostname):
    conn = mysql.connector.connect(**mysql_config)
    cursor = conn.cursor()

    query = "SELECT process_ID FROM vm_template_scan.waitForFlexera WHERE vm_hostname = %s"
    
    cursor.execute(query, (hostname,))
    result = cursor.fetchone()
    
    cursor.close()
    conn.close()

    if result:
        return result[0]
    else:
        return None


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
            cursor.execute("SELECT vm_hostname FROM vm_template_scan.waitForFlexera")
            return [x[0] for x in cursor.fetchall()]
    except mysql.connector.Error as err:
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
            logging.error(f"Error fetching report: {response.status_code}")
            return None
    except requests.RequestException as e:
        logging.error(f"Request error: {e}")
        return None


# Function to check for commercial software and return a dictionary of hostname and application names
def check_commercial_software(report_data):
    commercial_software_list = []

    if "values" in report_data:
        for item in report_data["values"]:
            classification = item.get("R3_5d630f71104d446b1788c0e4d47c9de3_InstallationToApplication_Classification", "")

            # Check if the classification is "Commercial"
            if classification and classification.lower() == "commercial":
                application_name = item.get("R2_4b7b120890bd74197bace50e3658cfdc_ComputerToInstallation_ApplicationName", "Unknown")
                commercial_software_list.append(application_name)

    return commercial_software_list


def run_flexera_checks():
    org_id = "35715"
    report_id = "351"  # name of report: "Checking the existence of the machine & apps (VM Image scan ...)"
    access_token = create_new_access_token()

    # hostnames = vmListToCheckOnFlexera()
    hostnames = ['DPRO_AUTOMATION_1728469955', 'DPRO_AUTOMATION_1728468621', 'GRW0MP6649']

    for hostname in hostnames:
        # Get the current number_of_checks before incrementing
        current_checks = get_number_of_checks(hostname)
        print(f"Checking hostname: {hostname}. (Checked {current_checks} times so far.)")

        process_id = get_process_ID(hostname)
        
        report_data = get_flexera_report(org_id, report_id, hostname, access_token)

        # Check if the report data is not empty
        if report_data:
            if "values" in report_data and report_data["values"]:
                # Total number of applications (all types)
                total_apps_found = len(report_data["values"])
                commercial_software_list = check_commercial_software(report_data)

                # total count of applications
                print(f"Total applications found for {hostname}: {total_apps_found}")
                
                if commercial_software_list:
                    print(f"Commercial software found for {hostname}:")
                    list_of_commercial_apps = []
                    for application_name in commercial_software_list:
                        list_of_commercial_apps.append(application_name)
                        print(f"- {application_name}")
                    log_to_database(process_id, f"Commercial software found for {hostname}: {list_of_commercial_apps}. Machine should be removed from Artifactory.", "INFO", "-", "FLEXERA REPORT")
                else:
                    print(f"No commercial software found for {hostname}.")
                    if total_apps_found > 5 or current_checks > 3:
                        print(f"Machine {hostname} can be deleted from cluster.")
                        log_to_database(process_id, f"No commercial software found for {hostname}. It can be deleted from cluster. (Applications found: {total_apps_found}, Checked: {current_checks} times.)", "INFO", "-", "FLEXERA REPORT")
                    else:
                        log_to_database(process_id, f"No commercial software found for {hostname}. Waiting for the next check tomorrow, because the number of applications found is {total_apps_found}, and the number of checks so far is {current_checks}", "INFO", "-", "FLEXERA REPORT")
                
                # Increment the number_of_checks in the database
                increment_number_of_checks(hostname)

            else:
                print(f"Machine not found for hostname: {hostname}.")

                # Increment the number_of_checks in the database
                increment_number_of_checks(hostname)
                log_to_database(process_id, f"No matching inventory: {hostname} in Flexera. Waiting for the next check tomorrow. Number of checks: {current_checks}", "INFO", "-", "FLEXERA REPORT")
        else:
            print(f"Error fetching report or no data returned for hostname: {hostname}.")
            log_to_database(process_id, f"Error fetching report or no data returned for hostname: {hostname}. Check flexeraInventoryChecker.py script or Flexera API issues.", "INFO", "-", "FLEXERA REPORT")


if __name__ == '__main__':
    run_flexera_checks()
