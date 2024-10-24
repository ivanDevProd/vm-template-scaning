import requests
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import logging
import pandas as pd
import gspread

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

def create_spreadsheets_for_each_process_id():
    try:
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()
        cursor.execute('SELECT process_ID, packages, source_url FROM raw_Installations')
        packages_data = cursor.fetchall()

        df = pd.DataFrame(packages_data, columns=['process_ID', 'packages', 'source_url'])

        folder_id = '1U5Vo1pfM9XYaW_KIOVbNSGMr_3beVG7r'  # Your folder ID

        gspread_client = gspread.service_account(filename="/home/noc_admin/image_scanner_project/tech-support-automation-11363608fad2.json")

        # Iterate over the unique process_IDs and create separate sheets
        for process_id in df['process_ID'].unique():
            # Filter the DataFrame for the current process_id
            df_filtered = df[df['process_ID'] == process_id]

            # Extract the source_url and packages for the current process_id
            source_url = df_filtered['source_url'].values[0]
            packages = df_filtered['packages'].values[0]

            # Split packages by the paragraph symbol (or newline, "\n")
            package_rows = packages.split('\n')  # Split by newline or other delimiter if applicable

            # Define a unique spreadsheet name for each process_id
            spreadsheet_name = f"{process_id}"

            # Create a new Google Sheet for the current process_id in the specified folder
            spreadsheet = gspread_client.create(spreadsheet_name, folder_id=folder_id)
            print(f"Spreadsheet created successfully for process_ID {process_id}: {spreadsheet.url}")

            # Select the first sheet
            worksheet = spreadsheet.get_worksheet(0)

            # Prepare data with header row
            data = [['process_ID', 'package', 'source_url']]  # Header row

            # Add each package row into the Google Sheet
            for package_row in package_rows:
                data.append([process_id, package_row.strip(), source_url])  # Strip removes any leading/trailing spaces

            # Update the sheet with the data
            worksheet.update(data, 'A1')
            print(f"Data for process_ID {process_id} successfully written to Google Sheet.")

            # Log success in the database
            log_to_database(process_id, f"Spreadsheet with raw data about installed packages uploaded/created successfully to Gdrive: {spreadsheet.url}", "SUCCEEDED", source_url, "G-drive raw report")

            # Delete the process_ID from the table after successful spreadsheet creation
            cursor.execute('DELETE FROM raw_Installations WHERE process_ID = %s', (process_id,))
            conn.commit()  # Commit the changes to the database
            print(f"process_ID {process_id} successfully deleted from the database.")

    except gspread.exceptions.APIError as e:
        print(f"An API error occurred: {e}")
        log_to_database(process_id, f"An API error occurred during uploading/creating the spreadsheet with raw data about installed packages on G-Drive: {e}", "FAILED", source_url, "G-drive raw report")
    except Exception as e:
        print(f"An error occurred: {e}")
        log_to_database(process_id, f"An error occurred during uploading/creating the spreadsheet with raw data about installed packages on G-Drive: {e}", "FAILED", source_url, "G-drive raw report")
    finally:
        # Close database connection
        cursor.close()
        conn.close()


if __name__ == '__main__':
    create_spreadsheets_for_each_process_id()
