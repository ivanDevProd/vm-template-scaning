from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import URLInputForm, FileUploadForm
import json
from .scripts import uploadeImageToCluster_v2
from django.db import connection
import subprocess
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import time
import os
import logging


def parse_urls(urls):
    url_list = [url.strip() for url in urls.split(';') if url.strip()]
    json_data = []
    for url in url_list:
        parts = url.split('/')
        if len(parts) > 2:
            name_part = parts[-2] + '-' + parts[-1] if parts[-1] else parts[-3] + '-' + parts[-2]
        else:
            name_part = url.replace('/', '-')
        # name = "DPRO-UNSUPPORTED-" + name_part.replace('/', '-')
        name = "DPRO-AUTOMATION-" + name_part.replace('/', '-')
        data = {
            "spec": {
                "name": name,
                "description": url,
                "resources": {
                    "image_type": "DISK_IMAGE",
                    "source_uri": url
                }
            },
            "api_version": "3.1.0",
            "metadata": {
                "kind": "image"
            }
        }
        json_data.append(data)
        # print(json_data)
    return json_data

def checkWorkflows():
    cursor = connection.cursor()
    cursor.execute("""
                    SELECT *
                    FROM (
                        SELECT *,
                            ROW_NUMBER() OVER (PARTITION BY process_ID ORDER BY timestamp DESC) AS rn
                        FROM vm_template_scan.workflow_state
                    ) subquery
                    WHERE rn = 1
                    ORDER BY timestamp DESC;  -- Ensure newest process_ID first
                """)
    existing_processes = cursor.fetchall()
    return existing_processes

# Path to the processes subfolder
log_directory = '/home/noc_admin/image_scanner_project/logs/processes/'

def url_input_view(request):
    if request.method == 'POST':
        # Handling URL input
        if 'urls' in request.POST:
            form = URLInputForm(request.POST)
            if form.is_valid():
                urls = form.cleaned_data['urls']
                json_data_list = parse_urls(urls)  # Ensure this function is defined

                # Create the logs/processes folder if it doesn't exist
                os.makedirs(log_directory, exist_ok=True)

                for json_data in json_data_list:
                    json_data_str = json.dumps(json_data, indent=4)
                    script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/uploadeImageToCluster_v2.py'

                    # Generate unique log file for each process
                    source_url = json_data['spec']['resources']['source_uri']
                    sanitized_source_url = source_url.replace('/', '_').replace(':', '_')  # Ensure the filename is valid
                    log_file_for_process = os.path.join(log_directory, f"{sanitized_source_url}_process.log")

                    # Open the log file for writing output
                    with open(log_file_for_process, 'w') as log_file:
                        command = ["/usr/bin/cpulimit", "--limit=90", "--", "python3", script_path, json_data_str]
                        try:
                            subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT)
                            logging.info(f"Started scanning process for URL{file.name if 'file' in request.FILES else source_url}, logging to {log_file_for_process}")
                        except Exception as e:
                            logging.error(f"Failed to start scanning process for {file.name if 'file' in request.FILES else source_url}: {e}")
                            messages.error(request, f"Failed to initiate scanning for {file.name if 'file' in request.FILES else source_url}.")

                        messages.success(request, f"Scanning initiated for {source_url} image.")

                return redirect('scanIt')  # Redirect after form submission
            else:
                return render(request, 'scanIt.html', {'form': form, 'latest_entries': checkWorkflows()})
        
        # Handling file upload
        elif 'file' in request.FILES:
            file_form = FileUploadForm(request.POST, request.FILES)
            if file_form.is_valid():
                file = request.FILES['file']
                file_path = handle_uploaded_file(file)

                # Run the Python script with the file path
                script_path = '/home/noc_admin/image_scanner_project/scanIt/scripts/uploade_Local_ImageToCluster_v1.py'
                log_file_for_process = os.path.join(log_directory, f"{file.name}_process.log")

                with open(log_file_for_process, 'w') as log_file:
                    command = ["/usr/bin/cpulimit", "--limit=90", "--", "python3", script_path, file_path]
                    try:
                        subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT)
                        logging.info(f"Started scanning process for {file.name}, logging to {log_file_for_process}")
                        messages.success(request, f"File {file.name} uploaded and scanning initiated.")
                    except Exception as e:
                        logging.error(f"Failed to start scanning process for {file.name}: {e}")
                        messages.error(request, f"Failed to initiate scanning for {file.name}.")

                return redirect('scanIt')  # Redirect after file submission
            else:
                for error in file_form.errors:
                    messages.error(request, f"{error}: {file_form.errors[error]}")
                return render(request, 'scanIt.html', {'form': FileUploadForm(),'file_form':file_form, 'latest_entries': checkWorkflows()})

    latest_entries = checkWorkflows() if request.user.is_authenticated else None
    form = URLInputForm()
    file_form = FileUploadForm()

    return render(request, 'scanIt.html', {'form': form, 'file_form': file_form, 'latest_entries': latest_entries})

def handle_uploaded_file(f):
    upload_path = '/home/noc_admin/image_scanner_project/downloads/'  # Path where the file will be saved
    os.makedirs(upload_path, exist_ok=True)
    file_path = os.path.join(upload_path, f.name)
    with open(file_path, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return file_path


def update_entry(request):
    process_id = request.GET.get('process_id')
    print(process_id)
    if process_id:
        try:
            cursor = connection.cursor()
            # Latest timestamp for the given process ID
            cursor.execute("""
                SELECT MAX(timestamp)
                FROM vm_template_scan.workflow_state
                WHERE process_ID = %s
            """, [process_id])
            latest_timestamp = cursor.fetchone()[0]

            # Update the stage for the row with the latest timestamp
            cursor.execute("""
                UPDATE vm_template_scan.workflow_state
                SET uploaded_to_artifactory = 1
                WHERE process_ID = %s AND timestamp = %s
            """, [process_id, latest_timestamp])
            connection.commit()
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    else:
        return JsonResponse({'success': False, 'error': 'Invalid process ID'})
    

def help_page(request):
    return render(request, 'help.html')