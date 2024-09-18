from django.shortcuts import render, get_object_or_404
from django.db import connection

def process_details(request, process_id):
    # print(process_id)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM vm_template_scan.workflow_state WHERE process_ID = %s ORDER BY timestamp", [process_id])
    records = cursor.fetchall()
    # print(records)

    context = {
        'process_id': process_id,
        'records': records,
    }
    return render(request, 'vmTemplateEachProcess/process_details.html', context)
