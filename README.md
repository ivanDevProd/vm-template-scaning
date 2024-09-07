# vm-template-scaning

**WORKFLOW:**
1. Receive Image URL from Endor or Other Filer

 - Input: A URL to a system image stored on Endor or another file storage system.
 - Process: Retrieve the system image URL from the requester or automated trigger.
 - Action: Store the image URL for further operations.

2. Analyze Image Extension and Perform Necessary Extractions
- Process: Identify the system image type (e.g., .iso, .img, .qcow2).
- Action:
  a. If it's a compressed format (e.g., .zip, .tar), extract it
  b. Depending on the image type, validate its integrity (e.g., using md5sum or sha256sum checks).
  c. Prepare the image for deployment if required (e.g., converting to a format suitable for your infrastructure).
  d. Upload the Image to the Cluster

3. Process: Transfer the image to the cluster where VMs can be spun up.
Action:
Upload the image to the target cluster using SCP, SFTP, or an API, depending on your infrastructure.
Store the image in the cluster’s designated image repository.
Spin Up VM with Image

4. Process: Create a virtual machine using the uploaded image.
Action:
Use cloud infrastructure (e.g., OpenStack, AWS, VMware) or an on-premise system to provision a new VM.
Select the system image for VM creation.
Apply necessary configuration, such as networking and storage.
Install Flexera Agent on the VM

5. Process: Deploy the Flexera agent to the VM for tracking and compliance.
Action:
Download and install the Flexera agent on the spun-up VM.
Configure the agent with the necessary credentials and settings for Flexera.
Check Flexera Logs

6. Process: Verify that the Flexera agent is working correctly.
Action:
Check the logs on the VM or in the Flexera dashboard to confirm that the agent is running and successfully communicating with Flexera.
Check Flexera Report for VM

7. Process: Validate that the VM has been included in the Flexera inventory and is being reported.
Action:
Review the Flexera dashboard or reports to ensure the VM is listed and tracked.
Confirm that the correct license usage and compliance data is being collected.
Terminate the Machine from the Cluster

8. Process: Once the system has been validated, shut down and remove the VM.
Action:
Decommission the VM using cloud or on-premise management tools.
Ensure the resources are released and the VM is no longer listed in the cluster.
Upload the System Image to Artifactory

9. Process: Store the validated system image in Artifactory for future use or distribution.
Action:
Upload the image to Artifactory using the Artifactory API or interface.
Tag the image with metadata, including version, description, and deployment details.
Ensure the image is accessible for future use or retrieval by authorized personnel.
Summary of Key Steps:
Receive and analyze the system image.
Perform necessary extractions and upload it to the cluster.
Spin up a VM, install Flexera, and validate reports.
Terminate the VM, then upload the image to Artifactory.


**FIX:**
 - Centos 7/8 became a deprecated system. A potential solution is to Include a repo setup step so that it can install the necessary packages. Use rpm packages for repo config. (yum install -y http://10.67.21.111/images/artifactory-centos-rocky-1.1-1.el9.noarch.rpm)...
 - Exclude VM renaming in case of failed_commands and commands retrying.


**BACKLOG:**
- Integrate opening a Jira ticket for the process and log all the steps there.
- Check possibilities for tracking who triggered the Scan Process. Notify the user and eng_sam_admins via email about the Jira case. Maybe add a field to enter a user's email address or integrate login with the AD account...
- Migrate to a new server with a bigger HDD capacity if we want to use it as a mounting point for extracting tar.gz files before uploading images to the cluster.
- Create a new UI for the end-user self-service process, with appropriate necessary fields in case of a self-service process.
- HA, DR, Backup

- Improve the loging of the process. Add details and modify the format.
- After entering the URL on the Dashboard, reload the page and display a popup message about success/failure. Change the format of the popup message.

- Add info about network configuration for Win VMs to logs. (PS command: _Get-NetIPConfiguration_)
- Consider introducing a command to set up DHCP for address and DNS. Address PS command: _Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Enabled_ DHCP POS command: _Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ResetServerAddresses_

- In the first “Cluster Image Upload” stage, add details about img size. It can indicate why this step takes so long in some cases. 
- In the first “Cluster Image Upload” stage, add details about the cluster on which the img is uploading (beg-cluster, so the user can check the progress.
