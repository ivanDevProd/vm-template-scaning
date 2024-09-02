# vm-template-scaning

**WORKFLOW:**
1. Download the image from Endor or other path
2. Analyze extension and perform different extractions if necessary, depending on the image type
3. Upload the Image to the cluster
4. Spin up VM with image
5. Install Flexera agent on the image
6. Check the Flexera logs 
7. Check the Flexera report for VM
8. Terminate the machine from the cluster
9. Upload the Image from Endor to Artifactory


**FIX:**
 - Centos 7/8 became a deprecated system. A potential solution is to Include a repo setup step, so it can install necessary packages. Use rpm packages for repo config. (yum install -y http://10.67.21.111/images/artifactory-centos-rocky-1.1-1.el9.noarch.rpm) 



**BACKLOG:**
- Integrate opening a Jira ticket for the process and log all the steps there.
- Check possibilities for tracking who triggered the Scan Process. Notify the user and eng_sam_admins via email about the Jira case. Maybe add a field to enter a user's email address or integrate login with the AD account...
- We need to migrate to a new server with a bigger HDD capacity if we want to use it as a mounting point for extracting tar.gz files before uploading images to the cluster.
- Create a new UI for the end-user self-service process, with appropriate necessary fields in case of a self-service process.
- Think about HA, DR

- Improve the loging of the process. Add details and modify the format.
- After entering the URL on the Dashboard, reload the page and display a popup message about success/failure. Change the format of the popup message. 
- In the first “Cluster Image Upload” stage, add details about img size. It can indicate why this step takes so long in some cases. 
- In the first “Cluster Image Upload” stage, add details about the cluster on which the img is uploading (beg-cluster, so the user can check the progress.
