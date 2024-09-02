# vm-template-scaning

1. Download the image from Endor or other path
2. Analyze extension and perform different extractions if necessary, depending on the image type
3. Upload the Image to the cluster
4. Spin up VM with image
5. Install Flexera agent on the image
6. Check the Flexera logs 
7. Check the Flexera report for VM
8. Terminate the machine from the cluster
9. Upload the Image from Endor to Artifactory



Backlog:
- Improve the loging of the process. Add details, and modify the format.
- After entering the URL on the Dashboard reload page and display a popup message about success/failure. Change the format of the popup message. 
- In the first “Cluster Image Upload” stage add details about img size. It can indicate why this step takes so long in some cases. 
- In the first “Cluster Image Upload” stage add details about the cluster on which the img is uploading (beg-cluster, so the user can check the progress.
