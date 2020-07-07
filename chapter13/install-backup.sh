#!/bin/bash
clear

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Installing Backup Components..."
echo -e "\nYou may be prompted to supply your sudo password during script execution"
echo -e "*******************************************************************************************************************"

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Installing Minio"
echo -e "*******************************************************************************************************************"
tput setaf 2
kubectl apply -f minio-deployment.yaml

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Adding Ingress rule for Minio"
echo -e "*******************************************************************************************************************"
tput setaf 2
kubectl apply -f minio-ingress.yaml

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Downloading the Velero executable"
echo -e "*******************************************************************************************************************"
tput setaf 2
wget  https://github.com/vmware-tanzu/velero/releases/download/v1.4.0/velero-v1.4.0-linux-amd64.tar.gz

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Extracting files"
echo -e "*******************************************************************************************************************"
tput setaf 2
tar xvf velero-v1.4.0-linux-amd64.tar.gz

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Moving executable to /usr/bin"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo mv velero-v1.4.0-linux-amd64/velero /usr/bin

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Installing Velero server"
echo -e "*******************************************************************************************************************"
tput setaf 2
velero install \
     --provider aws \
     --plugins velero/velero-plugin-for-aws:v1.1.0 \
     --bucket velero \
     --secret-file ./credentials-velero \
     --use-volume-snapshots=false \
     --backup-location-config region=minio,s3ForcePathStyle="true",s3Url=http://minio.velero.svc:9000

echo -e "\n \n*******************************************************************************************************************"
echo -e "Minio and Velero have been deployed."
echo -e "*******************************************************************************************************************"
tput setaf 2

hostip=$(hostname  -I | cut -f1 -d' ')

tput setaf 7
echo -e "\n \n*******************************************************************************************************************"
echo -e "External Minio Ingress Domain: minio.$hostip.nip.io"
echo -e "******************************************************************************************************************* \n"


echo -e "\n\n"
