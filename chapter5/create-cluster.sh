#!/bin/bash

tput setaf 3
echo -e "*******************************************************************************************************************"
echo -e "Creating KinD Cluster"
echo -e "*******************************************************************************************************************"

tput setaf 5
#Install kubectl
echo -e "\n \n*******************************************************************************************************************"
echo -e "Step 1: Install kubectl"
echo -e "*******************************************************************************************************************"
tput setaf 3
sudo snap install kubectl --classic

tput setaf 5
#install helm and jq
echo -e "\n \n*******************************************************************************************************************"
echo -e "Step 2: Install Helm3 and jq"
echo -e "*******************************************************************************************************************"
tput setaf 3
sudo snap install helm --classic
sudo snap install jq --classic

tput setaf 5
#Create KIND Cluster calle cluster01 using config cluster01-kind.yaml
echo -e "\n \n*******************************************************************************************************************"
echo -e "Step 3: Create KinD Cluster using cluster01-kind.yaml configuration"
echo -e "*******************************************************************************************************************"
tput setaf 3
kind create cluster --name cluster01 --config cluster01-kind.yaml

tput setaf 5
#Install Calico
echo -e "\n \n*******************************************************************************************************************"
echo -e "Step 4: Install Calico from local file, using 10.240.0.0/16 as the pod CIDR"
echo -e "*******************************************************************************************************************"
tput setaf 3
kubectl apply -f calico.yaml

#Deploy NGINX
tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Step 5: Install NGINX Ingress Controller"
echo -e "*******************************************************************************************************************"
tput setaf 3
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.28.0/deploy/static/mandatory.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.27.0/deploy/static/provider/baremetal/service-nodeport.yaml

#Patch NGINX for to forward 80 and 443
tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Step 6: Patch NGINX deployment to expose pod on HOST ports 80 ad 443"
echo -e "*******************************************************************************************************************"
tput setaf 3
kubectl patch deployments -n ingress-nginx nginx-ingress-controller -p '{"spec":{"template":{"spec":{"containers":[{"name":"nginx-ingress-controller","ports":[{"containerPort":80,"hostPort":80},{"containerPort":443,"hostPort":443}]}]}}}}'

#Find IP address of Docker Host
tput setaf 3
hostip=$(hostname  -I | cut -f1 -d' ')
echo -e "\n \n*******************************************************************************************************************"
echo -e "Cluster Creation Complete.  Please see the summary beloq for key information that will be used in later chapters"
echo -e "*******************************************************************************************************************"

tput setaf 7
echo -e "\n \n*******************************************************************************************************************"
echo -e "Your Kind Cluster Information: \n"
echo -e "Ingress Domain: $hostip.nip.io \n"
echo -e "Ingress rules will need to use the IP address of your Linux Host in the Domain name \n"
echo -e "Example:  You have a web server you want to expose using a host called ordering."
echo -e "          Your ingress rule would use the hostname: ordering.$hostip.nip.io"
echo -e "******************************************************************************************************************* \n"
